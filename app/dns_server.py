# SPDX-License-Identifier: BSD-3-Clause AND LicenseRef-Commons-Clause
# See the LICENSE file in the project root for full license terms.

from __future__ import annotations

import ipaddress
import logging
import queue
import random
import socket
import ssl
import threading
import time
from concurrent.futures import ThreadPoolExecutor

from dnslib import AAAA, CNAME, EDNS0, QTYPE, RCODE, RR, TXT, A, DNSHeader, DNSQuestion, DNSRecord, EDNSOption
from dnslib.server import DNSServer
from dnslib.server import TCPServer as _DNSLibTCPServer
from dnslib.server import UDPServer as _DNSLibUDPServer

from app import upstream as upstream_transport
from app.dns_rewrites import find_rewrite
from app.netmatch import ip_matches
from app.rate_limit import ClientRateLimiter
from app.safe_search import find_safe_search_target

logger = logging.getLogger("dnsshield.dns")

# Shared by all queries: race mode asks every upstream at once (the losers
# finish in the background), prefetch refreshes popular cache entries.
_RACE_POOL = ThreadPoolExecutor(max_workers=32, thread_name_prefix="dns-race")
_PREFETCH_POOL = ThreadPoolExecutor(max_workers=4, thread_name_prefix="dns-prefetch")

_DNSSEC_UDP_SIZE = 1232
_DNSSEC_RTYPES = frozenset({QTYPE.RRSIG, QTYPE.NSEC, QTYPE.NSEC3, QTYPE.NSEC3PARAM, QTYPE.DNSKEY, QTYPE.DS})
_EDNS_DO_BIT = 1 << 15

_TRUSTED_QUERY_NETWORKS = tuple(
    ipaddress.ip_network(net)
    for net in (
        "127.0.0.0/8",
        "10.0.0.0/8",
        "172.16.0.0/12",
        "192.168.0.0/16",
        "169.254.0.0/16",
        "::1/128",
        "fc00::/7",
        "fe80::/10",
    )
)


_ECS_OPTION = 8
_COOKIE_OPTION = 10
_PADDING_OPTION = 12
_EDE_OPTION = 15
# EDNS options that only make sense between the client and us.
_HOP_BY_HOP_OPTIONS = frozenset({_COOKIE_OPTION, _PADDING_OPTION})
# RFC 8467: pad queries to a multiple of 128 bytes, responses to 468.
_QUERY_PAD_BLOCK = 128
_RESPONSE_PAD_BLOCK = 468
_ENCRYPTED_UPSTREAM_PREFIXES = ("dot://", "doh://", "https://", *upstream_transport.DOQ_PREFIXES)


def pad_message(record: DNSRecord, block: int) -> bytes:
    """Pack a message with an EDNS padding option (RFC 7830) so its length
    is a multiple of block - on an encrypted transport the size of a query
    or answer otherwise gives away which name it is about."""
    padded = DNSRecord.parse(record.pack())
    opt = next((rr for rr in padded.ar if rr.rtype == QTYPE.OPT), None)
    if opt is None:
        opt = EDNS0(udp_len=_DNSSEC_UDP_SIZE)
        padded.add_ar(opt)
    options = [o for o in (opt.rdata or []) if o.code != _PADDING_OPTION]
    opt.rdata = options + [EDNSOption(_PADDING_OPTION, b"")]
    base = len(padded.pack())
    opt.rdata = options + [EDNSOption(_PADDING_OPTION, b"\x00" * ((-base) % block))]
    return padded.pack()


class _PaddedReply:
    """A reply that packs itself padded to a multiple of 468 bytes; looks
    like the DNSRecord it wraps to everything else."""

    def __init__(self, record: DNSRecord):
        self._record = record

    def __getattr__(self, name):
        return getattr(self._record, name)

    def pack(self) -> bytes:
        return pad_message(self._record, _RESPONSE_PAD_BLOCK)


class _UpstreamPayload:
    """One upstream query in wire format: padded for encrypted upstreams
    (dns.edns_padding, on by default), plain for the rest."""

    __slots__ = ("_record", "_plain", "_padded", "_padding")

    def __init__(self, record: DNSRecord, padding: bool):
        self._record = record
        self._plain = record.pack()
        self._padded: bytes | None = None
        self._padding = padding

    def for_upstream(self, upstream: str) -> bytes:
        if not self._padding or not upstream.startswith(_ENCRYPTED_UPSTREAM_PREFIXES):
            return self._plain
        if self._padded is None:
            self._padded = pad_message(self._record, _QUERY_PAD_BLOCK)
        return self._padded


class FilteringResolver:
    def __init__(
        self, blocklist, stats, config_store, cache=None, client_names=None, upstream_stats=None, dnssec_cache=None
    ):
        self._blocklist = blocklist
        self._stats = stats
        self._config = config_store
        self._cache = cache
        self._client_names = client_names
        self._upstream_stats = upstream_stats
        self._dnssec_cache = dnssec_cache
        self._rate_limiter = ClientRateLimiter(config_store)

    def resolve(self, request, handler):
        response = self._resolve(request, handler)
        if (
            handler is not None
            and self._wants_padded_response(request, handler)
            and bool(self._config.get("dns", "edns_padding", default=True))
        ):
            return _PaddedReply(response)
        return response

    @staticmethod
    def _wants_padded_response(request, handler) -> bool:
        """Pad the answer when the client padded its query (RFC 7830 s4)
        and the transport is encrypted (DoT / DoQ)."""
        encrypted = getattr(handler, "encrypted_transport", False) or getattr(
            getattr(handler, "server", None), "encrypted_transport", False
        )
        if not encrypted:
            return False
        for rr in request.ar:
            if rr.rtype == QTYPE.OPT:
                return any(option.code == _PADDING_OPTION for option in rr.rdata or [])
        return False

    def _resolve(self, request, handler):
        qname = str(request.q.qname).rstrip(".").lower()
        qtype = request.q.qtype
        qtype_name = QTYPE.get(qtype, str(qtype))
        client_ip = handler.client_address[0] if handler is not None else "?"

        if not self._query_allowed(client_ip):
            reply = request.reply(aa=0)
            reply.header.rcode = RCODE.REFUSED
            return reply

        if not self._rate_limiter.allow(client_ip):
            reply = request.reply(aa=0)
            reply.header.rcode = RCODE.REFUSED
            return reply

        if self._client_names is not None:
            self._client_names.touch(client_ip)

        if qtype == QTYPE.AAAA and self._config.get("dns", "block_ipv6", default=False):
            return request.reply(aa=0)

        reason = self._blocklist.block_reason(qname, client_ip) if qname else None
        blocked = reason is not None

        alert_match = self._blocklist.alert_match(qname) if qname else None
        alert_rule = alert_match[0] if alert_match else None

        typosquat = self._blocklist.typosquat_match(qname) if qname else None
        typosquat_match = f"{typosquat[0]}|{typosquat[1]}|{typosquat[2]}" if typosquat else None
        typosquat_action = self._config.get("dns", "typosquat_action", default="alert") if typosquat else "alert"
        typosquat_can_redirect = bool(typosquat) and qname and qtype_name in ("A", "AAAA")

        local_tld_match = self._blocklist.local_tld_match(qname) if qname else None
        rebinding_ip: str | None = None

        if blocked:
            response = self._blocked_reply(request)
        else:
            rewrite = find_rewrite(qname, qtype_name, self._config) if qname else None
            redirect_ip = self._config.get("dns", "typosquat_redirect_ip", default="") or ""
            if rewrite is not None:
                rewrite_value, rewrite_ttl = rewrite
                response = self._rewrite_entry_reply(request, qtype_name, rewrite_value, rewrite_ttl)
            elif typosquat_can_redirect and typosquat_action == "redirect_custom" and redirect_ip:
                response = self._rewrite_reply(request, qtype, redirect_ip)
            else:
                safe_search, group_upstreams = self._client_profile(client_ip)
                variant = self._cache_variant(safe_search, group_upstreams)
                response = self._cache.get(request, variant) if self._cache is not None else None
                if response is None:
                    response = self._resolve_upstream(
                        request, qname, client_ip, safe_search, group_upstreams, variant, typosquat=typosquat
                    )
                    if self._cache is not None:
                        self._cache.put(request, response, variant)

                for cname in self._answer_cnames(response):
                    cname_reason = self._blocklist.block_reason(cname, client_ip)
                    if cname_reason is not None:
                        response = self._blocked_reply(request)
                        blocked = True
                        reason = f"CNAME cloaking: {cname} ({cname_reason})"
                        break

                if not blocked:
                    for candidate_ip in self._answer_ips(response):
                        matched_pattern = self._blocklist.answer_ip_blocked(candidate_ip)
                        if matched_pattern is not None:
                            response = self._blocked_reply(request)
                            blocked = True
                            reason = f"Blocked destination IP ({matched_pattern})"
                            rebinding_ip = None
                            break
                        if rebinding_ip is None and self._is_rebinding_candidate(qname, candidate_ip):
                            rebinding_ip = candidate_ip

                if rebinding_ip is not None and not blocked:
                    rebinding_action = self._config.get("dns", "rebinding_action", default="block")
                    if rebinding_action == "block":
                        response = self._blocked_reply(request)
                        blocked = True
                        reason = f"DNS rebinding protection ({rebinding_ip})"

        self._stats.record(
            qname,
            blocked,
            client_ip,
            qtype_name,
            reason,
            self._answer_ip(response),
            alert_rule,
            typosquat_match,
            rebinding_ip,
            local_tld_match,
        )
        return response

    def _query_allowed(self, client_ip: str) -> bool:
        if not self._config.get("dns", "query_acl_enabled", default=True):
            return True
        try:
            addr = ipaddress.ip_address(client_ip)
        except ValueError:
            return True
        if any(addr in net for net in _TRUSTED_QUERY_NETWORKS):
            return True
        extra = self._config.get("dns", "query_acl_extra_networks", default=[]) or []
        return any(ip_matches(client_ip, pattern) for pattern in extra)

    def _is_rebinding_candidate(self, qname: str, candidate_ip: str) -> bool:
        if not qname or not self._config.get("dns", "rebinding_protection_enabled", default=True):
            return False
        try:
            addr = ipaddress.ip_address(candidate_ip)
        except ValueError:
            return False
        if addr.is_unspecified:
            return False
        if not addr.is_private:
            return False
        blocked_ipv4 = self._config.get("dns", "blocked_ipv4", default="0.0.0.0") or "0.0.0.0"
        blocked_ipv6 = self._config.get("dns", "blocked_ipv6", default="::") or "::"
        if candidate_ip in (blocked_ipv4, blocked_ipv6):
            return False
        if self._blocklist.local_tld_match_ignoring_toggle(qname):
            return False
        exempt = self._config.get("dns", "rebinding_exempt_domains", default=[]) or []
        return not any(qname == d or qname.endswith("." + d) for d in exempt)

    @staticmethod
    def _answer_ip(response: DNSRecord) -> str | None:
        for rr in response.rr:
            if rr.rtype in (QTYPE.A, QTYPE.AAAA):
                return str(rr.rdata)
        return None

    @staticmethod
    def _answer_ips(response: DNSRecord) -> list[str]:
        return [str(rr.rdata) for rr in response.rr if rr.rtype in (QTYPE.A, QTYPE.AAAA)]

    @staticmethod
    def _answer_cnames(response: DNSRecord) -> list[str]:
        return [str(rr.rdata).rstrip(".").lower() for rr in response.rr if rr.rtype == QTYPE.CNAME]

    def _blocked_reply(self, request: DNSRecord) -> DNSRecord:
        reply = request.reply(aa=0)
        mode = self._config.get("dns", "block_mode", default="nxdomain")
        qtype = request.q.qtype

        if mode == "null_ip" and qtype == QTYPE.A:
            ip = self._config.get("dns", "blocked_ipv4", default="0.0.0.0")
            reply.add_answer(RR(request.q.qname, QTYPE.A, rdata=A(ip), ttl=60))
        elif mode == "null_ip" and qtype == QTYPE.AAAA:
            ip = self._config.get("dns", "blocked_ipv6", default="::")
            reply.add_answer(RR(request.q.qname, QTYPE.AAAA, rdata=AAAA(ip), ttl=60))
        else:
            reply.header.rcode = RCODE.NXDOMAIN
        return reply

    def _redirect_to_hostname(
        self,
        request: DNSRecord,
        target_hostname: str,
        client_ip: str,
        group_upstreams: list[str] | None = None,
        variant: str = "",
    ) -> DNSRecord:
        qtype_name = QTYPE.get(request.q.qtype, "A")
        sub_request = DNSRecord.question(target_hostname, qtype=qtype_name)
        resolved = self._forward(
            sub_request, target_hostname, client_ip, group_upstreams=group_upstreams, variant=variant
        )
        reply = request.reply(aa=0)
        for rr in resolved.rr:
            if rr.rtype in (QTYPE.A, QTYPE.AAAA):
                reply.add_answer(RR(request.q.qname, rr.rtype, rdata=rr.rdata, ttl=rr.ttl))
        return reply

    @staticmethod
    def _rewrite_reply(request: DNSRecord, qtype: int, ip: str) -> DNSRecord:
        reply = request.reply(aa=0)
        if qtype == QTYPE.A:
            reply.add_answer(RR(request.q.qname, QTYPE.A, rdata=A(ip), ttl=300))
        else:
            reply.add_answer(RR(request.q.qname, QTYPE.AAAA, rdata=AAAA(ip), ttl=300))
        return reply

    @staticmethod
    def _rewrite_entry_reply(request: DNSRecord, record_type: str, value: str, ttl: int) -> DNSRecord:
        reply = request.reply(aa=0)
        if record_type == "A":
            reply.add_answer(RR(request.q.qname, QTYPE.A, rdata=A(value), ttl=ttl))
        elif record_type == "AAAA":
            reply.add_answer(RR(request.q.qname, QTYPE.AAAA, rdata=AAAA(value), ttl=ttl))
        elif record_type == "CNAME":
            reply.add_answer(RR(request.q.qname, QTYPE.CNAME, rdata=CNAME(value), ttl=ttl))
        elif record_type == "TXT":
            reply.add_answer(RR(request.q.qname, QTYPE.TXT, rdata=TXT(value), ttl=ttl))
        return reply

    def _group_upstreams(self, client_ip: str) -> list[str] | None:
        if not client_ip:
            return None
        group = self._blocklist.group_for(client_ip)
        if group is None:
            return None
        upstreams = [u for u in (group.get("upstreams") or []) if not upstream_transport.is_disabled(u)]
        return upstreams or None

    def _client_profile(self, client_ip: str) -> tuple[bool, list[str] | None]:
        """The per-client parts of how a query is answered: whether SafeSearch
        rewriting applies, and the client group's own upstreams (if any)."""
        safe_search = bool(self._blocklist.safe_search_enabled_for(client_ip))
        return safe_search, self._group_upstreams(client_ip)

    @staticmethod
    def _cache_variant(safe_search: bool, group_upstreams: list[str] | None) -> str:
        parts = []
        if safe_search:
            parts.append("ss")
        if group_upstreams:
            parts.append("up=" + ",".join(group_upstreams))
        return "|".join(parts)

    @staticmethod
    def _parse_cache_variant(variant: str) -> tuple[bool, list[str] | None]:
        safe_search = False
        group_upstreams: list[str] | None = None
        for part in (variant or "").split("|"):
            if part == "ss":
                safe_search = True
            elif part.startswith("up="):
                group_upstreams = [u for u in part[3:].split(",") if u] or None
        return safe_search, group_upstreams

    def _resolve_upstream(
        self,
        request: DNSRecord,
        qname: str,
        client_ip: str,
        safe_search: bool,
        group_upstreams: list[str] | None,
        variant: str,
        typosquat=None,
    ) -> DNSRecord:
        qtype_name = QTYPE.get(request.q.qtype, str(request.q.qtype))
        redirect_target = None
        if (
            typosquat
            and qname
            and qtype_name in ("A", "AAAA")
            and self._config.get("dns", "typosquat_action", default="alert") == "redirect_real"
        ):
            redirect_target = typosquat[0]
        elif qname and qtype_name in ("A", "AAAA") and safe_search:
            redirect_target = find_safe_search_target(qname)
        if redirect_target is not None:
            return self._redirect_to_hostname(request, redirect_target, client_ip, group_upstreams, variant)
        return self._forward(request, qname, client_ip, group_upstreams=group_upstreams, variant=variant)

    _UNSET = object()

    def _select_upstreams(self, qname: str, client_ip: str, group_upstreams=_UNSET) -> list[str]:
        for rule in self._config.get("domain_upstreams", default=[]) or []:
            domains = rule.get("domains") or []
            if any(qname == d or qname.endswith("." + d) for d in domains):
                upstreams = [u for u in (rule.get("upstreams") or []) if not upstream_transport.is_disabled(u)]
                if upstreams:
                    return upstreams

        if group_upstreams is self._UNSET:
            group_upstreams = self._group_upstreams(client_ip)
        if group_upstreams:
            return list(group_upstreams)

        upstreams = self._config.get("dns", "upstreams", default=["1.1.1.1:53"]) or ["1.1.1.1:53"]
        return [u for u in upstreams if not upstream_transport.is_disabled(u)]

    def _dnssec_enabled(self) -> bool:
        return self._dnssec_cache is not None and bool(self._config.get("dns", "dnssec_enabled", default=False))

    def _case_randomization_enabled(self) -> bool:
        return bool(self._config.get("dns", "query_case_randomization_enabled", default=False))

    @staticmethod
    def _randomize_case(name: str) -> str:
        return "".join(random.choice((c.upper(), c.lower())) if c.isalpha() else c for c in name)

    def _prepare_upstream_query(self, request: DNSRecord) -> DNSRecord:
        """The query as sent upstream: a fresh message with only the question
        and our own EDNS record. The client's EDNS options are passed on
        except the ones that are about this hop (cookies, padding) and, with
        dns.strip_ecs (on by default), EDNS Client Subnet: it would tell every
        upstream the client's network, and answers tailored to one subnet
        would land in the shared cache."""
        dnssec = self._dnssec_enabled()
        q = request.q
        qname = self._randomize_case(str(q.qname)) if self._case_randomization_enabled() else q.qname
        outgoing = DNSRecord(
            DNSHeader(id=request.header.id, rd=request.header.rd, cd=request.header.cd),
            q=DNSQuestion(qname, q.qtype, q.qclass),
        )
        client_opt = next((rr for rr in request.ar if rr.rtype == QTYPE.OPT), None)
        if client_opt is None and not dnssec:
            return outgoing
        strip_ecs = bool(self._config.get("dns", "strip_ecs", default=True))
        options = []
        if client_opt is not None:
            for option in client_opt.rdata or []:
                if option.code in _HOP_BY_HOP_OPTIONS or (strip_ecs and option.code == _ECS_OPTION):
                    continue
                options.append(option)
        do = dnssec or (client_opt is not None and bool(client_opt.ttl & _EDNS_DO_BIT))
        udp_len = _DNSSEC_UDP_SIZE if client_opt is None else max(512, min(int(client_opt.rclass), 4096))
        outgoing.add_ar(EDNS0(flags="do" if do else "", udp_len=udp_len, opts=options))
        return outgoing

    def _upstream_payload(self, request: DNSRecord) -> _UpstreamPayload:
        return _UpstreamPayload(
            self._prepare_upstream_query(request), bool(self._config.get("dns", "edns_padding", default=True))
        )

    def _record_dnssec(self, qname: str, response: DNSRecord) -> None:
        if self._dnssec_enabled() and qname:
            ttl_seconds = float(self._config.get("dns", "dnssec_cache_seconds", default=3600))
            self._dnssec_cache.set_ttl(ttl_seconds)
            self._dnssec_cache.record(qname, bool(response.header.get_ad()))

    @staticmethod
    def _restore_query_case(request: DNSRecord, parsed: DNSRecord) -> None:
        original = request.q.qname
        queried = str(original).rstrip(".").lower()
        parsed.q.qname = original
        for rr in parsed.rr:
            if str(rr.rname).rstrip(".").lower() == queried:
                rr.rname = original

    @staticmethod
    def _client_requested_dnssec(request: DNSRecord) -> bool:
        for rr in request.ar:
            if rr.rtype == QTYPE.OPT:
                return bool(rr.ttl & _EDNS_DO_BIT)
        return False

    @classmethod
    def _sanitize_dnssec(cls, request: DNSRecord, response: DNSRecord) -> None:
        response.header.aa = 0
        if cls._client_requested_dnssec(request):
            return
        response.header.ad = 0
        response.rr = [rr for rr in response.rr if rr.rtype not in _DNSSEC_RTYPES]
        response.auth = [rr for rr in response.auth if rr.rtype not in _DNSSEC_RTYPES]
        response.ar = [rr for rr in response.ar if rr.rtype != QTYPE.OPT and rr.rtype not in _DNSSEC_RTYPES]

    def _forward(
        self, request: DNSRecord, qname: str, client_ip: str, group_upstreams=_UNSET, variant: str = ""
    ) -> DNSRecord:
        payload = self._upstream_payload(request)
        timeout = float(self._config.get("dns", "upstream_timeout_seconds", default=3.0))
        upstreams = self._select_upstreams(qname, client_ip, group_upstreams)
        strategy = self._config.get("dns", "upstream_strategy", default="in_order")

        if strategy == "race" and len(upstreams) > 1:
            return self._forward_race(request, payload, upstreams, timeout, qname, variant)

        if strategy == "random":
            upstreams = list(upstreams)
            random.shuffle(upstreams)
        elif self._upstream_stats is not None:
            upstreams = self._upstream_stats.rank(upstreams, strategy)

        for upstream in upstreams:
            start = time.monotonic()
            try:
                resp = upstream_transport.forward(payload.for_upstream(upstream), upstream, timeout)
                if self._upstream_stats is not None:
                    self._upstream_stats.record(upstream, time.monotonic() - start, True)
                return self._finish_upstream_response(request, resp, qname)
            except Exception as exc:
                if self._upstream_stats is not None:
                    self._upstream_stats.record(upstream, time.monotonic() - start, False)
                logger.warning("upstream %s failed: %s", upstream, exc)
                continue

        return self._upstream_failure_reply(request, qname, variant)

    def _finish_upstream_response(self, request: DNSRecord, resp: bytes, qname: str) -> DNSRecord:
        parsed = DNSRecord.parse(resp)
        validation = self._validate_locally(resp)
        if validation == "bogus":
            logger.warning("DNSSEC validation failed (bogus) for %s - answering SERVFAIL", qname)
            if self._dnssec_cache is not None and qname:
                self._dnssec_cache.record(qname, False)
            reply = request.reply(aa=0)
            reply.header.rcode = RCODE.SERVFAIL
            # Extended DNS Error 6: DNSSEC Bogus (RFC 8914).
            reply.add_ar(EDNS0(udp_len=_DNSSEC_UDP_SIZE, opts=[EDNSOption(_EDE_OPTION, b"\x00\x06")]))
            return reply
        self._restore_query_case(request, parsed)
        if validation in ("secure", "insecure"):
            parsed.header.ad = 1 if validation == "secure" else 0
        self._record_dnssec(qname, parsed)
        self._sanitize_dnssec(request, parsed)
        return parsed

    def _local_validation_enabled(self) -> bool:
        return self._dnssec_enabled() and self._config.get("dns", "dnssec_validation", default="upstream") == "local"

    def _validate_locally(self, resp: bytes) -> str | None:
        """"secure" / "insecure" / "bogus" / "indeterminate" with local
        validation on, None otherwise (the upstream's AD flag is used)."""
        if not self._local_validation_enabled():
            return None
        validator = self._local_validator()
        return validator.validate(resp) if validator is not None else None

    def _local_validator(self):
        anchors = tuple(self._config.get("dns", "dnssec_trust_anchors", default=[]) or ())
        cache_seconds = float(self._config.get("dns", "dnssec_cache_seconds", default=3600))
        key = (anchors, cache_seconds)
        if getattr(self, "_validator_key", None) != key:
            from app.dnssec_validate import ROOT_TRUST_ANCHORS, LocalValidator, upstream_query_fn

            try:
                self._validator = LocalValidator(
                    upstream_query_fn(self._validation_forward),
                    anchors=anchors or ROOT_TRUST_ANCHORS,
                    cache_seconds=cache_seconds,
                )
            except ValueError as exc:
                logger.warning("invalid dns.dnssec_trust_anchors (%s) - local DNSSEC validation is off", exc)
                self._validator = None
            self._validator_key = key
        return self._validator

    def _validation_forward(self, data: bytes) -> bytes:
        """Send one of the validator's own lookups (DNSKEY, DS, SOA) to the default upstreams."""
        timeout = float(self._config.get("dns", "upstream_timeout_seconds", default=3.0))
        upstreams = self._config.get("dns", "upstreams", default=["1.1.1.1:53"]) or ["1.1.1.1:53"]
        error: Exception | None = None
        for upstream in upstreams:
            if upstream_transport.is_disabled(upstream):
                continue
            try:
                return upstream_transport.forward(data, upstream, timeout)
            except Exception as exc:
                error = exc
        raise OSError(f"no upstream answered: {error}")

    def _upstream_failure_reply(self, request: DNSRecord, qname: str, variant: str) -> DNSRecord:
        stale = self._stale_fallback(request, variant)
        if stale is not None:
            logger.info("serving stale cache entry for %s after upstream failure", qname)
            return stale
        reply = request.reply(aa=0)
        reply.header.rcode = RCODE.SERVFAIL
        return reply

    def _stale_fallback(self, request: DNSRecord, variant: str = "") -> DNSRecord | None:
        if self._cache is None:
            return None
        if not bool(self._config.get("dns", "cache_serve_stale_enabled", default=True)):
            return None
        grace = float(self._config.get("dns", "cache_stale_grace_seconds", default=3600))
        return self._cache.get_stale(request, grace, variant)

    def _forward_race(
        self,
        request: DNSRecord,
        payload: _UpstreamPayload,
        upstreams: list[str],
        timeout: float,
        qname: str = "",
        variant: str = "",
    ) -> DNSRecord:
        results: queue.Queue[tuple[str, bytes | None, Exception | None]] = queue.Queue()

        def worker(upstream: str) -> None:
            start = time.monotonic()
            try:
                resp = upstream_transport.forward(payload.for_upstream(upstream), upstream, timeout)
                if self._upstream_stats is not None:
                    self._upstream_stats.record(upstream, time.monotonic() - start, True)
                results.put((upstream, resp, None))
            except Exception as exc:
                if self._upstream_stats is not None:
                    self._upstream_stats.record(upstream, time.monotonic() - start, False)
                results.put((upstream, None, exc))

        for upstream in upstreams:
            _RACE_POOL.submit(worker, upstream)

        for _ in upstreams:
            upstream, resp, exc = results.get()
            if resp is not None:
                return self._finish_upstream_response(request, resp, qname)
            logger.warning("upstream %s failed (race mode): %s", upstream, exc)

        return self._upstream_failure_reply(request, qname, variant)

    def save_cache(self) -> None:
        if self._cache is not None:
            self._cache.save()

    def maintain_cache(self) -> None:
        if self._cache is None:
            return
        grace = float(self._config.get("dns", "cache_stale_grace_seconds", default=3600))
        self._cache.purge_expired(grace)

        if not bool(self._config.get("dns", "cache_prefetch_enabled", default=False)):
            return
        threshold = float(self._config.get("dns", "cache_prefetch_before_expiry_seconds", default=10))
        min_hits = int(self._config.get("dns", "cache_prefetch_min_hits", default=2))
        for key in self._cache.expiring_soon(threshold, min_hits):
            self._cache.mark_prefetching(key)
            _PREFETCH_POOL.submit(self._prefetch_one, key)

    def _prefetch_one(self, key: tuple[str, int, int, str]) -> None:
        qname, qtype, _qclass, variant = key
        try:
            sub_request = DNSRecord.question(qname, qtype=QTYPE.get(qtype, "A"))
            plain_qname = qname.rstrip(".").lower()
            safe_search, group_upstreams = self._parse_cache_variant(variant)
            response = self._resolve_upstream(
                sub_request,
                plain_qname,
                "",
                safe_search,
                group_upstreams,
                variant,
                typosquat=self._blocklist.typosquat_match(plain_qname),
            )
            if response.header.rcode == RCODE.NOERROR:
                self._cache.put(sub_request, response, variant)
        except Exception as exc:
            logger.debug("prefetch of %s failed: %s", qname, exc)
        finally:
            self._cache.clear_prefetching(key)


class QuietLogger:
    def log_pass(self, *args, **kwargs):
        pass

    def log_prefix(self, *args, **kwargs):
        return ""

    def log_recv(self, *args, **kwargs):
        pass

    def log_send(self, *args, **kwargs):
        pass

    def log_request(self, *args, **kwargs):
        pass

    def log_reply(self, *args, **kwargs):
        pass

    def log_truncated(self, *args, **kwargs):
        pass

    def log_error(self, handler, e):
        logger.warning("dns handler error: %s", e)

    def log_data(self, *args, **kwargs):
        pass


DEFAULT_SERVER_THREADS = 64
# Requests waiting for a free thread, per server; past that a UDP query is
# dropped (the client retries) and a TCP connection is closed.
_SERVER_QUEUE_PER_THREAD = 16


class _BoundedPoolMixIn:
    """Handle requests on a fixed pool of threads instead of dnslib's one new
    thread per packet, so a flood of queries (or a slow upstream piling them
    up) can't spawn thousands of threads and exhaust memory."""

    pool_size = DEFAULT_SERVER_THREADS
    dropped = 0

    def _pool(self) -> tuple[ThreadPoolExecutor, threading.BoundedSemaphore]:
        pool = getattr(self, "_request_pool", None)
        if pool is None:
            pool = (
                ThreadPoolExecutor(max_workers=self.pool_size, thread_name_prefix="dns-request"),
                threading.BoundedSemaphore(self.pool_size * (1 + _SERVER_QUEUE_PER_THREAD)),
            )
            self._request_pool = pool
        return pool

    def process_request(self, request, client_address):
        executor, slots = self._pool()
        if not slots.acquire(blocking=False):
            self.dropped += 1
            if self.dropped % 1000 == 1:
                logger.warning("DNS server busy - dropped %d request(s) so far", self.dropped)
            self.shutdown_request(request)
            return
        try:
            executor.submit(self._handle_pooled, request, client_address, slots)
        except RuntimeError:  # shutting down
            slots.release()
            self.shutdown_request(request)

    def _handle_pooled(self, request, client_address, slots) -> None:
        try:
            self.finish_request(request, client_address)
        except Exception:
            self.handle_error(request, client_address)
        finally:
            self.shutdown_request(request)
            slots.release()

    def server_close(self):
        super().server_close()
        pool = getattr(self, "_request_pool", None)
        if pool is not None:
            pool[0].shutdown(wait=False, cancel_futures=True)


class _PooledUDPServer(_BoundedPoolMixIn, _DNSLibUDPServer):
    pass


class _PooledTCPServer(_BoundedPoolMixIn, _DNSLibTCPServer):
    pass


class _ReusePortUDPServer(_PooledUDPServer):
    def server_bind(self):
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
        super().server_bind()


class _ReusePortTCPServer(_PooledTCPServer):
    def server_bind(self):
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
        super().server_bind()


def _with_pool_size(server_class, pool_size: int):
    return type(server_class.__name__, (server_class,), {"pool_size": max(1, pool_size)})


def _server_threads(config_store) -> int:
    try:
        return int(config_store.get("dns", "server_threads", default=DEFAULT_SERVER_THREADS))
    except (TypeError, ValueError):
        return DEFAULT_SERVER_THREADS


def reuse_port_supported() -> bool:
    return hasattr(socket, "SO_REUSEPORT")


def _make_dot_server_class(ssl_context: ssl.SSLContext):
    class _DoTServer(_PooledTCPServer):
        encrypted_transport = True

        def finish_request(self, request, client_address):
            try:
                tls_request = ssl_context.wrap_socket(request, server_side=True)
            except (ssl.SSLError, OSError) as exc:
                logger.debug("DoT handshake failed from %s: %s", client_address, exc)
                return
            super().finish_request(tls_request, client_address)

        def handle_error(self, request, client_address):
            logger.debug("DoT connection error from %s", client_address, exc_info=True)

    return _DoTServer


def start_dot_server(
    resolver: FilteringResolver,
    cert_path,
    key_path,
    address: str = "0.0.0.0",
    port: int = 853,
) -> DNSServer:
    ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ssl_context.load_cert_chain(certfile=str(cert_path), keyfile=str(key_path))

    server = DNSServer(
        resolver,
        address=address,
        port=port,
        tcp=True,
        logger=QuietLogger(),
        server=_make_dot_server_class(ssl_context),
    )
    server.start_thread()
    logger.info("DoT server listening on %s:%d (tls)", address, port)
    return server


def build_resolver(
    config_store,
    blocklist,
    stats,
    cache=None,
    client_names=None,
    upstream_stats=None,
    dnssec_cache=None,
) -> FilteringResolver:
    return FilteringResolver(
        blocklist,
        stats,
        config_store,
        cache=cache,
        client_names=client_names,
        upstream_stats=upstream_stats,
        dnssec_cache=dnssec_cache,
    )


def start_dns_servers(
    config_store,
    blocklist,
    stats,
    cache=None,
    client_names=None,
    upstream_stats=None,
    reuse_port=False,
    dnssec_cache=None,
    resolver: FilteringResolver | None = None,
) -> list[DNSServer]:
    if resolver is None:
        resolver = build_resolver(
            config_store,
            blocklist,
            stats,
            cache=cache,
            client_names=client_names,
            upstream_stats=upstream_stats,
            dnssec_cache=dnssec_cache,
        )
    logger_ = QuietLogger()
    address = config_store.get("dns", "listen_address", default="0.0.0.0")
    port = int(config_store.get("dns", "listen_port", default=53))

    threads = _server_threads(config_store)
    udp_server = _with_pool_size(_ReusePortUDPServer if reuse_port else _PooledUDPServer, threads)
    tcp_server = _with_pool_size(_ReusePortTCPServer if reuse_port else _PooledTCPServer, threads)
    servers = [
        DNSServer(resolver, address=address, port=port, tcp=False, logger=logger_, server=udp_server),
        DNSServer(resolver, address=address, port=port, tcp=True, logger=logger_, server=tcp_server),
    ]
    for server in servers:
        server.start_thread()
    logger.info("DNS server listening on %s:%d (udp+tcp)%s", address, port, " [SO_REUSEPORT]" if reuse_port else "")

    if cache is not None:
        start_cache_maintenance(resolver)

    return servers


def start_cache_maintenance(
    resolver: FilteringResolver, interval_seconds: float = 5.0, save_interval_seconds: float = 300.0
) -> threading.Thread:
    def loop() -> None:
        last_save = time.monotonic()
        while True:
            time.sleep(interval_seconds)
            try:
                resolver.maintain_cache()
            except Exception:
                logger.exception("cache maintenance tick failed")
            if time.monotonic() - last_save >= save_interval_seconds:
                try:
                    resolver.save_cache()
                except Exception:
                    logger.exception("cache persistence save failed")
                last_save = time.monotonic()

    thread = threading.Thread(target=loop, daemon=True, name="dnsshield-cache-maintenance")
    thread.start()
    return thread
