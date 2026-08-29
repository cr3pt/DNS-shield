from __future__ import annotations

import ipaddress
import logging
import queue
import ssl
import threading
import time

import socket

from dnslib import AAAA, EDNS0, QTYPE, RCODE, RR, A, DNSHeader, DNSRecord
from dnslib.server import DNSServer
from dnslib.server import TCPServer as _DNSLibTCPServer
from dnslib.server import UDPServer as _DNSLibUDPServer

from app import upstream as upstream_transport
from app.dns_rewrites import find_rewrite
from app.netmatch import ip_matches
from app.safe_search import find_safe_search_target

logger = logging.getLogger("dnsshield.dns")

_DNSSEC_UDP_SIZE = 1232


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

    def resolve(self, request, handler):
        qname = str(request.q.qname).rstrip(".").lower()
        qtype = request.q.qtype
        qtype_name = QTYPE.get(qtype, str(qtype))
        client_ip = handler.client_address[0] if handler is not None else "?"

        if self._client_names is not None:
            self._client_names.touch(client_ip)

        if qtype == QTYPE.AAAA and self._config.get("dns", "block_ipv6", default=False):
            return request.reply()

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
            rewrite_ip = find_rewrite(qname, qtype_name, self._config) if qname else None
            redirect_ip = self._config.get("dns", "typosquat_redirect_ip", default="") or ""
            if rewrite_ip is not None:
                response = self._rewrite_reply(request, qtype, rewrite_ip)
            elif typosquat_can_redirect and typosquat_action == "redirect_custom" and redirect_ip:
                response = self._rewrite_reply(request, qtype, redirect_ip)
            else:
                response = self._cache.get(request) if self._cache is not None else None
                if response is None:
                    redirect_target = None
                    if typosquat_can_redirect and typosquat_action == "redirect_real":
                        redirect_target = typosquat[0]
                    elif qname and qtype_name in ("A", "AAAA") and self._blocklist.safe_search_enabled_for(client_ip):
                        redirect_target = find_safe_search_target(qname)
                    if redirect_target is not None:
                        response = self._redirect_to_hostname(request, redirect_target, client_ip)
                    else:
                        response = self._forward(request, qname, client_ip)
                    if self._cache is not None:
                        self._cache.put(request, response)

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
                    rebinding_action = self._config.get("dns", "rebinding_action", default="alert")
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

    def _is_rebinding_candidate(self, qname: str, candidate_ip: str) -> bool:
        if not qname or not self._config.get("dns", "rebinding_protection_enabled", default=False):
            return False
        try:
            addr = ipaddress.ip_address(candidate_ip)
        except ValueError:
            return False
        if addr.is_unspecified:
            # 0.0.0.0 / :: are sinkhole/null-route answers (our own block page or an
            # upstream filtering resolver's block response), not a real rebinding target.
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

    def _blocked_reply(self, request: DNSRecord) -> DNSRecord:
        reply = request.reply()
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

    def _redirect_to_hostname(self, request: DNSRecord, target_hostname: str, client_ip: str) -> DNSRecord:
        qtype_name = QTYPE.get(request.q.qtype, "A")
        sub_request = DNSRecord.question(target_hostname, qtype=qtype_name)
        resolved = self._forward(sub_request, target_hostname, client_ip)
        reply = request.reply()
        for rr in resolved.rr:
            if rr.rtype in (QTYPE.A, QTYPE.AAAA):
                reply.add_answer(RR(request.q.qname, rr.rtype, rdata=rr.rdata, ttl=rr.ttl))
        return reply

    @staticmethod
    def _rewrite_reply(request: DNSRecord, qtype: int, ip: str) -> DNSRecord:
        reply = request.reply()
        if qtype == QTYPE.A:
            reply.add_answer(RR(request.q.qname, QTYPE.A, rdata=A(ip), ttl=300))
        else:
            reply.add_answer(RR(request.q.qname, QTYPE.AAAA, rdata=AAAA(ip), ttl=300))
        return reply

    def _select_upstreams(self, qname: str, client_ip: str) -> list[str]:
        for rule in self._config.get("domain_upstreams", default=[]) or []:
            domains = rule.get("domains") or []
            if any(qname == d or qname.endswith("." + d) for d in domains):
                upstreams = [u for u in (rule.get("upstreams") or []) if not upstream_transport.is_disabled(u)]
                if upstreams:
                    return upstreams

        if client_ip:
            for group in self._config.get("client_groups", default=[]) or []:
                if any(ip_matches(client_ip, pattern) for pattern in group.get("match", []) or []):
                    upstreams = [u for u in (group.get("upstreams") or []) if not upstream_transport.is_disabled(u)]
                    if upstreams:
                        return upstreams
                    break

        upstreams = self._config.get("dns", "upstreams", default=["1.1.1.1:53"]) or ["1.1.1.1:53"]
        return [u for u in upstreams if not upstream_transport.is_disabled(u)]

    def _dnssec_enabled(self) -> bool:
        return self._dnssec_cache is not None and bool(self._config.get("dns", "dnssec_enabled", default=False))

    def _prepare_upstream_data(self, request: DNSRecord) -> bytes:
        if not self._dnssec_enabled():
            return request.pack()
        outgoing = DNSRecord(DNSHeader(id=request.header.id, rd=request.header.rd), q=request.q)
        outgoing.add_ar(EDNS0(flags="do", udp_len=_DNSSEC_UDP_SIZE))
        return outgoing.pack()

    def _record_dnssec(self, qname: str, response: DNSRecord) -> None:
        if self._dnssec_enabled() and qname:
            ttl_seconds = float(self._config.get("dns", "dnssec_cache_seconds", default=3600))
            self._dnssec_cache.set_ttl(ttl_seconds)
            self._dnssec_cache.record(qname, bool(response.header.get_ad()))

    def _forward(self, request: DNSRecord, qname: str, client_ip: str) -> DNSRecord:
        data = self._prepare_upstream_data(request)
        timeout = float(self._config.get("dns", "upstream_timeout_seconds", default=3.0))
        upstreams = self._select_upstreams(qname, client_ip)
        strategy = self._config.get("dns", "upstream_strategy", default="in_order")

        if strategy == "race" and len(upstreams) > 1:
            return self._forward_race(request, data, upstreams, timeout, qname)

        if self._upstream_stats is not None:
            upstreams = self._upstream_stats.rank(upstreams, strategy)

        for upstream in upstreams:
            start = time.monotonic()
            try:
                resp = upstream_transport.forward(data, upstream, timeout)
                if self._upstream_stats is not None:
                    self._upstream_stats.record(upstream, time.monotonic() - start, True)
                parsed = DNSRecord.parse(resp)
                self._record_dnssec(qname, parsed)
                return parsed
            except Exception as exc:
                if self._upstream_stats is not None:
                    self._upstream_stats.record(upstream, time.monotonic() - start, False)
                logger.warning("upstream %s failed: %s", upstream, exc)
                continue

        reply = request.reply()
        reply.header.rcode = RCODE.SERVFAIL
        return reply

    def _forward_race(
        self, request: DNSRecord, data: bytes, upstreams: list[str], timeout: float, qname: str = ""
    ) -> DNSRecord:
        results: queue.Queue[tuple[str, bytes | None, Exception | None]] = queue.Queue()

        def worker(upstream: str) -> None:
            start = time.monotonic()
            try:
                resp = upstream_transport.forward(data, upstream, timeout)
                if self._upstream_stats is not None:
                    self._upstream_stats.record(upstream, time.monotonic() - start, True)
                results.put((upstream, resp, None))
            except Exception as exc:
                if self._upstream_stats is not None:
                    self._upstream_stats.record(upstream, time.monotonic() - start, False)
                results.put((upstream, None, exc))

        for upstream in upstreams:
            threading.Thread(target=worker, args=(upstream,), daemon=True).start()

        for _ in upstreams:
            upstream, resp, exc = results.get()
            if resp is not None:
                parsed = DNSRecord.parse(resp)
                self._record_dnssec(qname, parsed)
                return parsed
            logger.warning("upstream %s failed (race mode): %s", upstream, exc)

        reply = request.reply()
        reply.header.rcode = RCODE.SERVFAIL
        return reply


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


class _ReusePortUDPServer(_DNSLibUDPServer):
    def server_bind(self):
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
        super().server_bind()


class _ReusePortTCPServer(_DNSLibTCPServer):
    def server_bind(self):
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
        super().server_bind()


def reuse_port_supported() -> bool:
    return hasattr(socket, "SO_REUSEPORT")


def _make_dot_server_class(ssl_context: ssl.SSLContext):
    class _DoTServer(_DNSLibTCPServer):
        def finish_request(self, request, client_address):
            # Wrapping the socket here (not in get_request()) means the TLS handshake
            # runs inside the per-connection thread ThreadingMixIn already spawned, so a
            # slow/hanging client can't block the accept loop for other connections.
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

    udp_server = _ReusePortUDPServer if reuse_port else None
    tcp_server = _ReusePortTCPServer if reuse_port else None
    servers = [
        DNSServer(resolver, address=address, port=port, tcp=False, logger=logger_, server=udp_server),
        DNSServer(resolver, address=address, port=port, tcp=True, logger=logger_, server=tcp_server),
    ]
    for server in servers:
        server.start_thread()
    logger.info("DNS server listening on %s:%d (udp+tcp)%s", address, port, " [SO_REUSEPORT]" if reuse_port else "")
    return servers
