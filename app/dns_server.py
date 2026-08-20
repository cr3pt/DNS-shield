"""The actual DNS filtering proxy.

FilteringResolver decides, for every incoming query, whether the queried
name is blocked. If it is, we answer locally (NXDOMAIN or a null IP) -
no network traffic leaves the box for a blocked query. If it is not, the
raw request is forwarded verbatim to one of the configured upstream
resolvers and the raw reply is relayed back, so we stay correct for all
record types without having to reimplement DNS semantics.
"""

from __future__ import annotations

import logging
import time

from dnslib import AAAA, QTYPE, RCODE, RR, A, DNSRecord
from dnslib.server import DNSServer

from app import upstream as upstream_transport
from app.netmatch import ip_matches

logger = logging.getLogger("dnsshield.dns")


class FilteringResolver:
    def __init__(self, blocklist, stats, config_store, cache=None, client_names=None, upstream_stats=None):
        self._blocklist = blocklist
        self._stats = stats
        self._config = config_store
        self._cache = cache
        self._client_names = client_names
        self._upstream_stats = upstream_stats

    def resolve(self, request, handler):
        qname = str(request.q.qname).rstrip(".").lower()
        qtype = request.q.qtype
        qtype_name = QTYPE.get(qtype, str(qtype))
        client_ip = handler.client_address[0] if handler is not None else "?"

        if self._client_names is not None:
            self._client_names.touch(client_ip)

        if qtype == QTYPE.AAAA and self._config.get("dns", "block_ipv6", default=False):
            # Answer NOERROR with no records, rather than NXDOMAIN: this
            # tells the client "this name has no IPv6 address", which makes
            # a dual-stack client fall straight back to A/IPv4 instead of
            # waiting out a timeout or treating the whole name as missing.
            # Not logged at all - with IPv6 disabled, every single query
            # would otherwise get a noise entry here, which isn't useful.
            return request.reply()

        reason = self._blocklist.block_reason(qname, client_ip) if qname else None
        blocked = reason is not None
        self._stats.record(qname, blocked, client_ip, qtype_name, reason)

        if blocked:
            return self._blocked_reply(request)

        if self._cache is not None:
            cached = self._cache.get(request)
            if cached is not None:
                return cached

        response = self._forward(request, qname, client_ip)
        if self._cache is not None:
            self._cache.put(request, response)
        return response

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

    def _select_upstreams(self, qname: str, client_ip: str) -> list[str]:
        """Precedence: per-domain routing rule > matched client group's own
        upstreams > the global list. A domain rule wins even for a client
        whose group has its own upstreams, since domain routing is usually
        a hard technical requirement (e.g. "*.corp.local must go to the
        internal resolver") rather than a per-client preference.
        """
        for rule in self._config.get("domain_upstreams", default=[]) or []:
            domains = rule.get("domains") or []
            if any(qname == d or qname.endswith("." + d) for d in domains):
                upstreams = rule.get("upstreams") or []
                if upstreams:
                    return upstreams

        if client_ip:
            for group in self._config.get("client_groups", default=[]) or []:
                if any(ip_matches(client_ip, pattern) for pattern in group.get("match", []) or []):
                    upstreams = group.get("upstreams") or []
                    if upstreams:
                        return upstreams
                    break

        return self._config.get("dns", "upstreams", default=["1.1.1.1:53"]) or ["1.1.1.1:53"]

    def _forward(self, request: DNSRecord, qname: str, client_ip: str) -> DNSRecord:
        data = request.pack()
        timeout = float(self._config.get("dns", "upstream_timeout_seconds", default=3.0))
        upstreams = self._select_upstreams(qname, client_ip)

        strategy = self._config.get("dns", "upstream_strategy", default="in_order")
        if self._upstream_stats is not None:
            upstreams = self._upstream_stats.rank(upstreams, strategy)

        for upstream in upstreams:
            start = time.monotonic()
            try:
                resp = upstream_transport.forward(data, upstream, timeout)
                if self._upstream_stats is not None:
                    self._upstream_stats.record(upstream, time.monotonic() - start, True)
                return DNSRecord.parse(resp)
            except Exception as exc:  # noqa: BLE001 - socket/ssl/requests errors, any upstream can fail
                if self._upstream_stats is not None:
                    self._upstream_stats.record(upstream, time.monotonic() - start, False)
                logger.warning("upstream %s failed: %s", upstream, exc)
                continue

        reply = request.reply()
        reply.header.rcode = RCODE.SERVFAIL
        return reply


class QuietLogger:
    """dnslib logs every request/reply to stdout by default - keep it quiet."""

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


def start_dns_servers(config_store, blocklist, stats, cache=None, client_names=None, upstream_stats=None) -> list[DNSServer]:
    resolver = FilteringResolver(
        blocklist, stats, config_store, cache=cache, client_names=client_names, upstream_stats=upstream_stats
    )
    logger_ = QuietLogger()
    address = config_store.get("dns", "listen_address", default="0.0.0.0")
    port = int(config_store.get("dns", "listen_port", default=53))

    servers = [
        DNSServer(resolver, address=address, port=port, tcp=False, logger=logger_),
        DNSServer(resolver, address=address, port=port, tcp=True, logger=logger_),
    ]
    for server in servers:
        server.start_thread()
    logger.info("DNS server listening on %s:%d (udp+tcp)", address, port)
    return servers
