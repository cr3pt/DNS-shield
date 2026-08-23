from __future__ import annotations

import logging
import queue
import threading
import time

import socket

from dnslib import AAAA, QTYPE, RCODE, RR, A, DNSRecord
from dnslib.server import DNSServer
from dnslib.server import TCPServer as _DNSLibTCPServer
from dnslib.server import UDPServer as _DNSLibUDPServer

from app import upstream as upstream_transport
from app.dns_rewrites import find_rewrite
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
            return request.reply()

        reason = self._blocklist.block_reason(qname, client_ip) if qname else None
        blocked = reason is not None

        alert_match = self._blocklist.alert_match(qname) if qname else None
        alert_rule = alert_match[0] if alert_match else None

        if blocked:
            response = self._blocked_reply(request)
        else:
            rewrite_ip = find_rewrite(qname, qtype_name, self._config) if qname else None
            if rewrite_ip is not None:
                response = self._rewrite_reply(request, qtype, rewrite_ip)
            else:
                response = self._cache.get(request) if self._cache is not None else None
                if response is None:
                    response = self._forward(request, qname, client_ip)
                    if self._cache is not None:
                        self._cache.put(request, response)

                for candidate_ip in self._answer_ips(response):
                    matched_pattern = self._blocklist.answer_ip_blocked(candidate_ip)
                    if matched_pattern is not None:
                        response = self._blocked_reply(request)
                        blocked = True
                        reason = f"Blocked destination IP ({matched_pattern})"
                        break

        self._stats.record(qname, blocked, client_ip, qtype_name, reason, self._answer_ip(response), alert_rule)
        return response

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

    def _forward(self, request: DNSRecord, qname: str, client_ip: str) -> DNSRecord:
        data = request.pack()
        timeout = float(self._config.get("dns", "upstream_timeout_seconds", default=3.0))
        upstreams = self._select_upstreams(qname, client_ip)
        strategy = self._config.get("dns", "upstream_strategy", default="in_order")

        if strategy == "race" and len(upstreams) > 1:
            return self._forward_race(request, data, upstreams, timeout)

        if self._upstream_stats is not None:
            upstreams = self._upstream_stats.rank(upstreams, strategy)

        for upstream in upstreams:
            start = time.monotonic()
            try:
                resp = upstream_transport.forward(data, upstream, timeout)
                if self._upstream_stats is not None:
                    self._upstream_stats.record(upstream, time.monotonic() - start, True)
                return DNSRecord.parse(resp)
            except Exception as exc:
                if self._upstream_stats is not None:
                    self._upstream_stats.record(upstream, time.monotonic() - start, False)
                logger.warning("upstream %s failed: %s", upstream, exc)
                continue

        reply = request.reply()
        reply.header.rcode = RCODE.SERVFAIL
        return reply

    def _forward_race(self, request: DNSRecord, data: bytes, upstreams: list[str], timeout: float) -> DNSRecord:
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
                return DNSRecord.parse(resp)
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


def start_dns_servers(
    config_store, blocklist, stats, cache=None, client_names=None, upstream_stats=None, reuse_port=False
) -> list[DNSServer]:
    resolver = FilteringResolver(
        blocklist, stats, config_store, cache=cache, client_names=client_names, upstream_stats=upstream_stats
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
