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
import socket

from dnslib import AAAA, QTYPE, RCODE, RR, A, DNSRecord
from dnslib.server import DNSServer

logger = logging.getLogger("dnsshield.dns")


class FilteringResolver:
    def __init__(self, blocklist, stats, config_store):
        self._blocklist = blocklist
        self._stats = stats
        self._config = config_store

    def resolve(self, request, handler):
        qname = str(request.q.qname).rstrip(".").lower()
        qtype_name = QTYPE.get(request.q.qtype, str(request.q.qtype))
        client_ip = handler.client_address[0] if handler is not None else "?"

        blocked = bool(qname) and self._blocklist.is_blocked(qname)
        self._stats.record(qname, blocked, client_ip, qtype_name)

        if blocked:
            return self._blocked_reply(request)
        return self._forward(request)

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

    def _forward(self, request: DNSRecord) -> DNSRecord:
        data = request.pack()
        timeout = float(self._config.get("dns", "upstream_timeout_seconds", default=3.0))
        upstreams = self._config.get("dns", "upstreams", default=["1.1.1.1:53"]) or ["1.1.1.1:53"]

        for upstream in upstreams:
            host, _, port_str = upstream.partition(":")
            port = int(port_str) if port_str else 53
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                    sock.settimeout(timeout)
                    sock.sendto(data, (host, port))
                    resp, _ = sock.recvfrom(65535)
                return DNSRecord.parse(resp)
            except (socket.timeout, OSError) as exc:
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


def start_dns_servers(config_store, blocklist, stats) -> list[DNSServer]:
    resolver = FilteringResolver(blocklist, stats, config_store)
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
