# SPDX-License-Identifier: BSD-3-Clause AND LicenseRef-Commons-Clause
# See the LICENSE file in the project root for full license terms.

"""The DNS servers answer on a fixed pool of threads and shed load past it."""

import socket
import threading

from dnslib import DNSRecord

from app import dns_server
from app.dns_server import _BoundedPoolMixIn, start_dns_servers


class _FakeServer(_BoundedPoolMixIn):
    pool_size = 1

    def __init__(self):
        self.release = threading.Event()
        self.handled = []
        self.closed = []

    def finish_request(self, request, client_address):
        self.release.wait(5)
        self.handled.append(request)

    def shutdown_request(self, request):
        self.closed.append(request)

    def handle_error(self, request, client_address):
        raise AssertionError("unexpected error")


def test_requests_past_the_queue_are_dropped():
    server = _FakeServer()
    capacity = 1 * (1 + dns_server._SERVER_QUEUE_PER_THREAD)
    for i in range(capacity + 3):
        server.process_request(i, ("10.0.0.1", 5353))
    assert server.dropped == 3
    server.release.set()
    executor, _slots = server._pool()
    executor.shutdown(wait=True)
    assert sorted(server.handled) == list(range(capacity))
    # every request's socket is closed exactly once, handled or dropped
    assert sorted(server.closed) == list(range(capacity + 3))


class _Resolver:
    def resolve(self, request, handler):
        reply = request.reply()
        reply.header.rcode = 3
        return reply


def test_pooled_servers_answer_queries(config_store):
    config_store.mutate(
        lambda d: d.setdefault("dns", {}).update({"listen_address": "127.0.0.1", "listen_port": 0, "server_threads": 2})
    )
    servers = start_dns_servers(config_store, None, None, resolver=_Resolver())
    try:
        assert all(s.server.pool_size == 2 for s in servers)
        port = servers[0].server.server_address[1]
        query = DNSRecord.question("example.com").pack()
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.settimeout(3)
            for _ in range(5):
                sock.sendto(query, ("127.0.0.1", port))
                assert DNSRecord.parse(sock.recv(512)).header.rcode == 3
    finally:
        for server in servers:
            server.stop()
