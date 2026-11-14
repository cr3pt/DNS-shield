# SPDX-License-Identifier: BSD-3-Clause AND LicenseRef-Commons-Clause
# See the LICENSE file in the project root for full license terms.

"""DNS-over-TLS upstream connections are reused across queries."""

import socket
import ssl
import struct
import threading

import pytest
from dnslib import DNSRecord

from app import upstream
from app.tls import ensure_self_signed_cert


class _DoTServer:
    """Answers any number of queries per connection; can drop idle ones."""

    def __init__(self, tmp_path, queries_per_connection=None):
        cert, key = tmp_path / "c.pem", tmp_path / "k.pem"
        ensure_self_signed_cert(cert, key)
        self.cert = cert
        self.context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self.context.load_cert_chain(cert, key)
        self.listener = socket.create_server(("127.0.0.1", 0))
        self.port = self.listener.getsockname()[1]
        self.connections = 0
        self.queries_per_connection = queries_per_connection
        threading.Thread(target=self._accept, daemon=True).start()

    def _accept(self):
        while True:
            try:
                raw, _ = self.listener.accept()
            except OSError:
                return
            self.connections += 1
            threading.Thread(target=self._serve, args=(raw,), daemon=True).start()

    def _serve(self, raw):
        try:
            with self.context.wrap_socket(raw, server_side=True) as sock:
                served = 0
                while self.queries_per_connection is None or served < self.queries_per_connection:
                    head = sock.recv(2)
                    if len(head) < 2:
                        return
                    query = DNSRecord.parse(upstream._recv_exact(sock, struct.unpack("!H", head)[0]))
                    reply = query.reply().pack()
                    sock.sendall(struct.pack("!H", len(reply)) + reply)
                    served += 1
        except (OSError, ssl.SSLError):
            return

    def close(self):
        self.listener.close()


@pytest.fixture
def trusting_client(monkeypatch, tmp_path):
    def _context_for(server):
        context = ssl.create_default_context(cafile=str(server.cert))
        context.check_hostname = False
        monkeypatch.setattr(upstream, "_dot_ssl_context", lambda: context)

    monkeypatch.setattr(upstream, "_dot_idle", {})
    return _context_for


def _ask(port, name="example.com"):
    query = DNSRecord.question(name)
    resp = DNSRecord.parse(upstream.forward(query.pack(), f"dot://127.0.0.1:{port}", 3.0))
    assert resp.header.id == query.header.id
    return resp


def test_queries_share_one_connection(tmp_path, trusting_client):
    server = _DoTServer(tmp_path)
    trusting_client(server)
    try:
        for name in ("a.example", "b.example", "c.example"):
            assert str(_ask(server.port, name).q.qname) == name + "."
        assert server.connections == 1
    finally:
        server.close()


def test_a_connection_the_server_closed_is_replaced(tmp_path, trusting_client):
    server = _DoTServer(tmp_path, queries_per_connection=1)
    trusting_client(server)
    try:
        _ask(server.port)
        _ask(server.port)  # the kept connection is dead now: transparently reconnects
        assert server.connections == 2
    finally:
        server.close()


def test_idle_connections_expire(tmp_path, trusting_client, monkeypatch):
    server = _DoTServer(tmp_path)
    trusting_client(server)
    try:
        _ask(server.port)
        monkeypatch.setattr(upstream, "_DOT_IDLE_SECONDS", 0.0)
        _ask(server.port)
        assert server.connections == 2
    finally:
        server.close()
