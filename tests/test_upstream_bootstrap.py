# SPDX-License-Identifier: BSD-3-Clause AND LicenseRef-Commons-Clause
# See the LICENSE file in the project root for full license terms.

"""DoT and DoH upstream hostnames the system resolver can't resolve go through the bootstrap lookup."""

import asyncio
import secrets
import socket
import ssl
import struct
import threading

import pytest

from app import bootstrap, upstream
from app.tls import ensure_self_signed_cert


def _query(name_label: bytes = b"a") -> bytes:
    header = struct.pack("!HHHHHH", 0, 0x0100, 1, 0, 0, 0)
    return secrets.token_bytes(2) + header[2:] + bytes([len(name_label)]) + name_label + b"\0" + struct.pack("!HH", 1, 1)


class _DoTServer:
    """Answers every query on a TLS connection; remembers the SNI name it was asked for."""

    def __init__(self, tmp_path):
        cert, key = tmp_path / "c.pem", tmp_path / "k.pem"
        ensure_self_signed_cert(cert, key)
        self.cert = cert
        self.sni = []
        self.context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self.context.load_cert_chain(cert, key)
        self.context.sni_callback = lambda _sock, name, _ctx: self.sni.append(name)
        self.listener = socket.create_server(("127.0.0.1", 0))
        self.port = self.listener.getsockname()[1]
        threading.Thread(target=self._accept, daemon=True).start()

    def _accept(self):
        while True:
            try:
                raw, _ = self.listener.accept()
            except OSError:
                return
            threading.Thread(target=self._serve, args=(raw,), daemon=True).start()

    def _serve(self, raw):
        try:
            with self.context.wrap_socket(raw, server_side=True) as sock:
                while True:
                    head = sock.recv(2)
                    if len(head) < 2:
                        return
                    query = upstream._recv_exact(sock, struct.unpack("!H", head)[0])
                    reply = query[:2] + b"\x81\x80" + query[4:]
                    sock.sendall(struct.pack("!H", len(reply)) + reply)
        except (OSError, ssl.SSLError):
            return

    def close(self):
        self.listener.close()


def test_dot_upstream_is_reached_through_the_bootstrap_address(tmp_path, monkeypatch):
    server = _DoTServer(tmp_path)
    context = ssl.create_default_context(cafile=str(server.cert))
    context.check_hostname = False
    monkeypatch.setattr(upstream, "_dot_ssl_context", lambda: context)
    monkeypatch.setattr(upstream, "_dot_idle", {})

    async def fake_getaddrinfo(host, port, type=socket.SOCK_DGRAM):  # noqa: A002
        assert host == "dot.example.invalid"
        return [(socket.AF_INET, type, 0, "", ("127.0.0.1", port))]

    monkeypatch.setattr(bootstrap, "getaddrinfo", fake_getaddrinfo)
    try:
        query = _query()
        answer = upstream.forward(query, f"dot://dot.example.invalid:{server.port}", 5.0)
        assert answer[:2] == query[:2] and answer[2] & 0x80
        assert server.sni == ["dot.example.invalid"]
    finally:
        server.close()


def test_doh_resolver_uses_the_bootstrap_lookup(monkeypatch):
    async def fake_getaddrinfo(host, port, type=socket.SOCK_DGRAM):  # noqa: A002
        assert (host, port, type) == ("doh.example.invalid", 443, socket.SOCK_STREAM)
        return [
            (socket.AF_INET, type, 0, "", ("192.0.2.5", 443)),
            (socket.AF_INET6, type, 0, "", ("2001:db8::5", 443, 0, 0)),
        ]

    monkeypatch.setattr(bootstrap, "getaddrinfo", fake_getaddrinfo)
    resolver = upstream._BootstrapResolver()

    everything = asyncio.run(resolver.resolve("doh.example.invalid", 443))
    assert [r["host"] for r in everything] == ["192.0.2.5", "2001:db8::5"]
    assert all(r["hostname"] == "doh.example.invalid" and r["port"] == 443 for r in everything)

    only_v4 = asyncio.run(resolver.resolve("doh.example.invalid", 443, socket.AF_INET))
    assert [r["host"] for r in only_v4] == ["192.0.2.5"]


def test_dot_without_any_address_raises(monkeypatch):
    async def failing_getaddrinfo(host, port, type=socket.SOCK_DGRAM):  # noqa: A002
        raise OSError("no such host")

    monkeypatch.setattr(bootstrap, "getaddrinfo", failing_getaddrinfo)
    monkeypatch.setattr(upstream, "_dot_idle", {})
    with pytest.raises(OSError):
        upstream.forward(_query(), "dot://dot.example.invalid:853", 2.0)
