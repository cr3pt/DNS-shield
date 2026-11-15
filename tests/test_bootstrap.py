# SPDX-License-Identifier: BSD-3-Clause AND LicenseRef-Commons-Clause
# See the LICENSE file in the project root for full license terms.

"""Upstream hostnames the system resolver can't resolve are looked up on a bootstrap server."""

import asyncio
import socket
import struct
import threading

import pytest

from app import bootstrap


def _name(packet, pos):
    labels = []
    while packet[pos]:
        labels.append(packet[pos + 1 : pos + 1 + packet[pos]].decode())
        pos += 1 + packet[pos]
    return ".".join(labels), pos + 1


class _FakeDns:
    """Answers A with 192.0.2.5 and AAAA with 2001:db8::5 for any name; counts queries."""

    def __init__(self, answer=True):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind(("127.0.0.1", 0))
        self.port = self.sock.getsockname()[1]
        self.queries = []
        self.answer = answer
        threading.Thread(target=self._serve, daemon=True).start()

    def _serve(self):
        while True:
            try:
                packet, addr = self.sock.recvfrom(512)
            except OSError:
                return
            name, pos = _name(packet, 12)
            qtype = struct.unpack("!H", packet[pos : pos + 2])[0]
            self.queries.append((name, qtype))
            question = packet[12 : pos + 4]
            if not self.answer:
                self.sock.sendto(packet[:2] + b"\x81\x83" + packet[4:6] + b"\0\0\0\0\0\0" + question, addr)
                continue
            rdata = socket.inet_pton(socket.AF_INET, "192.0.2.5") if qtype == 1 else socket.inet_pton(socket.AF_INET6, "2001:db8::5")
            answer = b"\xc0\x0c" + struct.pack("!HHIH", qtype, 1, 60, len(rdata)) + rdata
            self.sock.sendto(packet[:2] + b"\x81\x80" + packet[4:6] + b"\0\x01\0\0\0\0" + question + answer, addr)

    def close(self):
        self.sock.close()


@pytest.fixture(autouse=True)
def _fresh_cache():
    bootstrap._cache.clear()


@pytest.fixture
def fake_dns(monkeypatch):
    server = _FakeDns()
    monkeypatch.setenv("DNSSHIELD_BOOTSTRAP", f"127.0.0.1:{server.port}")
    yield server
    server.close()


def test_name_the_system_cannot_resolve_goes_to_the_bootstrap_server(fake_dns):
    infos = asyncio.run(bootstrap.getaddrinfo("doq.example.invalid", 853))
    assert infos[0][0] == socket.AF_INET and infos[0][4] == ("192.0.2.5", 853)
    assert infos[1][0] == socket.AF_INET6 and infos[1][4][:2] == ("2001:db8::5", 853)
    assert ("doq.example.invalid", 1) in fake_dns.queries


def test_answers_are_cached(fake_dns):
    asyncio.run(bootstrap.getaddrinfo("doq.example.invalid", 853))
    count = len(fake_dns.queries)
    asyncio.run(bootstrap.getaddrinfo("doq.example.invalid", 853))
    assert len(fake_dns.queries) == count


def test_ip_literals_never_touch_the_network(monkeypatch):
    monkeypatch.setenv("DNSSHIELD_BOOTSTRAP", "127.0.0.1:9")
    infos = asyncio.run(bootstrap.getaddrinfo("127.0.0.1", 853))
    assert infos[0][4][:2] == ("127.0.0.1", 853)


def test_unresolvable_everywhere_raises_the_system_error(monkeypatch):
    server = _FakeDns(answer=False)
    monkeypatch.setenv("DNSSHIELD_BOOTSTRAP", f"127.0.0.1:{server.port}")
    try:
        with pytest.raises(OSError):
            asyncio.run(bootstrap.getaddrinfo("doq.example.invalid", 853))
    finally:
        server.close()


def test_default_bootstrap_servers(monkeypatch):
    monkeypatch.delenv("DNSSHIELD_BOOTSTRAP", raising=False)
    assert bootstrap.bootstrap_servers() == [("1.1.1.1", 53), ("9.9.9.9", 53)]
    monkeypatch.setenv("DNSSHIELD_BOOTSTRAP", "8.8.8.8, 10.0.0.1:5353")
    assert bootstrap.bootstrap_servers() == [("8.8.8.8", 53), ("10.0.0.1", 5353)]
