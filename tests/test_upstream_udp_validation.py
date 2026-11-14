# SPDX-License-Identifier: BSD-3-Clause AND LicenseRef-Commons-Clause
# See the LICENSE file in the project root for full license terms.

"""Plain-UDP upstream answers are only accepted when they match the query
(transaction ID, question, letter case) - anything else is ignored."""

import socket
import threading

import pytest
from dnslib import QTYPE, RR, A, DNSRecord

from app import upstream


def _serve_once(handler):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("127.0.0.1", 0))
    sock.settimeout(5)

    def run():
        try:
            data, addr = sock.recvfrom(65535)
            for packet in handler(DNSRecord.parse(data)):
                sock.sendto(packet, addr)
        except OSError:
            pass
        finally:
            sock.close()

    threading.Thread(target=run, daemon=True).start()
    return f"127.0.0.1:{sock.getsockname()[1]}"


def _answer(request, ip="1.2.3.4", qname=None):
    reply = DNSRecord.parse(request.pack()).reply()
    if qname is not None:
        reply.q.qname = qname
    reply.add_answer(RR(reply.q.qname, QTYPE.A, rdata=A(ip), ttl=60))
    return reply.pack()


def test_client_id_is_not_sent_upstream_but_restored(monkeypatch):
    seen_ids = []

    def handler(req):
        seen_ids.append(req.header.id)
        return [_answer(req)]

    monkeypatch.setattr(upstream.secrets, "token_bytes", lambda n: b"\x00\x07")
    addr = _serve_once(handler)
    query = DNSRecord.question("example.com")
    query.header.id = 4242
    resp = DNSRecord.parse(upstream.forward(query.pack(), addr, 2.0))
    assert resp.header.id == 4242
    assert str(resp.rr[0].rdata) == "1.2.3.4"
    assert seen_ids == [7]


def test_spoofed_wrong_id_and_wrong_question_are_ignored():
    def handler(req):
        wrong_id = DNSRecord.parse(_answer(req, ip="6.6.6.6"))
        wrong_id.header.id = (req.header.id + 1) % 65536
        wrong_question = _answer(req, ip="7.7.7.7", qname="evil.example.")
        return [wrong_id.pack(), wrong_question, _answer(req, ip="1.2.3.4")]

    addr = _serve_once(handler)
    resp = DNSRecord.parse(upstream.forward(DNSRecord.question("example.com").pack(), addr, 2.0))
    assert [str(rr.rdata) for rr in resp.rr] == ["1.2.3.4"]


def test_only_mismatching_packets_time_out():
    def handler(req):
        return [_answer(req, ip="7.7.7.7", qname="evil.example.")]

    addr = _serve_once(handler)
    with pytest.raises(OSError):
        upstream.forward(DNSRecord.question("example.com").pack(), addr, 0.5)


def test_case_mismatch_falls_back_to_tcp(monkeypatch):
    calls = []

    def fake_tcp(data, host, port, timeout):
        calls.append(DNSRecord.parse(data).q.qname)
        return b"tcp-answer"

    monkeypatch.setattr(upstream, "_forward_tcp", fake_tcp)

    def handler(req):
        return [_answer(req, qname=str(req.q.qname).lower())]

    addr = _serve_once(handler)
    assert upstream.forward(DNSRecord.question("ExAmPlE.CoM").pack(), addr, 2.0) == b"tcp-answer"
    assert len(calls) == 1


def test_check_response_accepts_exact_echo():
    query = DNSRecord.question("MiXeD.example.com").pack()
    resp = DNSRecord.parse(query).reply().pack()
    assert upstream._check_response(query, resp) == "ok"
