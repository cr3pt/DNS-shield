# SPDX-License-Identifier: BSD-3-Clause AND LicenseRef-Commons-Clause
# See the LICENSE file in the project root for full license terms.

"""A failing or silent upstream must not stall the resolver."""

import socket
import threading
import time

import pytest

from app import upstream, upstream_guard

QUERY = b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07example\x03com\x00\x00\x01\x00\x01"


def _boom(*_args):
    raise ConnectionError("connection refused")


def test_breaker_opens_after_three_failures_and_skips_without_calling():
    calls = []

    def failing():
        calls.append(1)
        raise TimeoutError

    for _ in range(upstream_guard.FAILURES_TO_OPEN):
        with pytest.raises(TimeoutError):
            upstream_guard.run("1.2.3.4:53", failing)
    with pytest.raises(upstream_guard.UpstreamSkipped):
        upstream_guard.run("1.2.3.4:53", failing)
    assert len(calls) == upstream_guard.FAILURES_TO_OPEN


def test_skipped_upstream_is_a_connection_error_the_resolver_already_handles():
    assert issubclass(upstream_guard.UpstreamSkipped, ConnectionError)


def test_other_upstreams_are_not_affected():
    for _ in range(upstream_guard.FAILURES_TO_OPEN):
        with pytest.raises(OSError):
            upstream_guard.run("bad:53", lambda: _boom())
    assert upstream_guard.run("good:53", lambda: b"ok") == b"ok"


def test_success_resets_the_failure_count():
    for _ in range(upstream_guard.FAILURES_TO_OPEN - 1):
        with pytest.raises(OSError):
            upstream_guard.run("flaky:53", lambda: _boom())
    assert upstream_guard.run("flaky:53", lambda: b"ok") == b"ok"
    for _ in range(upstream_guard.FAILURES_TO_OPEN - 1):
        with pytest.raises(OSError):
            upstream_guard.run("flaky:53", lambda: _boom())
    assert upstream_guard.run("flaky:53", lambda: b"ok") == b"ok"


def test_errors_that_are_not_network_failures_do_not_count():
    for _ in range(upstream_guard.FAILURES_TO_OPEN + 2):
        with pytest.raises(ValueError):
            upstream_guard.run("odd:53", lambda: (_ for _ in ()).throw(ValueError("not a DNS message")))
    assert upstream_guard.run("odd:53", lambda: b"ok") == b"ok"


def test_one_probe_after_the_cool_down_then_back_to_normal(monkeypatch):
    now = [1000.0]
    monkeypatch.setattr(upstream_guard.time, "monotonic", lambda: now[0])
    for _ in range(upstream_guard.FAILURES_TO_OPEN):
        with pytest.raises(OSError):
            upstream_guard.run("down:53", lambda: _boom())
    now[0] += upstream_guard.OPEN_SECONDS + 1

    seen_during_probe = []

    def probe():
        # while the probe is out, everyone else is still skipped
        with pytest.raises(upstream_guard.UpstreamSkipped):
            upstream_guard.run("down:53", lambda: b"second")
        seen_during_probe.append(True)
        return b"answer"

    assert upstream_guard.run("down:53", probe) == b"answer"
    assert seen_during_probe == [True]
    assert upstream_guard.run("down:53", lambda: b"again") == b"again"


def test_failed_probe_doubles_the_cool_down(monkeypatch):
    now = [1000.0]
    monkeypatch.setattr(upstream_guard.time, "monotonic", lambda: now[0])
    for _ in range(upstream_guard.FAILURES_TO_OPEN):
        with pytest.raises(OSError):
            upstream_guard.run("down:53", lambda: _boom())
    now[0] += upstream_guard.OPEN_SECONDS + 1
    with pytest.raises(OSError):
        upstream_guard.run("down:53", lambda: _boom())

    now[0] += upstream_guard.OPEN_SECONDS + 1  # not yet: the cool-down is twice as long now
    with pytest.raises(upstream_guard.UpstreamSkipped):
        upstream_guard.run("down:53", lambda: b"x")
    now[0] += upstream_guard.OPEN_SECONDS
    assert upstream_guard.run("down:53", lambda: b"x") == b"x"


def test_silent_upstream_costs_one_timeout_each_then_nothing():
    """A UDP upstream that never answers: the first queries each wait their
    timeout, after that the upstream is skipped instantly."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("127.0.0.1", 0))
    address = f"127.0.0.1:{sock.getsockname()[1]}"
    try:
        results = []

        def ask():
            try:
                upstream.forward(QUERY, address, 0.3)
            except OSError as exc:
                results.append(exc)

        threads = [threading.Thread(target=ask) for _ in range(upstream_guard.FAILURES_TO_OPEN)]
        started = time.monotonic()
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(5)
        assert time.monotonic() - started < 2.0
        assert len(results) == upstream_guard.FAILURES_TO_OPEN
        assert all(isinstance(exc, TimeoutError) for exc in results)

        started = time.monotonic()
        with pytest.raises(upstream_guard.UpstreamSkipped):
            upstream.forward(QUERY, address, 0.3)
        assert time.monotonic() - started < 0.1
    finally:
        sock.close()


def test_empty_timeout_gets_a_message_naming_the_upstream(monkeypatch):
    def silent(data, upstream_name, timeout):
        raise TimeoutError

    monkeypatch.setattr(upstream, "_forward", silent)
    with pytest.raises(TimeoutError, match=r"quic://x\.example did not answer within 2s"):
        upstream.forward(QUERY, "quic://x.example", 2.0)


def test_timeout_that_already_has_a_message_is_left_alone(monkeypatch):
    def silent(data, upstream_name, timeout):
        raise TimeoutError("no matching response from 1.1.1.1:53")

    monkeypatch.setattr(upstream, "_forward", silent)
    with pytest.raises(TimeoutError, match="no matching response from 1.1.1.1:53"):
        upstream.forward(QUERY, "1.1.1.1:53", 2.0)


def test_name_lookup_is_bounded_by_the_timeout(monkeypatch):
    release = threading.Event()

    def hanging_getaddrinfo(*_args, **_kwargs):
        release.wait(5)
        return []

    monkeypatch.setattr(upstream.socket, "getaddrinfo", hanging_getaddrinfo)
    started = time.monotonic()
    try:
        with pytest.raises(TimeoutError, match="looking up slow.example.invalid"):
            upstream._connect("slow.example.invalid", 853, 0.3)
        assert time.monotonic() - started < 2.0
    finally:
        release.set()


def test_connect_to_an_ip_literal_needs_no_lookup(monkeypatch):
    class _NoLookups:
        def submit(self, *_args, **_kwargs):
            raise AssertionError("no name lookup is needed for an IP literal")

    listener = socket.create_server(("127.0.0.1", 0))
    monkeypatch.setattr(upstream, "_resolve_pool", _NoLookups())
    try:
        with upstream._connect("127.0.0.1", listener.getsockname()[1], 1.0) as sock:
            assert sock.getpeername()[0] == "127.0.0.1"
    finally:
        listener.close()
