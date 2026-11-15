# SPDX-License-Identifier: BSD-3-Clause AND LicenseRef-Commons-Clause
# See the LICENSE file in the project root for full license terms.

"""A slow upstream must not use up every worker thread."""

import threading

import pytest

from app import upstream_guard


class _Blocked:
    """Holds `count` queries inside run() until release() is called."""

    def __init__(self, upstream: str, count: int):
        self._release = threading.Event()
        self._entered = threading.Semaphore(0)
        self.threads = [threading.Thread(target=self._wait, args=(upstream,)) for _ in range(count)]
        for thread in self.threads:
            thread.start()
        for _ in range(count):
            assert self._entered.acquire(timeout=5)

    def _wait(self, upstream: str) -> None:
        def slow() -> bytes:
            self._entered.release()
            self._release.wait(5)
            return b"late"

        upstream_guard.run(upstream, slow)

    def release(self) -> None:
        self._release.set()
        for thread in self.threads:
            thread.join(5)


def test_queries_beyond_the_limit_are_skipped_at_once(monkeypatch):
    monkeypatch.setattr(upstream_guard, "MAX_IN_FLIGHT", 2)
    blocked = _Blocked("slow:53", 2)
    try:
        with pytest.raises(upstream_guard.UpstreamSkipped, match="already waiting"):
            upstream_guard.run("slow:53", lambda: b"never called")
        assert upstream_guard.run("other:53", lambda: b"fine") == b"fine"
    finally:
        blocked.release()
    assert upstream_guard.run("slow:53", lambda: b"free again") == b"free again"


def test_skipped_queries_do_not_open_the_breaker(monkeypatch):
    monkeypatch.setattr(upstream_guard, "MAX_IN_FLIGHT", 1)
    blocked = _Blocked("slow:53", 1)
    try:
        for _ in range(upstream_guard.FAILURES_TO_OPEN + 2):
            with pytest.raises(upstream_guard.UpstreamSkipped, match="already waiting"):
                upstream_guard.run("slow:53", lambda: b"x")
    finally:
        blocked.release()
    assert upstream_guard.run("slow:53", lambda: b"ok") == b"ok"


def test_a_slot_is_freed_when_the_query_fails(monkeypatch):
    monkeypatch.setattr(upstream_guard, "MAX_IN_FLIGHT", 1)
    for _ in range(upstream_guard.FAILURES_TO_OPEN - 1):
        with pytest.raises(TimeoutError):
            upstream_guard.run("flaky:53", lambda: (_ for _ in ()).throw(TimeoutError()))
    assert upstream_guard.run("flaky:53", lambda: b"ok") == b"ok"


def test_a_slot_is_freed_by_an_error_that_is_not_a_network_failure(monkeypatch):
    monkeypatch.setattr(upstream_guard, "MAX_IN_FLIGHT", 1)
    for _ in range(3):
        with pytest.raises(ValueError):
            upstream_guard.run("odd:53", lambda: (_ for _ in ()).throw(ValueError("bad query")))
    assert upstream_guard.run("odd:53", lambda: b"ok") == b"ok"


def test_a_probe_is_not_stuck_when_the_limit_is_hit(monkeypatch):
    now = [1000.0]
    monkeypatch.setattr(upstream_guard.time, "monotonic", lambda: now[0])
    for _ in range(upstream_guard.FAILURES_TO_OPEN):
        with pytest.raises(OSError):
            upstream_guard.run("down:53", lambda: (_ for _ in ()).throw(ConnectionError("refused")))
    now[0] += upstream_guard.OPEN_SECONDS + 1

    monkeypatch.setattr(upstream_guard, "MAX_IN_FLIGHT", 0)
    with pytest.raises(upstream_guard.UpstreamSkipped, match="already waiting"):
        upstream_guard.run("down:53", lambda: b"x")
    monkeypatch.setattr(upstream_guard, "MAX_IN_FLIGHT", 32)

    assert upstream_guard.run("down:53", lambda: b"probe works") == b"probe works"
