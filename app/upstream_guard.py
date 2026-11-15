# SPDX-License-Identifier: BSD-3-Clause AND LicenseRef-Commons-Clause
# See the LICENSE file in the project root for full license terms.

"""Keeps one failing upstream from stalling every query.

Every upstream query goes through run(). After FAILURES_TO_OPEN failures in a
row an upstream is skipped without touching the network for OPEN_SECONDS - the
resolver moves on to the next upstream (or serves a stale answer, or SERVFAIL)
at once instead of waiting out the timeout for every client query. When the
cool-down is over exactly one query is let through as a probe: if it works the
upstream is back, if it fails the cool-down doubles (up to MAX_OPEN_SECONDS).

Only network-type failures count (OSError, which includes timeouts, refused
connections and HTTP errors); a malformed query or a bug doesn't open the
breaker.
"""

from __future__ import annotations

import logging
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

logger = logging.getLogger("dnsshield.upstream")

FAILURES_TO_OPEN = 3
OPEN_SECONDS = 15.0
MAX_OPEN_SECONDS = 120.0


class UpstreamSkipped(ConnectionError):
    """Raised, without any network traffic, while an upstream is in its cool-down."""


@dataclass
class _State:
    failures: int = 0
    open_until: float = 0.0
    open_for: float = OPEN_SECONDS
    probing: bool = False


_states: dict[str, _State] = {}
_lock = threading.Lock()


def reset() -> None:
    """Forget everything (tests)."""
    with _lock:
        _states.clear()


def _describe(exc: BaseException) -> str:
    text = str(exc)
    return f"{type(exc).__name__}: {text}" if text else type(exc).__name__


def _enter(upstream: str) -> bool:
    """Let a query through, or raise UpstreamSkipped. True if it is the probe."""
    now = time.monotonic()
    with _lock:
        state = _states.get(upstream)
        if state is None or state.failures < FAILURES_TO_OPEN:
            return False
        if now < state.open_until:
            raise UpstreamSkipped(
                f"{upstream} skipped for another {state.open_until - now:.0f}s after {state.failures} failures in a row"
            )
        if state.probing:
            raise UpstreamSkipped(f"{upstream} is being probed")
        state.probing = True
        return True


def _leave(upstream: str, outcome: object, probe: bool) -> None:
    """outcome: True (answered), an exception, or None (cancelled)."""
    now = time.monotonic()
    with _lock:
        if outcome is True:
            state = _states.pop(upstream, None)
            if state is not None and state.failures >= FAILURES_TO_OPEN:
                logger.info("upstream %s is answering again", upstream)
            return
        state = _states.get(upstream)
        counts = isinstance(outcome, OSError)
        if not counts:
            if probe and state is not None:
                state.probing = False
            return
        if state is None:
            state = _states[upstream] = _State()
        state.failures += 1
        if probe:
            state.probing = False
            state.open_for = min(state.open_for * 2, MAX_OPEN_SECONDS)
            state.open_until = now + state.open_for
        elif state.failures == FAILURES_TO_OPEN:
            state.open_for = OPEN_SECONDS
            state.open_until = now + state.open_for
        else:
            return
        logger.warning(
            "upstream %s failed %d times in a row (last: %s) - skipping it for %.0fs",
            upstream,
            state.failures,
            _describe(outcome),
            state.open_for,
        )


def run(upstream: str, call: Callable[[], Any]) -> Any:
    """Run one query against `upstream` unless it is being skipped."""
    probe = _enter(upstream)
    outcome: object = None
    try:
        result = call()
        outcome = True
        return result
    except Exception as exc:
        outcome = exc
        raise
    finally:
        _leave(upstream, outcome, probe)
