# SPDX-License-Identifier: BSD-3-Clause AND LicenseRef-Commons-Clause
# See the LICENSE file in the project root for full license terms.

"""Forward every logged query to a syslog server / SIEM (logging.syslog_*).

Messages are RFC 5424, facility local0: severity notice for a blocked query,
info for the rest. The message text is key=value pairs ("text") or one JSON
object ("json"). UDP sends one datagram per message; TCP uses octet-counting
framing (RFC 6587) and reconnects on failure.

Sending happens on a background thread from a bounded queue: a slow or
unreachable syslog server never delays DNS answers - messages are dropped
(and counted) instead."""

from __future__ import annotations

import json
import logging
import os
import queue
import socket
import threading
import time
from datetime import timezone, datetime

logger = logging.getLogger("dnsshield.syslog")

_FACILITY_LOCAL0 = 16
_SEVERITY_NOTICE = 5
_SEVERITY_INFO = 6
_MAX_QUEUE = 10000
_MAX_UDP = 2048
_APP_NAME = "dns-shield"


def _sd_escape(value: str) -> str:
    return value.replace("\\", "\\\\").replace('"', '\\"').replace("]", "\\]")


def format_message(entry: dict, fmt: str = "text", hostname: str | None = None) -> bytes:
    severity = _SEVERITY_NOTICE if entry.get("blocked") else _SEVERITY_INFO
    pri = _FACILITY_LOCAL0 * 8 + severity
    timestamp = datetime.fromtimestamp(entry["ts"], tz=timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")
    host = (hostname or socket.gethostname() or "-").replace(" ", "_")[:255]
    fields = {
        "client": entry.get("client") or "",
        "domain": entry.get("domain") or "",
        "qtype": entry.get("qtype") or "",
        "blocked": 1 if entry.get("blocked") else 0,
        "reason": entry.get("reason") or "",
    }
    if fmt == "json":
        text = json.dumps({"ts": timestamp, **fields}, ensure_ascii=False)
    else:
        text = " ".join(f'{key}="{_sd_escape(str(value))}"' for key, value in fields.items())
    header = f"<{pri}>1 {timestamp} {host} {_APP_NAME} {os.getpid()} query - "
    return (header + text).encode("utf-8", "replace")


class SyslogForwarder:
    def __init__(self, config_store):
        self._config = config_store
        self._queue: queue.Queue[dict] = queue.Queue(maxsize=_MAX_QUEUE)
        self._dropped = 0
        self._sock: socket.socket | None = None
        self._target: tuple[str, int, str] | None = None
        self._started = False
        self._start_lock = threading.Lock()
        self._hostname = socket.gethostname()

    def _settings(self) -> dict:
        cfg = self._config.get("logging", default={}) or {}
        return cfg if isinstance(cfg, dict) else {}

    def enabled(self) -> bool:
        cfg = self._settings()
        return bool(cfg.get("syslog_enabled")) and bool(cfg.get("syslog_host"))

    def submit(self, entry: dict) -> None:
        """Queue one logged query (dict with ts, client, domain, qtype, blocked, reason)."""
        if not self.enabled():
            return
        cfg = self._settings()
        if cfg.get("syslog_only_blocked") and not entry.get("blocked"):
            return
        self._ensure_started()
        try:
            self._queue.put_nowait(entry)
        except queue.Full:
            self._dropped += 1
            if self._dropped % 10000 == 1:
                logger.warning("syslog queue full - dropped %d message(s) so far", self._dropped)

    def _ensure_started(self) -> None:
        if self._started:
            return
        with self._start_lock:
            if not self._started:
                threading.Thread(target=self._run, name="syslog-forwarder", daemon=True).start()
                self._started = True

    def _run(self) -> None:
        while True:
            entry = self._queue.get()
            try:
                self._send(entry)
            except Exception as exc:  # never let the thread die
                logger.debug("syslog send failed: %s", exc)
            finally:
                self._queue.task_done()

    def _connect(self, host: str, port: int, protocol: str) -> socket.socket:
        family, socktype, proto, _name, addr = socket.getaddrinfo(
            host, port, type=socket.SOCK_STREAM if protocol == "tcp" else socket.SOCK_DGRAM
        )[0]
        sock = socket.socket(family, socktype, proto)
        sock.settimeout(5)
        sock.connect(addr)
        return sock

    def _close(self) -> None:
        if self._sock is not None:
            try:
                self._sock.close()
            except OSError:
                pass
        self._sock = None

    def _send(self, entry: dict) -> None:
        cfg = self._settings()
        host = str(cfg.get("syslog_host") or "")
        if not host:
            return
        port = int(cfg.get("syslog_port") or 514)
        protocol = "tcp" if cfg.get("syslog_protocol") == "tcp" else "udp"
        fmt = "json" if cfg.get("syslog_format") == "json" else "text"
        target = (host, port, protocol)
        if target != self._target:
            self._close()
            self._target = target
        message = format_message(entry, fmt, self._hostname)
        for attempt in range(2):
            try:
                if self._sock is None:
                    self._sock = self._connect(host, port, protocol)
                if protocol == "tcp":
                    self._sock.sendall(f"{len(message)} ".encode() + message)
                else:
                    self._sock.send(message[:_MAX_UDP])
                return
            except OSError as exc:
                self._close()
                if attempt:
                    logger.debug("syslog to %s:%d/%s failed: %s", host, port, protocol, exc)
                    # Don't spin on a dead server.
                    time.sleep(1)

    def drain(self, timeout: float = 2.0) -> None:
        """Wait until queued messages are sent (tests)."""
        deadline = time.monotonic() + timeout
        while self._queue.unfinished_tasks and time.monotonic() < deadline:
            time.sleep(0.01)
