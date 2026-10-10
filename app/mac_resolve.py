# SPDX-License-Identifier: BSD-3-Clause AND LicenseRef-Commons-Clause
# See the LICENSE file in the project root for full license terms.

from __future__ import annotations

import logging
import threading
import time
from pathlib import Path

logger = logging.getLogger("dnsshield.mac_resolve")

_ARP_TABLE_PATH = Path("/proc/net/arp")


def _read_arp_table() -> dict[str, str]:
    table: dict[str, str] = {}
    try:
        lines = _ARP_TABLE_PATH.read_text().splitlines()
    except OSError as exc:
        logger.debug("could not read %s: %s", _ARP_TABLE_PATH, exc)
        return table

    for line in lines[1:]:
        parts = line.split()
        if len(parts) < 4:
            continue
        ip, mac, flags = parts[0], parts[3], parts[2]
        if flags == "0x0" or mac in ("00:00:00:00:00:00", "<incomplete>"):
            continue
        table[ip] = mac.upper()
    return table


class MacResolver:
    def __init__(self, refresh_seconds: float = 30.0):
        self._refresh_seconds = refresh_seconds
        self._lock = threading.Lock()
        self._table: dict[str, str] = {}
        self._stop_event = threading.Event()
        self._thread: threading.Thread | None = None

    def start(self) -> None:
        if self._thread is not None:
            return
        self._refresh()
        self._thread = threading.Thread(target=self._loop, name="mac-resolver", daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop_event.set()

    def _loop(self) -> None:
        while not self._stop_event.wait(self._refresh_seconds):
            self._refresh()

    def _refresh(self) -> None:
        table = _read_arp_table()
        with self._lock:
            self._table = table

    def mac_for(self, ip: str) -> str | None:
        with self._lock:
            return self._table.get(ip)

    def snapshot(self) -> dict[str, str]:
        with self._lock:
            return dict(self._table)
