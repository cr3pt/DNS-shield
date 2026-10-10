# SPDX-License-Identifier: BSD-3-Clause AND LicenseRef-Commons-Clause
# See the LICENSE file in the project root for full license terms.

from __future__ import annotations

import logging
import random
import socket
import threading
import time

from app.dhcp import protocol as proto

logger = logging.getLogger("dnsshield.dhcp.rogue_detector")

_RANDOM_MAC_PREFIX = "02:00:00"


def _probe_mac() -> bytes:
    suffix = random.randbytes(3)
    return proto.parse_mac(_RANDOM_MAC_PREFIX + ":" + ":".join(f"{b:02x}" for b in suffix))


def find_rogue_servers(responder_ips: set[str], allowed_ips: set[str]) -> set[str]:
    return responder_ips - allowed_ips


def discover_dhcp_servers(interface: str | None, listen_seconds: float = 4.0) -> set[str]:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    bindtodevice = getattr(socket, "SO_BINDTODEVICE", None)
    if bindtodevice is not None and interface:
        try:
            sock.setsockopt(socket.SOL_SOCKET, bindtodevice, interface.encode() + b"\x00")
        except OSError as exc:
            logger.warning("rogue-DHCP probe could not bind to interface %s: %s", interface, exc)

    responders: set[str] = set()
    try:
        sock.bind(("0.0.0.0", 68))
    except OSError as exc:
        logger.warning("rogue-DHCP probe could not bind to port 68: %s", exc)
        sock.close()
        return responders

    xid = random.randint(1, 0xFFFFFFFF)
    discover = proto.DhcpPacket(
        op=proto.BOOTREQUEST,
        xid=xid,
        flags=proto.FLAG_BROADCAST,
        chaddr=_probe_mac() + b"\x00" * 10,
        options={
            proto.OPT_MESSAGE_TYPE: bytes([proto.DISCOVER]),
            proto.OPT_PARAMETER_REQUEST_LIST: bytes([proto.OPT_SUBNET_MASK, proto.OPT_ROUTER, proto.OPT_DNS_SERVERS]),
        },
    )
    try:
        sock.sendto(proto.build(discover), ("255.255.255.255", 67))
    except OSError as exc:
        logger.warning("rogue-DHCP probe could not send DISCOVER: %s", exc)
        sock.close()
        return responders

    sock.settimeout(0.5)
    deadline = time.monotonic() + listen_seconds
    while time.monotonic() < deadline:
        try:
            data, addr = sock.recvfrom(4096)
        except socket.timeout:
            continue
        except OSError:
            break
        try:
            reply = proto.parse(data)
        except ValueError:
            continue
        if reply.xid != xid or reply.message_type != proto.OFFER:
            continue
        responders.add(reply.server_identifier or addr[0])

    sock.close()
    return responders


class RogueDhcpDetector:
    def __init__(self, config_store, anomaly_detector=None):
        self._config = config_store
        self._anomaly = anomaly_detector
        self._stop_event = threading.Event()
        self._thread: threading.Thread | None = None
        self._last_alerted: dict[str, float] = {}

    def start(self) -> None:
        if not self._config.get("rogue_dhcp_detection", "enabled", default=False):
            return
        self._thread = threading.Thread(target=self._loop, name="rogue-dhcp-detector", daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop_event.set()

    def _allowed_ips(self) -> set[str]:
        allowed = set(self._config.get("rogue_dhcp_detection", "allowed_server_ips", default=[]) or [])
        for scope in self._config.get("dhcp", "scopes", default=[]) or []:
            server_ip = scope.get("server_ip")
            if server_ip:
                allowed.add(server_ip)
        return allowed

    def check_once(self) -> list[dict]:
        interfaces = self._config.get("rogue_dhcp_detection", "interfaces", default=[]) or [None]
        responders: set[str] = set()
        for interface in interfaces:
            responders |= discover_dhcp_servers(interface)

        rogue = find_rogue_servers(responders, self._allowed_ips())
        if not rogue or self._anomaly is None:
            return []

        cooldown_seconds = max(
            float(self._config.get("rogue_dhcp_detection", "cooldown_minutes", default=60) or 60), 1.0
        ) * 60
        now = time.time()
        found = []
        for server_ip in sorted(rogue):
            last = self._last_alerted.get(server_ip)
            if last is not None and now - last < cooldown_seconds:
                continue
            self._last_alerted[server_ip] = now
            summary = f"DHCP offer from unrecognized server {server_ip}"
            entry = self._anomaly.record_external_alert(
                client=server_ip,
                kind="rogue_dhcp_server",
                severity="high",
                summary=summary,
                details={"server_ip": server_ip, "allowed_ips": sorted(self._allowed_ips())},
            )
            found.append(entry)
        return found

    def _loop(self) -> None:
        while not self._stop_event.is_set():
            interval_minutes = self._config.get("rogue_dhcp_detection", "check_interval_minutes", default=15) or 15
            interval = max(float(interval_minutes), 1.0) * 60
            if self._stop_event.wait(interval):
                return
            if not self._config.get("rogue_dhcp_detection", "enabled", default=False):
                continue
            try:
                self.check_once()
            except Exception:
                logger.exception("rogue-DHCP check failed")
