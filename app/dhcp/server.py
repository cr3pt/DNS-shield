# SPDX-License-Identifier: BSD-3-Clause AND LicenseRef-Commons-Clause
# See the LICENSE file in the project root for full license terms.

from __future__ import annotations

import ipaddress
import logging
import socket
import threading
import time
from pathlib import Path
from typing import Any

from app.dhcp import protocol as proto
from app.dhcp import vlan
from app.dhcp.leases import LeaseStore, find_free_ip
from app.dhcp.options import build_reply_options, find_reservation

logger = logging.getLogger("dnsshield.dhcp")


def _client_id(request: proto.DhcpPacket) -> str | None:
    raw = request.options.get(proto.OPT_CLIENT_IDENTIFIER)
    return raw.hex() if raw else None


def _in_pool(scope: dict[str, Any], ip: str) -> bool:
    value = int(ipaddress.IPv4Address(ip))
    start = int(ipaddress.IPv4Address(scope["pool_start"]))
    end = int(ipaddress.IPv4Address(scope["pool_end"]))
    return start <= value <= end


def determine_offer_ip(
    scope: dict[str, Any],
    lease_store: LeaseStore,
    mac: str,
    reservation: dict[str, Any] | None,
    requested_ip: str | None,
    now: float | None = None,
) -> str | None:
    if reservation:
        return reservation["ip"]

    now = time.time() if now is None else now
    existing = lease_store.get_by_mac(mac)
    preferred = existing["ip"] if existing and existing["scope"] == scope["name"] else requested_ip

    taken = lease_store.taken_ips(scope["name"], exclude_mac=mac, now=now)
    declined = lease_store.declined_ips(scope["name"], now=now)
    excluded = set(scope.get("excluded_ips") or [])
    gateway = scope.get("gateway") or ""
    if gateway:
        excluded.add(gateway)

    return find_free_ip(scope["pool_start"], scope["pool_end"], taken, excluded | declined, preferred)


def _build_reply(
    request: proto.DhcpPacket,
    message_type: int,
    offered_ip: str,
    scope: dict[str, Any],
    reservation: dict[str, Any] | None,
    server_ip: str,
    lease_seconds: float,
    include_lease_options: bool = True,
) -> proto.DhcpPacket:
    options = {proto.OPT_MESSAGE_TYPE: bytes([message_type])}
    if include_lease_options:
        options.update(build_reply_options(scope, reservation, server_ip, lease_seconds))
    else:
        options[proto.OPT_SERVER_IDENTIFIER] = ipaddress.IPv4Address(server_ip).packed

    hostname = (reservation or {}).get("hostname")
    if hostname:
        options[proto.OPT_HOSTNAME] = hostname.encode("ascii", errors="ignore")

    return proto.DhcpPacket(
        op=proto.BOOTREPLY,
        htype=request.htype,
        hlen=request.hlen,
        xid=request.xid,
        flags=request.flags,
        ciaddr="0.0.0.0",
        yiaddr=offered_ip,
        siaddr=server_ip,
        giaddr=request.giaddr,
        chaddr=request.chaddr,
        options=options,
    )


def _build_nak(request: proto.DhcpPacket, server_ip: str) -> proto.DhcpPacket:
    return proto.DhcpPacket(
        op=proto.BOOTREPLY,
        htype=request.htype,
        hlen=request.hlen,
        xid=request.xid,
        flags=request.flags,
        giaddr=request.giaddr,
        chaddr=request.chaddr,
        options={
            proto.OPT_MESSAGE_TYPE: bytes([proto.NAK]),
            proto.OPT_SERVER_IDENTIFIER: ipaddress.IPv4Address(server_ip).packed,
        },
    )


def handle_packet(
    scope: dict[str, Any],
    request: proto.DhcpPacket,
    lease_store: LeaseStore,
    server_ip: str,
    now: float | None = None,
) -> proto.DhcpPacket | None:
    now = time.time() if now is None else now
    message_type = request.message_type
    if message_type is None:
        return None

    mac = request.client_mac
    reservation = find_reservation(scope, mac)
    lease_seconds = float(scope.get("lease_seconds", 86400) or 86400)

    if message_type == proto.DISCOVER:
        offered_ip = determine_offer_ip(scope, lease_store, mac, reservation, request.requested_ip, now)
        if offered_ip is None:
            logger.warning("DHCP pool exhausted for scope %r (client %s)", scope["name"], mac)
            return None
        lease_store.commit_lease(
            mac, offered_ip, scope["name"], request.hostname, _client_id(request), lease_seconds,
            static=bool(reservation), now=now,
        )
        return _build_reply(request, proto.OFFER, offered_ip, scope, reservation, server_ip, lease_seconds)

    if message_type == proto.REQUEST:
        server_id = request.server_identifier
        if server_id and server_id != server_ip:
            return None

        requested = request.requested_ip or (request.ciaddr if request.ciaddr != "0.0.0.0" else None)
        if requested is None:
            return _build_nak(request, server_ip)

        if reservation:
            if requested != reservation["ip"]:
                return _build_nak(request, server_ip)
        else:
            if not _in_pool(scope, requested):
                return _build_nak(request, server_ip)
            taken = lease_store.taken_ips(scope["name"], exclude_mac=mac, now=now)
            declined = lease_store.declined_ips(scope["name"], now=now)
            excluded = set(scope.get("excluded_ips") or [])
            if requested in taken or requested in excluded or requested in declined:
                return _build_nak(request, server_ip)

        lease_store.commit_lease(
            mac, requested, scope["name"], request.hostname, _client_id(request), lease_seconds,
            static=bool(reservation), now=now,
        )
        return _build_reply(request, proto.ACK, requested, scope, reservation, server_ip, lease_seconds)

    if message_type == proto.RELEASE:
        lease_store.release(mac)
        return None

    if message_type == proto.DECLINE:
        declined_ip = request.requested_ip or (request.ciaddr if request.ciaddr != "0.0.0.0" else None)
        if declined_ip:
            lease_store.decline(declined_ip, scope["name"], now=now)
        lease_store.release(mac)
        return None

    if message_type == proto.INFORM:
        return _build_reply(
            request, proto.ACK, request.ciaddr, scope, reservation, server_ip, lease_seconds,
            include_lease_options=False,
        )

    return None


class ScopeListener:
    def __init__(self, scope_name: str, config_store, lease_store: LeaseStore, on_new_client=None):
        self._scope_name = scope_name
        self._config = config_store
        self._lease_store = lease_store
        self._on_new_client = on_new_client
        self._sock: socket.socket | None = None
        self._thread: threading.Thread | None = None
        self._stop_event = threading.Event()

    def _scope(self) -> dict[str, Any] | None:
        for scope in self._config.get("dhcp", "scopes", default=[]) or []:
            if scope.get("name") == self._scope_name:
                return scope
        return None

    def start(self) -> bool:
        scope = self._scope()
        if scope is None:
            return False

        interface = scope.get("interface") or ""
        vlan_id = scope.get("vlan_id") or 0
        if vlan_id:
            resolved = vlan.ensure_vlan_interface(interface, int(vlan_id))
            if resolved is None:
                return False
            interface = resolved

        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        bindtodevice = getattr(socket, "SO_BINDTODEVICE", None)
        if bindtodevice is not None and interface:
            try:
                sock.setsockopt(socket.SOL_SOCKET, bindtodevice, interface.encode() + b"\x00")
            except OSError as exc:
                logger.error("could not bind DHCP scope %r to interface %s: %s", self._scope_name, interface, exc)
                sock.close()
                return False
        try:
            sock.bind(("0.0.0.0", 67))
        except OSError as exc:
            logger.error("could not bind DHCP scope %r to port 67: %s", self._scope_name, exc)
            sock.close()
            return False

        self._sock = sock
        self._thread = threading.Thread(target=self._loop, name=f"dhcp-{self._scope_name}", daemon=True)
        self._thread.start()
        logger.info("DHCP scope %r listening on %s", self._scope_name, interface or "0.0.0.0")
        return True

    def stop(self) -> None:
        self._stop_event.set()
        if self._sock is not None:
            self._sock.close()

    def _loop(self) -> None:
        while not self._stop_event.is_set():
            try:
                data, _addr = self._sock.recvfrom(4096)
            except OSError:
                return
            scope = self._scope()
            if scope is None or not scope.get("enabled", True):
                continue
            try:
                request = proto.parse(data)
            except ValueError:
                continue
            if request.op != proto.BOOTREQUEST:
                continue

            server_ip = scope.get("server_ip") or ""
            if not server_ip:
                continue

            try:
                reply = handle_packet(scope, request, self._lease_store, server_ip)
            except Exception:
                logger.exception("error handling DHCP packet on scope %r", self._scope_name)
                continue
            if reply is not None:
                self._send(reply)
                if request.message_type == proto.REQUEST and reply.message_type == proto.ACK and self._on_new_client:
                    mac = request.client_mac
                    if self._lease_store.mark_known(mac):
                        try:
                            self._on_new_client(mac, reply.yiaddr, self._scope_name)
                        except Exception:
                            logger.exception("on_new_client callback failed")

    def _send(self, reply: proto.DhcpPacket) -> None:
        dest = "255.255.255.255" if reply.ciaddr == "0.0.0.0" else reply.ciaddr
        try:
            self._sock.sendto(proto.build(reply), (dest, 68))
        except OSError:
            logger.exception("failed to send DHCP reply for scope %r", self._scope_name)


class DhcpServer:
    def __init__(self, config_store, data_dir: Path, on_new_client=None):
        self._config = config_store
        self._lease_store = LeaseStore(data_dir / "dhcp_leases.db")
        self._on_new_client = on_new_client
        self._listeners: list[ScopeListener] = []
        self._stop_event = threading.Event()
        self._sweep_thread: threading.Thread | None = None

    @property
    def lease_store(self) -> LeaseStore:
        return self._lease_store

    def start(self) -> None:
        if not self._config.get("dhcp", "enabled", default=False):
            return
        for scope in self._config.get("dhcp", "scopes", default=[]) or []:
            if not scope.get("enabled", True):
                continue
            listener = ScopeListener(scope["name"], self._config, self._lease_store, self._on_new_client)
            if listener.start():
                self._listeners.append(listener)

        self._sweep_thread = threading.Thread(target=self._sweep_loop, name="dhcp-lease-sweep", daemon=True)
        self._sweep_thread.start()

    def stop(self) -> None:
        self._stop_event.set()
        for listener in self._listeners:
            listener.stop()

    def _sweep_loop(self) -> None:
        while not self._stop_event.wait(300):
            try:
                self._lease_store.expire_sweep()
            except Exception:
                logger.exception("DHCP lease expiry sweep failed")
