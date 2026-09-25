from __future__ import annotations

import logging

from pyroute2 import IPRoute
from pyroute2.netlink.exceptions import NetlinkError

logger = logging.getLogger("dnsshield.dhcp.vlan")


def vlan_interface_name(parent: str, vlan_id: int) -> str:
    return f"{parent}.{vlan_id}"


def ensure_vlan_interface(parent: str, vlan_id: int) -> str | None:
    ifname = vlan_interface_name(parent, vlan_id)
    with IPRoute() as ipr:
        existing = ipr.link_lookup(ifname=ifname)
        if existing:
            ipr.link("set", index=existing[0], state="up")
            return ifname

        parent_idx = ipr.link_lookup(ifname=parent)
        if not parent_idx:
            logger.error("cannot create VLAN %d: parent interface %r not found", vlan_id, parent)
            return None

        try:
            ipr.link("add", ifname=ifname, kind="vlan", link=parent_idx[0], vlan_id=vlan_id)
            new_idx = ipr.link_lookup(ifname=ifname)[0]
            ipr.link("set", index=new_idx, state="up")
        except NetlinkError as exc:
            logger.error(
                "could not create VLAN interface %s (needs NET_ADMIN capability and a real parent link): %s",
                ifname,
                exc,
            )
            return None
    return ifname


def teardown_vlan_interface(parent: str, vlan_id: int) -> None:
    ifname = vlan_interface_name(parent, vlan_id)
    with IPRoute() as ipr:
        existing = ipr.link_lookup(ifname=ifname)
        if not existing:
            return
        try:
            ipr.link("del", index=existing[0])
        except NetlinkError as exc:
            logger.warning("could not remove VLAN interface %s: %s", ifname, exc)


def list_interfaces() -> list[str]:
    with IPRoute() as ipr:
        names = []
        for link in ipr.get_links():
            name = link.get_attr("IFLA_IFNAME")
            if name and name != "lo":
                names.append(name)
        return names
