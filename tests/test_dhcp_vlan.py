from app.dhcp.vlan import ensure_vlan_interface, list_interfaces, vlan_interface_name


def test_vlan_interface_name_format():
    assert vlan_interface_name("eth0", 10) == "eth0.10"


def test_list_interfaces_returns_real_names_without_loopback():
    interfaces = list_interfaces()
    assert "lo" not in interfaces
    assert isinstance(interfaces, list)


def test_ensure_vlan_interface_returns_none_for_missing_parent():
    assert ensure_vlan_interface("no-such-interface-xyz", 10) is None
