from app.blocklist import BlocklistManager
from app.upstream import _split_host_port, hostname_of


def test_split_host_port_hostname_with_custom_port():
    assert _split_host_port("dns.example.com:5353", 53) == ("dns.example.com", 5353)


def test_split_host_port_ipv4_with_custom_port():
    assert _split_host_port("192.168.1.10:5353", 53) == ("192.168.1.10", 5353)


def test_split_host_port_bare_host_uses_default_port():
    assert _split_host_port("1.1.1.1", 53) == ("1.1.1.1", 53)
    assert _split_host_port("dns.example.com", 853) == ("dns.example.com", 853)


def test_split_host_port_bare_ipv6_literal_uses_default_port():
    assert _split_host_port("2606:4700:4700::1111", 53) == ("2606:4700:4700::1111", 53)


def test_split_host_port_bracketed_ipv6_with_custom_port():
    assert _split_host_port("[2606:4700:4700::1111]:5353", 53) == ("2606:4700:4700::1111", 5353)


def test_split_host_port_bracketed_ipv6_without_port_uses_default():
    assert _split_host_port("[2606:4700:4700::1111]", 853) == ("2606:4700:4700::1111", 853)


def test_split_host_port_bracketed_loopback_ipv6():
    assert _split_host_port("[::1]:8853", 853) == ("::1", 8853)


def test_hostname_of_ignores_custom_port():
    assert hostname_of("dns.example.com:5353") == "dns.example.com"


def test_hostname_of_returns_none_for_bare_ipv4():
    assert hostname_of("1.1.1.1:53") is None


def test_hostname_of_returns_none_for_bracketed_ipv6_with_port():
    assert hostname_of("[2606:4700:4700::1111]:53") is None


def test_hostname_of_returns_none_for_bare_ipv6():
    assert hostname_of("2606:4700:4700::1111") is None


def test_hostname_of_dot_hostname_with_custom_port():
    assert hostname_of("dot://dns.example.com:8853") == "dns.example.com"


def test_hostname_of_doh_url_with_custom_port():
    assert hostname_of("doh://dns.example.com:8443/dns-query") == "dns.example.com"


def test_split_host_port_never_raises_on_malformed_port():
    assert _split_host_port("dns.example.com:notaport", 53) == ("dns.example.com", 53)
    assert _split_host_port("[::1]:notaport", 853) == ("::1", 853)
    assert _split_host_port("dns.example.com:", 53) == ("dns.example.com", 53)
    assert _split_host_port("dns.example.com:-1", 53) == ("dns.example.com", 53)


def test_hostname_of_never_raises_on_malformed_port():
    assert hostname_of("dns.example.com:notaport") == "dns.example.com"
    assert hostname_of("[2606:4700:4700::1111]:notaport") is None


def test_block_reason_survives_malformed_upstream_entry(config_store, tmp_path):
    config_store.mutate(lambda d: d.setdefault("enrichment", {}).update({"public_enabled": True}))
    config_store.mutate(lambda d: d.setdefault("dns", {}).update(
        {"upstreams": ["dns.example.com:notaport", "1.1.1.1:53"]}
    ))
    blocklist = BlocklistManager(config_store, tmp_path / "cache")
    assert blocklist.block_reason("example.com", "1.2.3.4") is None
