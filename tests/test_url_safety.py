import socket

import pytest

from app.url_safety import check_public_url, public_dns_guard


def test_check_public_url_rejects_loopback():
    with pytest.raises(ValueError, match="private/loopback/link-local"):
        check_public_url("http://127.0.0.1:8899/")


def test_check_public_url_rejects_private_rfc1918():
    with pytest.raises(ValueError, match="private/loopback/link-local"):
        check_public_url("http://192.168.1.50/list.txt")


def test_check_public_url_rejects_link_local():
    with pytest.raises(ValueError, match="private/loopback/link-local"):
        check_public_url("http://169.254.169.254/latest/meta-data/")


def test_check_public_url_rejects_non_http_scheme():
    with pytest.raises(ValueError, match="http"):
        check_public_url("file:///etc/passwd")


def test_check_public_url_rejects_url_with_no_hostname():
    with pytest.raises(ValueError, match="hostname"):
        check_public_url("http:///path")


def test_check_public_url_allows_public_ip_literal():
    check_public_url("http://1.1.1.1/list.txt")


def test_public_dns_guard_blocks_resolution_that_is_only_private():
    with public_dns_guard("http://localhost/list.txt"):
        with pytest.raises(socket.gaierror, match="SSRF guard"):
            socket.getaddrinfo("localhost", 80)


def test_public_dns_guard_is_a_noop_outside_the_context():
    infos = socket.getaddrinfo("localhost", 80)
    assert infos


def test_public_dns_guard_does_not_block_public_resolution():
    with public_dns_guard("http://1.1.1.1/list.txt"):
        infos = socket.getaddrinfo("1.1.1.1", 443)
    assert infos


def test_public_dns_guard_does_not_affect_unrelated_hostnames():
    with public_dns_guard("http://example.invalid/list.txt"):
        infos = socket.getaddrinfo("localhost", 80)
    assert infos


def test_public_dns_guard_closes_toctou_gap_after_rebind(monkeypatch):
    import app.url_safety as url_safety

    true_getaddrinfo = url_safety._real_getaddrinfo
    calls = {"count": 0}

    def rebinding_getaddrinfo(host, *args, **kwargs):
        calls["count"] += 1
        if host == "rebind.example":
            fake_ip = "1.1.1.1" if calls["count"] == 1 else "127.0.0.1"
            return true_getaddrinfo(fake_ip, *args, **kwargs)
        return true_getaddrinfo(host, *args, **kwargs)

    monkeypatch.setattr(url_safety, "_real_getaddrinfo", rebinding_getaddrinfo)

    check_public_url("http://rebind.example/list.txt")

    with public_dns_guard("http://rebind.example/list.txt"):
        with pytest.raises(socket.gaierror, match="SSRF guard"):
            socket.getaddrinfo("rebind.example", 80)
