import pytest

from app.url_safety import check_public_url


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
