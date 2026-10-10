# SPDX-License-Identifier: BSD-3-Clause AND LicenseRef-Commons-Clause
# See the LICENSE file in the project root for full license terms.

import pytest

from app.proxy.domain import normalize_domain, normalize_rule
from app.proxy.validate import (
    ValidationError,
    assert_file_path,
    assert_hostname,
    assert_path,
    assert_redirect_code,
    assert_redirect_target,
    assert_upstream,
)


def test_assert_hostname_accepts_valid_hostname():
    assert assert_hostname("app.example.com") == "app.example.com"


def test_assert_hostname_lowercases():
    assert assert_hostname("APP.Example.COM") == "app.example.com"


@pytest.mark.parametrize("value", ["", "has space.com", "-leading.com", "trailing-.com", "a" * 300, None, 123])
def test_assert_hostname_rejects_invalid(value):
    with pytest.raises(ValidationError):
        assert_hostname(value)


def test_assert_upstream_accepts_http_and_https():
    assert assert_upstream("http://127.0.0.1:8080") == "http://127.0.0.1:8080"
    assert assert_upstream("https://backend.internal/api") == "https://backend.internal/api"


@pytest.mark.parametrize("value", ["", "ftp://example.com", "127.0.0.1:8080", "http://", None])
def test_assert_upstream_rejects_invalid(value):
    with pytest.raises(ValidationError):
        assert_upstream(value)


def test_assert_path_accepts_root_and_subpaths():
    assert assert_path("/") == "/"
    assert assert_path("/api/v1") == "/api/v1"


@pytest.mark.parametrize("value", ["", "no-leading-slash", "/has space", "/semi;colon", None])
def test_assert_path_rejects_invalid(value):
    with pytest.raises(ValidationError):
        assert_path(value)


@pytest.mark.parametrize("code", [301, 302, 307, 308])
def test_assert_redirect_code_accepts_known_codes(code):
    assert assert_redirect_code(code) == code


def test_assert_redirect_code_accepts_numeric_string():
    assert assert_redirect_code("301") == 301


@pytest.mark.parametrize("code", [200, 404, 500, "abc", None])
def test_assert_redirect_code_rejects_invalid(code):
    with pytest.raises(ValidationError):
        assert_redirect_code(code)


def test_assert_redirect_target_accepts_url():
    assert assert_redirect_target("https://example.com/new") == "https://example.com/new"


@pytest.mark.parametrize("value", ["", None, "a" * 3000, "https://example.com/\r\nInjected: header"])
def test_assert_redirect_target_rejects_invalid(value):
    with pytest.raises(ValidationError):
        assert_redirect_target(value)


def test_assert_file_path_accepts_absolute_path():
    assert assert_file_path("/etc/letsencrypt/live/example.com/fullchain.pem", "cert") == (
        "/etc/letsencrypt/live/example.com/fullchain.pem"
    )


@pytest.mark.parametrize("value", ["", None, "relative/path.pem", "/has\nnewline", "/has;semicolon"])
def test_assert_file_path_rejects_invalid(value):
    with pytest.raises(ValidationError):
        assert_file_path(value, "cert")


def test_normalize_rule_proxy_defaults():
    rule = normalize_rule({"type": "proxy", "path": "/", "upstream": "http://127.0.0.1:8080"})
    assert rule["type"] == "proxy"
    assert rule["path"] == "/"
    assert rule["upstream"] == "http://127.0.0.1:8080"
    assert rule["websocket"] is False
    assert rule["id"]


def test_normalize_rule_proxy_preserves_existing_id():
    rule = normalize_rule({"id": "keep-me", "type": "proxy", "path": "/", "upstream": "http://127.0.0.1:8080"})
    assert rule["id"] == "keep-me"


def test_normalize_rule_redirect_defaults_to_301():
    rule = normalize_rule({"type": "redirect", "path": "/old", "target": "https://example.com/new"})
    assert rule["type"] == "redirect"
    assert rule["code"] == 301


def test_normalize_rule_redirect_missing_target_raises():
    with pytest.raises(ValidationError):
        normalize_rule({"type": "redirect", "path": "/old"})


def test_normalize_rule_proxy_missing_upstream_raises():
    with pytest.raises(ValidationError):
        normalize_rule({"type": "proxy", "path": "/"})


def test_normalize_rule_rejects_non_dict():
    with pytest.raises(ValidationError):
        normalize_rule("not-a-dict")


def _valid_domain_input(**overrides):
    base = {
        "hostnames": ["app.example.com"],
        "rules": [{"type": "proxy", "path": "/", "upstream": "http://127.0.0.1:8080"}],
    }
    base.update(overrides)
    return base


def test_normalize_domain_generates_id_and_timestamps_on_create():
    domain = normalize_domain(_valid_domain_input())
    assert domain["id"]
    assert domain["hostnames"] == ["app.example.com"]
    assert domain["created_at"] == domain["updated_at"]
    assert domain["enabled"] is True
    assert domain["custom_config"] == ""


def test_normalize_domain_accepts_comma_or_space_separated_hostname_string():
    domain = normalize_domain(_valid_domain_input(hostnames="app.example.com, api.example.com"))
    assert domain["hostnames"] == ["app.example.com", "api.example.com"]


def test_normalize_domain_requires_at_least_one_hostname():
    with pytest.raises(ValidationError):
        normalize_domain(_valid_domain_input(hostnames=[]))


def test_normalize_domain_requires_at_least_one_rule():
    with pytest.raises(ValidationError):
        normalize_domain(_valid_domain_input(rules=[]))


def test_normalize_domain_preserves_id_and_created_at_on_update():
    existing = normalize_domain(_valid_domain_input())
    updated = normalize_domain(_valid_domain_input(hostnames=["new.example.com"]), existing=existing)
    assert updated["id"] == existing["id"]
    assert updated["created_at"] == existing["created_at"]
    assert updated["updated_at"] >= existing["updated_at"]
    assert updated["hostnames"] == ["new.example.com"]


def test_normalize_domain_preserves_custom_config_when_not_supplied_on_update():
    existing = normalize_domain(_valid_domain_input(custom_config="add_header X-Test 1;"))
    updated = normalize_domain(_valid_domain_input(), existing=existing)
    assert updated["custom_config"] == "add_header X-Test 1;"


def test_normalize_domain_ssl_requires_cert_and_key_when_enabled():
    with pytest.raises(ValidationError):
        normalize_domain(_valid_domain_input(ssl={"enabled": True}))


def test_normalize_domain_ssl_valid_paths_accepted():
    domain = normalize_domain(_valid_domain_input(ssl={
        "enabled": True,
        "cert_path": "/etc/letsencrypt/live/app.example.com/fullchain.pem",
        "key_path": "/etc/letsencrypt/live/app.example.com/privkey.pem",
    }))
    assert domain["ssl"]["enabled"] is True
    assert domain["ssl"]["cert_path"] == "/etc/letsencrypt/live/app.example.com/fullchain.pem"


def test_normalize_domain_rejects_invalid_hostname_in_list():
    with pytest.raises(ValidationError):
        normalize_domain(_valid_domain_input(hostnames=["not a hostname"]))
