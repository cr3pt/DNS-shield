from app.proxy import nginx_manager
from app.proxy.domain import normalize_domain


def _domain(**overrides):
    base = {
        "hostnames": ["app.example.com"],
        "rules": [{"type": "proxy", "path": "/", "upstream": "http://127.0.0.1:8080"}],
    }
    base.update(overrides)
    return normalize_domain(base)


def test_render_plain_http_proxy_domain():
    conf = nginx_manager.render_domain(_domain())
    assert "listen 80;" in conf
    assert "server_name app.example.com;" in conf
    assert "proxy_pass http://127.0.0.1:8080;" in conf
    assert "location / {" in conf
    assert "listen 443" not in conf
    assert "return 301 https" not in conf


def test_render_redirect_domain():
    conf = nginx_manager.render_domain(_domain(rules=[
        {"type": "redirect", "path": "/old", "target": "https://example.com/new", "code": 302}
    ]))
    assert "location /old {" in conf
    assert 'return 302 "https://example.com/new";' in conf
    assert "proxy_pass" not in conf


def test_render_ssl_without_force_https_serves_both_ports_without_redirect():
    conf = nginx_manager.render_domain(_domain(ssl={
        "enabled": True,
        "cert_path": "/etc/letsencrypt/live/app.example.com/fullchain.pem",
        "key_path": "/etc/letsencrypt/live/app.example.com/privkey.pem",
    }))
    assert "listen 80;" in conf
    assert "listen 443 ssl;" in conf
    assert "ssl_certificate /etc/letsencrypt/live/app.example.com/fullchain.pem;" in conf
    assert "ssl_certificate_key /etc/letsencrypt/live/app.example.com/privkey.pem;" in conf
    # without force_https, port 80 still serves the real rules, not a redirect
    assert "return 301 https" not in conf
    assert conf.count("proxy_pass http://127.0.0.1:8080;") == 2


def test_render_ssl_with_force_https_redirects_port_80():
    conf = nginx_manager.render_domain(_domain(force_https=True, ssl={
        "enabled": True,
        "cert_path": "/etc/letsencrypt/live/app.example.com/fullchain.pem",
        "key_path": "/etc/letsencrypt/live/app.example.com/privkey.pem",
    }))
    assert "return 301 https://$host$request_uri;" in conf
    assert "listen 443 ssl;" in conf
    assert "ssl_certificate " in conf
    # port 80 block should be redirect-only - the real rule only appears once (in the 443 block)
    assert conf.count("proxy_pass http://127.0.0.1:8080;") == 1


def test_render_includes_custom_config_verbatim():
    conf = nginx_manager.render_domain(_domain(custom_config="add_header X-Test 1;"))
    assert "add_header X-Test 1;" in conf


def test_render_websocket_rule_adds_upgrade_headers():
    conf = nginx_manager.render_domain(_domain(rules=[
        {"type": "proxy", "path": "/ws", "upstream": "http://127.0.0.1:9000", "websocket": True}
    ]))
    assert "proxy_set_header Upgrade $http_upgrade;" in conf
    assert "proxy_set_header Connection $connection_upgrade;" in conf


def test_render_multiple_hostnames_joined_in_server_name():
    conf = nginx_manager.render_domain(_domain(hostnames=["app.example.com", "api.example.com"]))
    assert "server_name app.example.com api.example.com;" in conf


def test_preview_domain_matches_render_domain():
    domain = _domain()
    assert nginx_manager.preview_domain(domain) == nginx_manager.render_domain(domain)


def test_conf_path_for_includes_domain_id_and_conf_dir():
    path = nginx_manager.conf_path_for("abc123")
    assert path.parent == nginx_manager.CONF_DIR
    assert path.name == "domain-abc123.conf"
