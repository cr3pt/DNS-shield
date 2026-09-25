from __future__ import annotations

import os
import subprocess
from pathlib import Path
from typing import Any

CONF_DIR = Path(os.environ.get("DNSSHIELD_NGINX_CONF_DIR", "/etc/nginx/conf.d"))
CERTBOT_WEBROOT = os.environ.get("DNSSHIELD_CERTBOT_WEBROOT", "/var/www/certbot")


def conf_path_for(domain_id: str) -> Path:
    return CONF_DIR / f"domain-{domain_id}.conf"


def _run(cmd: list[str]) -> dict[str, Any]:
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
        return {"ok": result.returncode == 0, "stdout": result.stdout, "stderr": result.stderr}
    except (OSError, subprocess.SubprocessError) as exc:
        return {"ok": False, "stdout": "", "stderr": str(exc)}


def test_config() -> dict[str, Any]:
    return _run(["nginx", "-t"])


def reload_nginx() -> dict[str, Any]:
    return _run(["nginx", "-s", "reload"])


def _render_location(rule: dict[str, Any]) -> str:
    path = rule["path"]
    if rule["type"] == "redirect":
        return f'    location {path} {{\n        return {rule["code"]} "{rule["target"]}";\n    }}\n'
    ws_lines = (
        "        proxy_http_version 1.1;\n"
        "        proxy_set_header Upgrade $http_upgrade;\n"
        "        proxy_set_header Connection $connection_upgrade;\n"
        if rule.get("websocket")
        else ""
    )
    return (
        f"    location {path} {{\n"
        f'        proxy_pass {rule["upstream"]};\n'
        "        proxy_set_header Host $host;\n"
        "        proxy_set_header X-Real-IP $remote_addr;\n"
        "        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;\n"
        "        proxy_set_header X-Forwarded-Proto $scheme;\n"
        "        proxy_connect_timeout 60s;\n"
        "        proxy_send_timeout 60s;\n"
        "        proxy_read_timeout 60s;\n"
        f"{ws_lines}"
        "    }\n"
    )


def render_domain(domain: dict[str, Any]) -> str:
    server_names = " ".join(domain["hostnames"])
    rules_block = "".join(_render_location(r) for r in domain.get("rules") or [])
    custom = ""
    if domain.get("custom_config"):
        custom = "    " + domain["custom_config"].replace("\n", "\n    ") + "\n"

    ssl_enabled = bool(domain.get("ssl", {}).get("enabled"))
    http_redirect_only = ssl_enabled and domain.get("force_https")

    if http_redirect_only:
        http_block = (
            "server {\n"
            "    listen 80;\n"
            f"    server_name {server_names};\n\n"
            "    location /.well-known/acme-challenge/ {\n"
            f"        root {CERTBOT_WEBROOT};\n"
            "    }\n\n"
            "    location / {\n"
            "        return 301 https://$host$request_uri;\n"
            "    }\n"
            "}\n"
        )
    else:
        http_block = (
            "server {\n"
            "    listen 80;\n"
            f"    server_name {server_names};\n\n"
            "    location /.well-known/acme-challenge/ {\n"
            f"        root {CERTBOT_WEBROOT};\n"
            "    }\n\n"
            f"{rules_block}"
            f"{custom}"
            "}\n"
        )

    https_block = ""
    if ssl_enabled:
        https_block = (
            "\nserver {\n"
            "    listen 443 ssl;\n"
            "    http2 on;\n"
            f"    server_name {server_names};\n\n"
            f'    ssl_certificate {domain["ssl"]["cert_path"]};\n'
            f'    ssl_certificate_key {domain["ssl"]["key_path"]};\n'
            "    ssl_protocols TLSv1.2 TLSv1.3;\n\n"
            f"{rules_block}"
            f"{custom}"
            "}\n"
        )

    return http_block + https_block


def preview_domain(domain: dict[str, Any]) -> str:
    return render_domain(domain)


def remove_domain_config(domain_id: str) -> dict[str, Any]:
    target = conf_path_for(domain_id)
    if not target.exists():
        return {"ok": True}
    backup = target.read_text()
    target.unlink()
    test = test_config()
    if not test["ok"]:
        target.write_text(backup)
        return {"ok": False, "error": test["stderr"] or test["stdout"]}
    reload_result = reload_nginx()
    if not reload_result["ok"]:
        return {"ok": False, "error": reload_result["stderr"] or reload_result["stdout"]}
    return {"ok": True}


def apply_domain(domain: dict[str, Any]) -> dict[str, Any]:
    target = conf_path_for(domain["id"])
    backup = target.read_text() if target.exists() else None

    if not domain.get("enabled", True):
        return remove_domain_config(domain["id"])

    rendered = render_domain(domain)
    CONF_DIR.mkdir(parents=True, exist_ok=True)
    target.write_text(rendered)

    test = test_config()
    if not test["ok"]:
        if backup is not None:
            target.write_text(backup)
        elif target.exists():
            target.unlink()
        return {"ok": False, "error": test["stderr"] or test["stdout"]}

    reload_result = reload_nginx()
    if not reload_result["ok"]:
        return {"ok": False, "error": reload_result["stderr"] or reload_result["stdout"]}
    return {"ok": True}
