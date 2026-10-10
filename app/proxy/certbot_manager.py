# SPDX-License-Identifier: BSD-3-Clause AND LicenseRef-Commons-Clause
# See the LICENSE file in the project root for full license terms.

from __future__ import annotations

import os
import subprocess
from typing import Any

CERTBOT_WEBROOT = os.environ.get("DNSSHIELD_CERTBOT_WEBROOT", "/var/www/certbot")
CERT_BASE = os.environ.get("DNSSHIELD_CERTBOT_CONFIG_DIR", "/etc/letsencrypt/live")


def issue_certificate(hostnames: list[str], email: str) -> dict[str, Any]:
    args = [
        "certbot",
        "certonly",
        "--webroot",
        "--webroot-path",
        CERTBOT_WEBROOT,
        "--non-interactive",
        "--agree-tos",
        "--email",
        email,
        "--no-eff-email",
    ]
    for host in hostnames:
        args += ["-d", host]

    try:
        result = subprocess.run(args, capture_output=True, text=True, timeout=120)
    except (OSError, subprocess.SubprocessError) as exc:
        return {"ok": False, "error": str(exc)}

    if result.returncode != 0:
        return {"ok": False, "error": result.stderr or result.stdout}

    primary = hostnames[0]
    return {
        "ok": True,
        "cert_path": f"{CERT_BASE}/{primary}/fullchain.pem",
        "key_path": f"{CERT_BASE}/{primary}/privkey.pem",
        "log": result.stdout,
    }
