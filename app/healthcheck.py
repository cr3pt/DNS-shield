from __future__ import annotations

import ssl
import sys
import urllib.request

_URLS = ("http://127.0.0.1:3000/healthz", "https://127.0.0.1:3000/healthz")


def main() -> None:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    for url in _URLS:
        try:
            context = ctx if url.startswith("https") else None
            with urllib.request.urlopen(url, timeout=2, context=context) as resp:
                if resp.status == 200:
                    return
        except Exception:
            continue
    sys.exit(1)


if __name__ == "__main__":
    main()
