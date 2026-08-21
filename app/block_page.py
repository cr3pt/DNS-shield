"""Optional local HTTP server that shows a "this domain is blocked" page,
so a plain-HTTP request to a null_ip-blocked domain gets something readable
instead of a bare connection error. Purely local: this only ever answers
requests that already arrived at it - no outbound connections, no calls to
anything else.

Off by default (`dns.block_page_enabled`). When on, point `dns.blocked_ipv4`
(block_mode "null_ip") at wherever this ends up reachable - typically this
same host's LAN IP - and the browser's request for the blocked domain lands
here; the domain name itself comes from the request's own Host header, not
from anywhere else.

HTTPS can't be shown a page this way: the browser fails the certificate
check before ever sending the request, which is a fundamental limit of
DNS-level blocking, not something to work around here - doing so would mean
terminating TLS with a certificate the client doesn't trust, i.e. a MITM,
deliberately not implemented.
"""

from __future__ import annotations

import logging
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

logger = logging.getLogger("dnsshield.blockpage")

_PAGE_TEMPLATE = """<!doctype html>
<html><head><meta charset="utf-8"><title>Blocked - DNS-shield</title>
<style>
  body {{ margin:0; padding:3.5rem 1.5rem; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; background:#0a1128; color:#e8ecfb; text-align:center; }}
  h1 {{ font-size:1.4rem; margin:0 0 0.6rem; }}
  .domain {{ font-size:1.05rem; font-family: ui-monospace, monospace; color:#ff5d75; word-break:break-all; margin-bottom:1rem; }}
  p {{ color:#8b96c4; font-size:0.9rem; max-width:28rem; margin:0 auto; }}
</style></head>
<body>
  <h1>Blocked by DNS-shield</h1>
  <div class="domain">{domain}</div>
  <p>This domain was blocked at the DNS level for your network. If this looks
  wrong, an administrator can allow it from the DNS-shield dashboard.</p>
</body></html>
"""


def _escape(text: str) -> str:
    return text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


class _BlockPageHandler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:  # noqa: N802 - http.server's naming convention
        self._respond()

    def do_POST(self) -> None:  # noqa: N802
        self._respond()

    def _respond(self) -> None:
        domain = (self.headers.get("Host") or "this site").split(":", 1)[0]
        body = _PAGE_TEMPLATE.format(domain=_escape(domain)).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format: str, *args) -> None:  # noqa: A002 - stdlib signature
        pass  # keep stdout quiet, same reasoning as dns_server.QuietLogger


def start_block_page_server(address: str, port: int) -> ThreadingHTTPServer:
    server = ThreadingHTTPServer((address, port), _BlockPageHandler)
    threading.Thread(target=server.serve_forever, daemon=True, name="block-page").start()
    logger.info("block page server listening on %s:%d", address, port)
    return server
