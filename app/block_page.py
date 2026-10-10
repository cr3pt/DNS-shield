# SPDX-License-Identifier: BSD-3-Clause AND LicenseRef-Commons-Clause
# See the LICENSE file in the project root for full license terms.

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
  .domain {{ font-size:1.05rem; font-family: ui-monospace, monospace; color:#ff5d75; word-break:break-all; margin-bottom:0.6rem; }}
  .reason {{ display:inline-block; font-size:0.78rem; color:#ffb454; background:rgba(255,180,84,0.12); border:1px solid rgba(255,180,84,0.35); border-radius:999px; padding:0.2rem 0.75rem; margin-bottom:1.2rem; }}
  p {{ color:#8b96c4; font-size:0.9rem; max-width:28rem; margin:0 auto; }}
</style></head>
<body>
  <h1>Blocked by DNS-shield</h1>
  <div class="domain">{domain}</div>
  <div class="reason">{reason}</div>
  <p>This domain was blocked at the DNS level for your network. If this looks
  wrong, an administrator can allow it from the DNS-shield dashboard.</p>
</body></html>
"""

_UNKNOWN_REASON = "Not currently blocked - config may have changed since you were sent here"


def _escape(text: str) -> str:
    return text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


class _BlockPageHandler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:
        self._respond()

    def do_POST(self) -> None:
        self._respond()

    def _respond(self) -> None:
        domain = (self.headers.get("Host") or "this site").split(":", 1)[0]
        reason = self.server.blocklist.block_reason(domain, self.client_address[0]) if domain else None
        body = _PAGE_TEMPLATE.format(
            domain=_escape(domain), reason=_escape(reason or _UNKNOWN_REASON)
        ).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format: str, *args) -> None:
        pass


def start_block_page_server(address: str, port: int, blocklist) -> ThreadingHTTPServer:
    server = ThreadingHTTPServer((address, port), _BlockPageHandler)
    server.blocklist = blocklist
    threading.Thread(target=server.serve_forever, daemon=True, name="block-page").start()
    logger.info("block page server listening on %s:%d", address, port)
    return server
