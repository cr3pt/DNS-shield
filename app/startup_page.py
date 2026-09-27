from __future__ import annotations

import logging
import ssl
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

logger = logging.getLogger("dnsshield.startuppage")

_PAGE = """<!doctype html>
<html><head><meta charset="utf-8"><title>Starting - DNS-shield</title>
<meta http-equiv="refresh" content="3">
<style>
  body { margin:0; padding:4rem 1.5rem; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; background:#0a1128; color:#e8ecfb; text-align:center; }
  .spinner { width:2.2rem; height:2.2rem; margin:0 auto 1.4rem; border:3px solid rgba(255,255,255,0.15); border-top-color:#4d9fff; border-radius:50%; animation:spin 0.8s linear infinite; }
  @keyframes spin { to { transform: rotate(360deg); } }
  h1 { font-size:1.3rem; margin:0 0 0.5rem; }
  p { color:#8b96c4; font-size:0.9rem; max-width:24rem; margin:0 auto; }
</style></head>
<body>
  <div class="spinner"></div>
  <h1>DNS-shield is starting up...</h1>
  <p>Loading blocklists and initializing services - this page refreshes
  automatically and will show the dashboard once the service is ready.</p>
</body></html>
"""


class _StartupPageHandler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:
        self._respond()

    def do_POST(self) -> None:
        self._respond()

    def _respond(self) -> None:
        body = _PAGE.encode("utf-8")
        self.send_response(503)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Retry-After", "3")
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format: str, *args) -> None:
        pass


def start_startup_page_server(
    address: str,
    port: int,
    https_enabled: bool = False,
    cert_path: Path | None = None,
    key_path: Path | None = None,
) -> ThreadingHTTPServer | None:
    try:
        server = ThreadingHTTPServer((address, port), _StartupPageHandler)
    except OSError as exc:
        logger.warning("could not start startup placeholder page on %s:%d: %s", address, port, exc)
        return None

    scheme = "http"
    if https_enabled and cert_path is not None and key_path is not None:
        try:
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.load_cert_chain(str(cert_path), str(key_path))
            server.socket = context.wrap_socket(server.socket, server_side=True)
            scheme = "https"
        except (OSError, ssl.SSLError) as exc:
            logger.warning("could not enable TLS for the startup placeholder page: %s", exc)

    threading.Thread(target=server.serve_forever, daemon=True, name="startup-page").start()
    logger.info("startup placeholder page listening on %s://%s:%d", scheme, address, port)
    return server


def stop_startup_page_server(server: ThreadingHTTPServer | None) -> None:
    if server is None:
        return
    server.shutdown()
    server.server_close()
