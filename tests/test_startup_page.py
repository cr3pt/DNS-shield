import socket
import socketserver
import ssl
import urllib.error
import urllib.request
from unittest.mock import MagicMock

from app.startup_page import _StartupPageHandler, start_startup_page_server, stop_startup_page_server
from app.tls import ensure_self_signed_cert


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _get(url: str, **kwargs):
    try:
        with urllib.request.urlopen(url, timeout=5, **kwargs) as resp:
            return resp.status, resp.read()
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read()


def test_startup_page_serves_plain_http_by_default():
    port = _free_port()
    server = start_startup_page_server("127.0.0.1", port)
    try:
        status, body = _get(f"http://127.0.0.1:{port}/")
    finally:
        stop_startup_page_server(server)

    assert status == 503
    assert b"starting up" in body.lower()


def test_startup_page_serves_https_when_enabled(tmp_path):
    cert_path = tmp_path / "cert.pem"
    key_path = tmp_path / "key.pem"
    ensure_self_signed_cert(cert_path, key_path)

    port = _free_port()
    server = start_startup_page_server(
        "127.0.0.1", port, https_enabled=True, cert_path=cert_path, key_path=key_path
    )
    try:
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        status, body = _get(f"https://127.0.0.1:{port}/", context=context)
    finally:
        stop_startup_page_server(server)

    assert status == 503
    assert b"starting up" in body.lower()


def test_respond_swallows_client_disconnect_mid_write():
    handler = object.__new__(_StartupPageHandler)
    handler.send_response = MagicMock()
    handler.send_header = MagicMock()
    handler.end_headers = MagicMock()
    handler.wfile = MagicMock()
    handler.wfile.write.side_effect = BrokenPipeError()

    handler._respond()  # must not raise


def test_finish_swallows_client_disconnect(monkeypatch):
    monkeypatch.setattr(socketserver.StreamRequestHandler, "finish", MagicMock(side_effect=ConnectionResetError()))
    handler = object.__new__(_StartupPageHandler)

    handler.finish()  # must not raise


def test_startup_page_falls_back_to_http_on_bad_cert(tmp_path):
    port = _free_port()
    server = start_startup_page_server(
        "127.0.0.1",
        port,
        https_enabled=True,
        cert_path=tmp_path / "missing-cert.pem",
        key_path=tmp_path / "missing-key.pem",
    )
    try:
        status, body = _get(f"http://127.0.0.1:{port}/")
    finally:
        stop_startup_page_server(server)

    assert status == 503
    assert b"starting up" in body.lower()
