import json

import requests

from app.enrichment import _http_error_message, _network_error_message


def _http_error(status_code, headers=None):
    resp = requests.Response()
    resp.status_code = status_code
    if headers:
        resp.headers.update(headers)
    return requests.HTTPError(response=resp)


def test_http_error_401_403_report_bad_key():
    assert "API key" in _http_error_message(_http_error(401))
    assert "API key" in _http_error_message(_http_error(403))


def test_http_error_404_reports_no_data():
    assert "no data" in _http_error_message(_http_error(404))


def test_http_error_429_without_retry_after():
    msg = _http_error_message(_http_error(429))
    assert "rate limited" in msg
    assert "later" in msg


def test_http_error_429_with_retry_after_surfaces_seconds():
    msg = _http_error_message(_http_error(429, headers={"Retry-After": "60"}))
    assert "60" in msg


def test_http_error_5xx_reports_service_error():
    msg = _http_error_message(_http_error(503))
    assert "503" in msg
    assert "later" in msg


def test_http_error_unrecognized_status_falls_back_to_status_code():
    assert "418" in _http_error_message(_http_error(418))


def test_http_error_no_response_falls_back_to_str():
    exc = requests.HTTPError("boom")
    assert _http_error_message(exc) == "boom"


def test_network_error_timeout():
    assert "timed out" in _network_error_message(requests.Timeout())


def test_network_error_ssl_before_generic_connection_error():
    # SSLError subclasses ConnectionError - must be reported as a TLS issue,
    # not a generic network error.
    msg = _network_error_message(requests.exceptions.SSLError())
    assert "TLS" in msg or "certificate" in msg


def test_network_error_plain_connection_error():
    msg = _network_error_message(requests.ConnectionError())
    assert "network error" in msg


def test_network_error_too_many_redirects():
    assert "redirects" in _network_error_message(requests.exceptions.TooManyRedirects())


def test_network_error_invalid_json():
    try:
        json.loads("not json")
    except ValueError as exc:
        msg = _network_error_message(exc)
        assert "JSON" in msg
    else:
        raise AssertionError("expected ValueError")


def test_network_error_unexpected_shape():
    for exc in (KeyError("data"), TypeError("bad"), IndexError("oob"), AttributeError("missing")):
        msg = _network_error_message(exc)
        assert "unexpected" in msg


def test_network_error_generic_fallback():
    exc = RuntimeError("something else entirely")
    assert _network_error_message(exc) == "something else entirely"
