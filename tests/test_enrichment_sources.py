from unittest.mock import MagicMock, patch

from app.enrichment import query_ipinfo, query_rdap


def _fake_response(payload):
    resp = MagicMock()
    resp.raise_for_status.return_value = None
    resp.json.return_value = payload
    return resp


RDAP_PAYLOAD = {
    "objectClassName": "domain",
    "ldhName": "EXAMPLE.COM",
    "status": ["client transfer prohibited", "server delete prohibited"],
    "entities": [
        {
            "objectClassName": "entity",
            "handle": "292",
            "roles": ["registrar"],
            "vcardArray": ["vcard", [["version", {}, "text", "4.0"], ["fn", {}, "text", "Example Registrar Inc."]]],
        }
    ],
    "nameservers": [
        {"objectClassName": "nameserver", "ldhName": "NS2.EXAMPLE.COM"},
        {"objectClassName": "nameserver", "ldhName": "NS1.EXAMPLE.COM"},
    ],
    "events": [
        {"eventAction": "registration", "eventDate": "1995-08-14T04:00:00Z"},
        {"eventAction": "expiration", "eventDate": "2099-08-13T04:00:00Z"},
        {"eventAction": "last changed", "eventDate": "2024-08-14T07:01:31Z"},
    ],
}


def test_query_rdap_extracts_full_whois_style_record():
    with patch("app.enrichment._session") as mock_session:
        mock_session.get.return_value = _fake_response(RDAP_PAYLOAD)
        result = query_rdap("example.com")

    assert result["ok"] is True
    assert result["verdict"] == "safe"  # registered decades ago
    assert result["details"]["registrar"] == "Example Registrar Inc."
    assert result["details"]["expiration_date"] == "2099-08-13T04:00:00Z"
    assert result["details"]["nameservers"] == ["ns1.example.com", "ns2.example.com"]
    assert "Example Registrar Inc." in result["summary"]
    assert "expires: 2099-08-13" in result["summary"]
    assert "2 nameserver(s)" in result["summary"]


def test_query_rdap_flags_very_recently_registered_domain():
    import copy
    from datetime import datetime, timedelta, timezone

    payload = copy.deepcopy(RDAP_PAYLOAD)
    recent = (datetime.now(timezone.utc) - timedelta(days=2)).isoformat().replace("+00:00", "Z")
    payload["events"][0]["eventDate"] = recent

    with patch("app.enrichment._session") as mock_session:
        mock_session.get.return_value = _fake_response(payload)
        result = query_rdap("freshly-registered.example")

    assert result["verdict"] == "high"
    assert "recently registered" in result["summary"]


def test_query_ipinfo_reports_geolocation_and_org():
    payload = {
        "ip": "8.8.8.8",
        "city": "Mountain View",
        "region": "California",
        "country": "US",
        "loc": "37.4056,-122.0775",
        "org": "AS15169 Google LLC",
        "postal": "94043",
        "timezone": "America/Los_Angeles",
    }
    with patch("app.enrichment._session") as mock_session:
        mock_session.get.return_value = _fake_response(payload)
        result = query_ipinfo("8.8.8.8", "")

    assert result["ok"] is True
    assert result["verdict"] == "safe"
    assert result["score"] == 0
    assert "Mountain View" in result["summary"]
    assert "AS15169 Google LLC" in result["summary"]
    assert result["details"]["country"] == "US"


def test_query_ipinfo_handles_bogon_private_ip():
    with patch("app.enrichment._session") as mock_session:
        mock_session.get.return_value = _fake_response({"ip": "192.168.1.5", "bogon": True})
        result = query_ipinfo("192.168.1.5", "")

    assert result["ok"] is True
    assert "Private/reserved" in result["summary"]


def test_query_ipinfo_passes_token_when_provided():
    with patch("app.enrichment._session") as mock_session:
        mock_session.get.return_value = _fake_response({"ip": "1.1.1.1", "org": "AS13335 Cloudflare"})
        query_ipinfo("1.1.1.1", "mytoken123")

    _, kwargs = mock_session.get.call_args
    assert kwargs["params"] == {"token": "mytoken123"}
