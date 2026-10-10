# SPDX-License-Identifier: BSD-3-Clause AND LicenseRef-Commons-Clause
# See the LICENSE file in the project root for full license terms.

from unittest.mock import patch

from app.whois import _parse_whois_text, find_whois_server, whois_lookup

IANA_REFERRAL_TEXT = """
refer:        whois.example-registry.net

domain:       COM
organisation: VeriSign Global Registry Services
"""

REGISTRY_WHOIS_TEXT = """
Domain Name: EXAMPLE.COM
Registry Domain ID: 123456_DOMAIN_COM-VRSN
Registrar WHOIS Server: whois.example-registrar.com
Registrar: Example Registrar Inc.
Creation Date: 1995-08-14T04:00:00Z
Registry Expiry Date: 2099-08-13T04:00:00Z
Domain Status: clientTransferProhibited https://icann.org/epp#clientTransferProhibited
Domain Status: clientDeleteProhibited https://icann.org/epp#clientDeleteProhibited
Name Server: NS1.EXAMPLE.COM
Name Server: NS2.EXAMPLE.COM
"""

REGISTRAR_WHOIS_TEXT = """
Domain Name: EXAMPLE.COM
Registrar: Example Registrar Inc.
Registrant Organization: Example Owner LLC
Registrant Name: John Doe
Registrant Country: US
Creation Date: 1995-08-14T04:00:00Z
Registry Expiry Date: 2099-08-13T04:00:00Z
Name Server: NS1.EXAMPLE.COM
Name Server: NS2.EXAMPLE.COM
"""


def test_parse_whois_text_extracts_fields():
    parsed = _parse_whois_text(REGISTRAR_WHOIS_TEXT)

    assert parsed["registrar"] == "Example Registrar Inc."
    assert parsed["registrant_org"] == "Example Owner LLC"
    assert parsed["registrant_name"] == "John Doe"
    assert parsed["registrant_country"] == "US"
    assert parsed["creation_date"] == "1995-08-14T04:00:00Z"
    assert parsed["expiration_date"] == "2099-08-13T04:00:00Z"
    assert parsed["status"] == []
    assert parsed["nameservers"] == ["ns1.example.com", "ns2.example.com"]


def test_parse_whois_text_extracts_status_and_referral():
    parsed = _parse_whois_text(REGISTRY_WHOIS_TEXT)

    assert parsed["registrar"] == "Example Registrar Inc."
    assert parsed["referral_server"] == "whois.example-registrar.com"
    assert parsed["status"] == ["clientdeleteprohibited", "clienttransferprohibited"]


def test_find_whois_server_parses_referral_line():
    with patch("app.whois._query_whois_server", return_value=IANA_REFERRAL_TEXT):
        server = find_whois_server("com")

    assert server == "whois.example-registry.net"


def test_find_whois_server_returns_none_on_socket_error():
    with patch("app.whois._query_whois_server", side_effect=OSError("timed out")):
        server = find_whois_server("com")

    assert server is None


def test_whois_lookup_follows_registrar_referral_and_merges_fields():
    with patch("app.whois.find_whois_server", return_value="whois.example-registry.net"):
        with patch(
            "app.whois._query_whois_server",
            side_effect=[REGISTRY_WHOIS_TEXT, REGISTRAR_WHOIS_TEXT],
        ) as mock_query:
            result = whois_lookup("example.com")

    assert result is not None
    assert result["registrar"] == "Example Registrar Inc."
    assert result["registrant_org"] == "Example Owner LLC"
    assert result["registrant_name"] == "John Doe"
    assert result["server"] == "whois.example-registrar.com"
    assert mock_query.call_count == 2


def test_whois_lookup_returns_none_when_no_server_found():
    with patch("app.whois.find_whois_server", return_value=None):
        result = whois_lookup("example.com")

    assert result is None


def test_whois_lookup_returns_none_for_bare_tld():
    result = whois_lookup("com")

    assert result is None


def test_whois_lookup_returns_none_when_no_useful_data_present():
    with patch("app.whois.find_whois_server", return_value="whois.example-registry.net"):
        with patch("app.whois._query_whois_server", return_value="No match for domain.\n"):
            result = whois_lookup("nonexistent-domain-xyz.com")

    assert result is None
