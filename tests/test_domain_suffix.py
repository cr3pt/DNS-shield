# SPDX-License-Identifier: BSD-3-Clause AND LicenseRef-Commons-Clause
# See the LICENSE file in the project root for full license terms.

from app.domain_suffix import registrable_domain


def test_multi_part_public_suffix_co_uk():
    assert registrable_domain("sub.deep.example.co.uk") == "example.co.uk"


def test_multi_part_public_suffix_com_au():
    assert registrable_domain("sub.example.com.au") == "example.com.au"


def test_plain_domain_unchanged():
    assert registrable_domain("example.com") == "example.com"


def test_www_subdomain_collapses_to_registrable_domain():
    assert registrable_domain("www.example.com") == "example.com"


def test_private_suffix_github_io_not_split_by_default():
    assert registrable_domain("foo.github.io") == "github.io"
    assert registrable_domain("github.io") == "github.io"


def test_bare_hostname_without_recognized_suffix_falls_back_to_last_label():
    assert registrable_domain("localhost") == "localhost"
    assert registrable_domain("a.b.c.internal") == "internal"


def test_ip_address_passes_through_unchanged():
    assert registrable_domain("192.168.1.1") == "192.168.1.1"


def test_trailing_dot_and_uppercase_are_normalized():
    assert registrable_domain("EXAMPLE.COM.") == "example.com"


def test_empty_string_returns_empty_string():
    assert registrable_domain("") == ""


def test_whitespace_only_returns_empty_string():
    assert registrable_domain("   ") == ""
