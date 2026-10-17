# SPDX-License-Identifier: BSD-3-Clause AND LicenseRef-Commons-Clause
# See the LICENSE file in the project root for full license terms.

from app.typosquat import DEFAULT_PROTECTED_DOMAINS, find_typosquat_match


def _match(qname, protected=DEFAULT_PROTECTED_DOMAINS, max_distance=2):
    return find_typosquat_match(qname, protected, max_distance)


def test_exact_match_and_real_subdomain_are_not_flagged():
    assert _match("google.com") is None
    assert _match("www.google.com") is None
    assert _match("mail.google.com") is None


def test_classic_typosquats_are_caught():
    for qname in (
        "gooogle.com",
        "arnazon.com",
        "paypa1.com",
        "faceb00k.com",
        "secure-google-login.com",
        "amazon-account-verify.com",
    ):
        result = _match(qname)
        assert result is not None, f"expected {qname} to be flagged"


def test_embedded_brand_name_is_flagged_as_embedded():
    result = _match("paypal-security-check.com")
    assert result is not None
    protected, kind, distance = result
    assert protected == "paypal.com"
    assert kind == "embedded"


def test_digit_delimited_brand_embedding_is_flagged():
    for qname in ("paypal123.com", "0paypal.com", "google99.com"):
        result = _match(qname)
        assert result is not None, f"expected {qname} to be flagged"
        _protected, kind, _distance = result
        assert kind == "embedded"


def test_legitimate_compound_domains_are_not_flagged():
    for qname in (
        "firebaselogging.googleapis.com",
        "lcprd1.samsungcloudsolution.net",
        "api.amazon.co.uk",
        "adb-sc.cdn-canalplus.pl",
        "static.amazonaws.com",
        "raw.githubusercontent.com",
        "content.dropboxusercontent.com",
        "www.paypalobjects.com",
        "login.microsoftonline.com",
    ):
        assert _match(qname) is None, f"expected {qname} to NOT be flagged"


def test_short_protected_label_requires_a_delimiter_to_avoid_dictionary_word_collisions():
    for qname in ("cdn-canalplus.pl", "purchase-receipts.com", "pineapple-farm.com"):
        assert _match(qname) is None, f"expected {qname} to NOT be flagged"


def test_brand_embedded_with_no_delimiter_is_now_flagged():
    for qname in ("paypalsecurity.com", "securepaypalnow.com", "googleaccountverify.com"):
        result = _match(qname)
        assert result is not None, f"expected {qname} to be flagged"
        _protected, kind, _distance = result
        assert kind == "embedded"


def test_short_protected_label_does_not_match_unrelated_short_domains():
    assert _match("wp.pl") is None


def test_popular_short_polish_domains_are_not_flagged():
    for qname in ("onet.pl", "interia.pl", "gazeta.pl", "money.pl", "o2.pl", "rp.pl", "tvn24.pl"):
        assert _match(qname) is None, f"expected {qname} to NOT be flagged"


def test_plain_two_label_typo_is_caught():
    result = _match("allegr0.pl")
    assert result is not None
    protected, kind, _ = result
    assert protected == "allegro.pl"
    assert kind == "typo"


def test_multi_label_cctld_suffix_is_handled():
    for qname in ("allegro-sklep.com.pl", "sub.allegro-sklep.com.pl"):
        result = _match(qname)
        assert result is not None, f"expected {qname} to be flagged"
        protected, kind, _ = result
        assert protected == "allegro.pl"
        assert kind == "embedded"


def test_empty_and_trailing_dot_input():
    assert _match("") is None
    assert _match("google.com.") is None


def test_custom_protected_list_is_used():
    assert _match("exarnple.com", protected=["example.com"]) is not None
    assert _match("totally-unrelated.com", protected=["example.com"]) is None
