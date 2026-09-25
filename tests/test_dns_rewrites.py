import pytest

from app.dns_rewrites import DEFAULT_TTL, find_rewrite


@pytest.fixture
def rewrites(config_store):
    def _set(entries):
        config_store.mutate(lambda d: d.update({"dns_rewrites": entries}))
        return config_store
    return _set


def test_a_record_round_trip(rewrites):
    cs = rewrites([{"name": "host.example.com", "type": "A", "value": "10.0.0.5"}])
    assert find_rewrite("host.example.com", "A", cs) == ("10.0.0.5", DEFAULT_TTL)


def test_aaaa_record_round_trip(rewrites):
    cs = rewrites([{"name": "host.example.com", "type": "AAAA", "value": "::1"}])
    assert find_rewrite("host.example.com", "AAAA", cs) == ("::1", DEFAULT_TTL)


def test_cname_record_round_trip(rewrites):
    cs = rewrites([{"name": "alias.example.com", "type": "CNAME", "value": "target.example.com"}])
    assert find_rewrite("alias.example.com", "CNAME", cs) == ("target.example.com", DEFAULT_TTL)


def test_txt_record_round_trip(rewrites):
    cs = rewrites([{"name": "txt.example.com", "type": "TXT", "value": "hello world"}])
    assert find_rewrite("txt.example.com", "TXT", cs) == ("hello world", DEFAULT_TTL)


def test_custom_ttl_used_when_present(rewrites):
    cs = rewrites([{"name": "host.example.com", "type": "A", "value": "10.0.0.5", "ttl": 60}])
    assert find_rewrite("host.example.com", "A", cs) == ("10.0.0.5", 60)


def test_default_ttl_used_when_ttl_missing(rewrites):
    cs = rewrites([{"name": "host.example.com", "type": "A", "value": "10.0.0.5"}])
    value, ttl = find_rewrite("host.example.com", "A", cs)
    assert ttl == DEFAULT_TTL


def test_default_ttl_used_when_ttl_is_zero_or_none(rewrites):
    cs = rewrites([{"name": "host.example.com", "type": "A", "value": "10.0.0.5", "ttl": 0}])
    value, ttl = find_rewrite("host.example.com", "A", cs)
    assert ttl == DEFAULT_TTL


def test_wildcard_matches_subdomain(rewrites):
    cs = rewrites([{"name": "*.internal.example", "type": "A", "value": "10.0.0.9"}])
    assert find_rewrite("vpn.internal.example", "A", cs) == ("10.0.0.9", DEFAULT_TTL)


def test_wildcard_does_not_match_bare_domain(rewrites):
    cs = rewrites([{"name": "*.internal.example", "type": "A", "value": "10.0.0.9"}])
    assert find_rewrite("internal.example", "A", cs) is None


def test_exact_match_does_not_match_subdomain_of_itself_unless_suffix_rule(rewrites):
    cs = rewrites([{"name": "example.com", "type": "A", "value": "10.0.0.1"}])
    assert find_rewrite("example.com", "A", cs) == ("10.0.0.1", DEFAULT_TTL)
    assert find_rewrite("www.example.com", "A", cs) == ("10.0.0.1", DEFAULT_TTL)
    assert find_rewrite("notexample.com", "A", cs) is None


def test_no_match_returns_none(rewrites):
    cs = rewrites([{"name": "example.com", "type": "A", "value": "10.0.0.1"}])
    assert find_rewrite("other.com", "A", cs) is None


def test_type_mismatch_returns_none(rewrites):
    cs = rewrites([{"name": "example.com", "type": "A", "value": "10.0.0.1"}])
    assert find_rewrite("example.com", "TXT", cs) is None


def test_unsupported_qtype_returns_none_even_with_matching_entry(rewrites):
    cs = rewrites([{"name": "example.com", "type": "A", "value": "10.0.0.1"}])
    assert find_rewrite("example.com", "MX", cs) is None


def test_entry_name_is_lowercased_for_matching(rewrites):
    cs = rewrites([{"name": "Example.COM", "type": "A", "value": "10.0.0.1"}])
    assert find_rewrite("example.com", "A", cs) == ("10.0.0.1", DEFAULT_TTL)


def test_trailing_dot_in_entry_name_is_stripped(rewrites):
    cs = rewrites([{"name": "example.com.", "type": "A", "value": "10.0.0.1"}])
    assert find_rewrite("example.com", "A", cs) == ("10.0.0.1", DEFAULT_TTL)


def test_empty_name_or_value_entries_are_skipped(rewrites):
    cs = rewrites([
        {"name": "", "type": "A", "value": "10.0.0.1"},
        {"name": "example.com", "type": "A", "value": ""},
        {"name": "example.com", "type": "A", "value": "10.0.0.2"},
    ])
    assert find_rewrite("example.com", "A", cs) == ("10.0.0.2", DEFAULT_TTL)


def test_first_matching_entry_wins(rewrites):
    cs = rewrites([
        {"name": "example.com", "type": "A", "value": "10.0.0.1"},
        {"name": "example.com", "type": "A", "value": "10.0.0.2"},
    ])
    assert find_rewrite("example.com", "A", cs) == ("10.0.0.1", DEFAULT_TTL)


def test_no_rewrites_configured_returns_none(config_store):
    assert find_rewrite("example.com", "A", config_store) is None
