import json
import time

from dnslib import QTYPE, RR, A, DNSRecord

from app.dns_cache import DNSCache


def _response(qname: str, ip: str = "1.2.3.4", ttl: int = 60) -> DNSRecord:
    request = DNSRecord.question(qname, qtype="A")
    reply = request.reply()
    reply.add_answer(RR(qname, QTYPE.A, rdata=A(ip), ttl=ttl))
    return reply


def test_get_stale_within_grace_returns_answer(config_store):
    cache = DNSCache(config_store)
    request = DNSRecord.question("expired.example.com", qtype="A")
    cache.put(request, _response("expired.example.com", ttl=1))

    key = cache._key(request)
    expires_at, answers, hits = cache._store[key]
    cache._store[key] = (time.time() - 10, answers, hits)

    stale = cache.get_stale(request, grace_seconds=60)
    assert stale is not None
    assert str(stale.rr[0].rdata) == "1.2.3.4"


def test_get_stale_beyond_grace_returns_none(config_store):
    cache = DNSCache(config_store)
    request = DNSRecord.question("gone.example.com", qtype="A")
    cache.put(request, _response("gone.example.com", ttl=1))

    key = cache._key(request)
    _expires_at, answers, hits = cache._store[key]
    cache._store[key] = (time.time() - 120, answers, hits)

    assert cache.get_stale(request, grace_seconds=60) is None


def test_purge_expired_removes_only_beyond_grace(config_store):
    cache = DNSCache(config_store)
    fresh_request = DNSRecord.question("fresh.example.com", qtype="A")
    old_request = DNSRecord.question("old.example.com", qtype="A")
    cache.put(fresh_request, _response("fresh.example.com", ttl=1))
    cache.put(old_request, _response("old.example.com", ttl=1))

    fresh_key = cache._key(fresh_request)
    old_key = cache._key(old_request)
    cache._store[fresh_key] = (time.time() - 5, cache._store[fresh_key][1], 0)
    cache._store[old_key] = (time.time() - 120, cache._store[old_key][1], 0)

    cache.purge_expired(grace_seconds=60)

    assert fresh_key in cache._store
    assert old_key not in cache._store


def test_expiring_soon_respects_min_hits_and_inflight(config_store):
    cache = DNSCache(config_store)
    request = DNSRecord.question("hot.example.com", qtype="A")
    cache.put(request, _response("hot.example.com", ttl=1))
    cache.get(request)
    key = cache._key(request)

    assert cache.expiring_soon(threshold_seconds=60, min_hits=1) == [key]
    assert cache.expiring_soon(threshold_seconds=60, min_hits=5) == []

    cache.mark_prefetching(key)
    assert cache.expiring_soon(threshold_seconds=60, min_hits=1) == []
    cache.clear_prefetching(key)
    assert cache.expiring_soon(threshold_seconds=60, min_hits=1) == [key]


def test_persistence_round_trip(config_store, tmp_path):
    path = tmp_path / "dns_cache.json"
    cache = DNSCache(config_store, persist_path=path)
    request = DNSRecord.question("persisted.example.com", qtype="A")
    cache.put(request, _response("persisted.example.com", ttl=300))
    cache.save()

    reloaded = DNSCache(config_store, persist_path=path)
    answer = reloaded.get(request)
    assert answer is not None
    assert str(answer.rr[0].rdata) == "1.2.3.4"


def test_persistence_drops_already_expired_entries(config_store, tmp_path):
    path = tmp_path / "dns_cache.json"
    cache = DNSCache(config_store, persist_path=path)
    request = DNSRecord.question("shortlived.example.com", qtype="A")
    cache.put(request, _response("shortlived.example.com", ttl=1))
    key = cache._key(request)
    cache._store[key] = (time.time() - 10, cache._store[key][1], 0)
    cache.save()

    reloaded = DNSCache(config_store, persist_path=path)
    assert reloaded.get(request) is None


def test_persisted_file_is_plain_json_not_pickle(config_store, tmp_path):
    path = tmp_path / "dns_cache.json"
    cache = DNSCache(config_store, persist_path=path)
    request = DNSRecord.question("jsoncheck.example.com", qtype="A")
    cache.put(request, _response("jsoncheck.example.com", ttl=300))
    cache.save()

    with open(path, encoding="utf-8") as f:
        data = json.load(f)
    assert data["version"] == 1
    assert data["entries"][0]["key"][0] == "jsoncheck.example.com."


def test_load_ignores_corrupt_or_hostile_file_contents(config_store, tmp_path):
    path = tmp_path / "dns_cache.json"

    path.write_text('{"not": "a pickle", "entries": "garbage"}', encoding="utf-8")
    cache = DNSCache(config_store, persist_path=path)
    assert cache.stats()["entries"] == 0

    path.write_text('{"version": 1, "entries": [{"key": ["a"], "answers": "not-a-list"}]}', encoding="utf-8")
    cache = DNSCache(config_store, persist_path=path)
    assert cache.stats()["entries"] == 0

    path.write_text('{"version": 1, "entries": [{"key": ["x.example.com.", 1, 1], "expires_at": 9999999999, "hits": 0, "answers": ["not-valid-base64-dns!!"]}]}', encoding="utf-8")
    cache = DNSCache(config_store, persist_path=path)
    assert cache.stats()["entries"] == 0

    path.write_text("not even json{{{", encoding="utf-8")
    cache = DNSCache(config_store, persist_path=path)
    assert cache.stats()["entries"] == 0
