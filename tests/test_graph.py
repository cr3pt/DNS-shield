# SPDX-License-Identifier: BSD-3-Clause AND LicenseRef-Commons-Clause
# See the LICENSE file in the project root for full license terms.

import pytest

from app.graph import ClientDomainGraph


class FakeGraphStats:
    def __init__(self):
        self._rows = []
        self._next_id = 1

    def add(self, domain, client, blocked=False, ts=None, qtype="A"):
        row = {
            "id": self._next_id,
            "ts": float(self._next_id) if ts is None else ts,
            "domain": domain,
            "qtype": qtype,
            "client": client,
            "blocked": blocked,
        }
        self._rows.append(row)
        self._next_id += 1
        return row

    def max_query_id(self):
        return self._rows[-1]["id"] if self._rows else 0

    def queries_since(self, last_id, limit=5000):
        return [r for r in self._rows if r["id"] > last_id][:limit]


def _make_graph(config_store, tmp_path, stats=None):
    return ClientDomainGraph(config_store, stats or FakeGraphStats(), tmp_path / "graph.db")


def test_first_process_call_only_initializes_cursor(config_store, tmp_path):
    stats = FakeGraphStats()
    stats.add("example.com", "10.0.0.1")
    graph = _make_graph(config_store, tmp_path, stats)

    graph._process_new_queries()
    result = graph.get_graph()
    assert result["clients"] == []
    assert result["domains"] == []
    assert result["edges"] == []

    stats.add("example2.com", "10.0.0.2")
    graph._process_new_queries()
    result = graph.get_graph()
    assert {c["id"] for c in result["clients"]} == {"10.0.0.2"}
    assert {d["id"] for d in result["domains"]} == {"example2.com"}


def test_subdomains_collapse_into_same_edge_and_count_increments(config_store, tmp_path):
    stats = FakeGraphStats()
    graph = _make_graph(config_store, tmp_path, stats)
    graph._process_new_queries()

    stats.add("a.example.com", "10.0.0.1", ts=100.0)
    stats.add("b.example.com", "10.0.0.1", ts=200.0)
    stats.add("c.example.com", "10.0.0.1", ts=300.0)
    graph._process_new_queries()

    result = graph.get_graph()
    assert len(result["edges"]) == 1
    edge = result["edges"][0]
    assert edge["client"] == "10.0.0.1"
    assert edge["domain"] == "example.com"
    assert edge["count"] == 3


def test_first_seen_fixed_last_seen_advances(config_store, tmp_path):
    stats = FakeGraphStats()
    graph = _make_graph(config_store, tmp_path, stats)
    graph._process_new_queries()

    stats.add("a.example.com", "10.0.0.1", ts=100.0)
    graph._process_new_queries()
    stats.add("b.example.com", "10.0.0.1", ts=250.0)
    graph._process_new_queries()

    edge = graph.get_graph()["edges"][0]
    assert edge["first_seen"] == 100.0
    assert edge["last_seen"] == 250.0


def test_reverse_dns_queries_are_excluded_entirely(config_store, tmp_path):
    stats = FakeGraphStats()
    graph = _make_graph(config_store, tmp_path, stats)
    graph._process_new_queries()

    stats.add("4.3.2.1.in-addr.arpa", "10.0.0.1")
    stats.add(
        "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.ip6.arpa",
        "10.0.0.1",
    )
    graph._process_new_queries()

    result = graph.get_graph()
    assert result["clients"] == []
    assert result["domains"] == []
    assert result["edges"] == []


def test_blocked_count_only_increments_for_blocked_queries(config_store, tmp_path):
    stats = FakeGraphStats()
    graph = _make_graph(config_store, tmp_path, stats)
    graph._process_new_queries()

    stats.add("example.com", "10.0.0.1", blocked=False)
    stats.add("example.com", "10.0.0.1", blocked=True)
    stats.add("example.com", "10.0.0.1", blocked=True)
    graph._process_new_queries()

    edge = graph.get_graph()["edges"][0]
    assert edge["count"] == 3
    assert edge["blocked"] == 2


def test_get_graph_min_count_filters_edges(config_store, tmp_path):
    stats = FakeGraphStats()
    graph = _make_graph(config_store, tmp_path, stats)
    graph._process_new_queries()

    stats.add("example.com", "10.0.0.1")
    stats.add("example.org", "10.0.0.2")
    stats.add("example.org", "10.0.0.2")
    graph._process_new_queries()

    result = graph.get_graph(min_count=2)
    assert {d["id"] for d in result["domains"]} == {"example.org"}
    assert {c["id"] for c in result["clients"]} == {"10.0.0.2"}
    assert len(result["edges"]) == 1
    assert result["edges"][0]["domain"] == "example.org"


def test_get_graph_restrict_client_ips(config_store, tmp_path):
    stats = FakeGraphStats()
    graph = _make_graph(config_store, tmp_path, stats)
    graph._process_new_queries()

    stats.add("example.com", "10.0.0.1")
    stats.add("example.org", "10.0.0.2")
    graph._process_new_queries()

    everyone = graph.get_graph(restrict_client_ips=None)
    assert {c["id"] for c in everyone["clients"]} == {"10.0.0.1", "10.0.0.2"}

    nobody = graph.get_graph(restrict_client_ips=[])
    assert nobody["clients"] == []
    assert nobody["domains"] == []
    assert nobody["edges"] == []

    only_one = graph.get_graph(restrict_client_ips=["10.0.0.1"])
    assert {c["id"] for c in only_one["clients"]} == {"10.0.0.1"}
    assert {d["id"] for d in only_one["domains"]} == {"example.com"}
    assert len(only_one["edges"]) == 1
    assert only_one["edges"][0]["client"] == "10.0.0.1"


def test_client_detail_restrict_client_ips_denies_access(config_store, tmp_path):
    stats = FakeGraphStats()
    graph = _make_graph(config_store, tmp_path, stats)
    graph._process_new_queries()

    stats.add("example.com", "10.0.0.1")
    graph._process_new_queries()

    assert graph.client_detail("10.0.0.1", restrict_client_ips=None) is not None
    assert graph.client_detail("10.0.0.1", restrict_client_ips=["10.0.0.1"]) is not None
    assert graph.client_detail("10.0.0.1", restrict_client_ips=["10.0.0.2"]) is None
    assert graph.client_detail("10.0.0.1", restrict_client_ips=[]) is None


def test_domain_detail_restrict_client_ips_filters_clients(config_store, tmp_path):
    stats = FakeGraphStats()
    graph = _make_graph(config_store, tmp_path, stats)
    graph._process_new_queries()

    stats.add("example.com", "10.0.0.1")
    stats.add("example.com", "10.0.0.2")
    graph._process_new_queries()

    full = graph.domain_detail("example.com", restrict_client_ips=None)
    assert {c["client"] for c in full["clients"]} == {"10.0.0.1", "10.0.0.2"}
    assert full["distinct_clients"] == 2

    filtered = graph.domain_detail("example.com", restrict_client_ips=["10.0.0.1"])
    assert {c["client"] for c in filtered["clients"]} == {"10.0.0.1"}
    assert filtered["distinct_clients"] == 1

    none_visible = graph.domain_detail("example.com", restrict_client_ips=[])
    assert none_visible["clients"] == []
    assert none_visible["distinct_clients"] == 0


def test_get_graph_limit_nodes_caps_and_sets_truncated(config_store, tmp_path):
    stats = FakeGraphStats()
    graph = _make_graph(config_store, tmp_path, stats)
    graph._process_new_queries()

    for i in range(5):
        stats.add(f"example{i}.com", f"10.0.0.{i}")
    graph._process_new_queries()

    capped = graph.get_graph(limit_nodes=2)
    assert len(capped["clients"]) == 2
    assert len(capped["domains"]) == 2
    assert capped["truncated"] is True

    uncapped = graph.get_graph(limit_nodes=0)
    assert len(uncapped["clients"]) == 5
    assert len(uncapped["domains"]) == 5
    assert uncapped["truncated"] is False


def test_suspicious_flags_only_the_outlier_client(config_store, tmp_path):
    config_store.mutate(lambda d: d.setdefault("graph", {}).update({
        "suspicious_zscore": 1.0,
        "suspicious_min_degree": 3,
    }))
    stats = FakeGraphStats()
    graph = _make_graph(config_store, tmp_path, stats)
    graph._process_new_queries()

    for i in range(5):
        stats.add(f"site{i}.com", f"10.0.1.{i}")
    for i in range(10):
        stats.add(f"outlier{i}.com", "10.0.2.1")
    graph._process_new_queries()

    result = graph.get_graph(limit_nodes=0)
    suspicious_clients = [c["id"] for c in result["clients"] if c["suspicious"]]
    assert suspicious_clients == ["10.0.2.1"]

    normal_client = next(c for c in result["clients"] if c["id"] == "10.0.1.0")
    assert normal_client["suspicious"] is False


def test_clear_wipes_all_edges(config_store, tmp_path):
    stats = FakeGraphStats()
    graph = _make_graph(config_store, tmp_path, stats)
    graph._process_new_queries()

    stats.add("example.com", "10.0.0.1")
    graph._process_new_queries()
    assert graph.get_graph()["clients"] != []

    graph.clear()

    result = graph.get_graph()
    assert result["clients"] == []
    assert result["domains"] == []
    assert result["edges"] == []


def _seed(graph, stats, rows):
    graph._process_new_queries()
    for domain, client, times in rows:
        for _ in range(times):
            stats.add(domain, client)
    graph._process_new_queries()


def _link_pairs(result):
    return {frozenset((link["a"], link["b"])) for link in result["links"]}


def test_domain_view_links_domains_that_the_same_clients_query(config_store, tmp_path):
    stats = FakeGraphStats()
    graph = _make_graph(config_store, tmp_path, stats)
    _seed(
        graph,
        stats,
        [
            ("a.com", "10.0.0.1", 5),
            ("b.com", "10.0.0.1", 5),
            ("c.com", "10.0.0.2", 5),
        ],
    )

    result = graph.get_graph(view="domains")

    assert result["view"] == "domains"
    assert result["clients"] == []
    assert result["edges"] == []
    assert {d["id"] for d in result["domains"]} == {"a.com", "b.com", "c.com"}
    assert _link_pairs(result) == {frozenset(("a.com", "b.com"))}
    link = result["links"][0]
    assert link["shared"] == 1
    assert link["weight"] == 1.0


def test_domain_view_weights_domains_by_how_alike_their_audiences_are(config_store, tmp_path):
    stats = FakeGraphStats()
    graph = _make_graph(config_store, tmp_path, stats)
    _seed(
        graph,
        stats,
        [
            ("same-a.com", "10.0.0.1", 10),
            ("same-a.com", "10.0.0.2", 10),
            ("same-b.com", "10.0.0.1", 10),
            ("same-b.com", "10.0.0.2", 10),
            ("lopsided.com", "10.0.0.1", 1),
            ("lopsided.com", "10.0.0.2", 30),
        ],
    )

    result = graph.get_graph(view="domains")
    weights = {frozenset((link["a"], link["b"])): link["weight"] for link in result["links"]}

    assert weights[frozenset(("same-a.com", "same-b.com"))] == 1.0
    assert weights[frozenset(("same-a.com", "lopsided.com"))] < 1.0
    assert all(link["shared"] == 2 for link in result["links"])


def test_client_view_links_clients_that_query_the_same_domains(config_store, tmp_path):
    stats = FakeGraphStats()
    graph = _make_graph(config_store, tmp_path, stats)
    _seed(
        graph,
        stats,
        [
            ("shared.com", "10.0.0.1", 3),
            ("shared.com", "10.0.0.2", 3),
            ("lonely.com", "10.0.0.3", 3),
        ],
    )

    result = graph.get_graph(view="clients")

    assert result["view"] == "clients"
    assert result["domains"] == []
    assert {c["id"] for c in result["clients"]} == {"10.0.0.1", "10.0.0.2", "10.0.0.3"}
    assert _link_pairs(result) == {frozenset(("10.0.0.1", "10.0.0.2"))}


def test_default_view_is_unchanged_and_carries_no_links(config_store, tmp_path):
    stats = FakeGraphStats()
    graph = _make_graph(config_store, tmp_path, stats)
    _seed(graph, stats, [("a.com", "10.0.0.1", 1), ("b.com", "10.0.0.1", 1)])

    result = graph.get_graph()

    assert result["view"] == "bipartite"
    assert result["links"] == []
    assert len(result["edges"]) == 2
    assert len(result["clients"]) == 1
    assert len(result["domains"]) == 2


def test_projection_never_reveals_clients_a_restricted_user_may_not_see(config_store, tmp_path):
    stats = FakeGraphStats()
    graph = _make_graph(config_store, tmp_path, stats)
    _seed(
        graph,
        stats,
        [
            ("mine.com", "10.0.0.1", 4),
            ("overlap.com", "10.0.0.1", 4),
            ("overlap.com", "10.0.0.2", 4),
            ("hidden-only.com", "10.0.0.2", 4),
            ("hidden-pair.com", "10.0.0.2", 4),
        ],
    )

    restricted = graph.get_graph(view="domains", restrict_client_ips=["10.0.0.1"])

    assert {d["id"] for d in restricted["domains"]} == {"mine.com", "overlap.com"}
    assert _link_pairs(restricted) == {frozenset(("mine.com", "overlap.com"))}
    assert restricted["links"][0]["shared"] == 1
    assert graph.get_graph(view="domains", restrict_client_ips=[])["links"] == []
    assert graph.get_graph(view="clients", restrict_client_ips=["10.0.0.1"])["links"] == []


def test_projection_respects_the_minimum_queries_per_edge(config_store, tmp_path):
    stats = FakeGraphStats()
    graph = _make_graph(config_store, tmp_path, stats)
    _seed(
        graph,
        stats,
        [
            ("busy-a.com", "10.0.0.1", 5),
            ("busy-b.com", "10.0.0.1", 5),
            ("quiet.com", "10.0.0.1", 1),
        ],
    )

    result = graph.get_graph(view="domains", min_count=3)

    assert {d["id"] for d in result["domains"]} == {"busy-a.com", "busy-b.com"}
    assert _link_pairs(result) == {frozenset(("busy-a.com", "busy-b.com"))}


def test_projection_keeps_only_the_closest_neighbours_of_each_node(config_store, tmp_path):
    stats = FakeGraphStats()
    graph = _make_graph(config_store, tmp_path, stats)
    domains = [f"site{i:02d}.com" for i in range(12)]
    _seed(graph, stats, [(domain, "10.0.0.1", 2) for domain in domains])

    result = graph.get_graph(view="domains")

    degree = {}
    for link in result["links"]:
        degree[link["a"]] = degree.get(link["a"], 0) + 1
        degree[link["b"]] = degree.get(link["b"], 0) + 1
    assert set(degree) == set(domains)
    assert len(result["links"]) <= len(domains) * 3
    assert len(result["links"]) < len(domains) * (len(domains) - 1) // 2


def test_projection_is_empty_with_a_single_node(config_store, tmp_path):
    stats = FakeGraphStats()
    graph = _make_graph(config_store, tmp_path, stats)
    _seed(graph, stats, [("only.com", "10.0.0.1", 2)])

    assert graph.get_graph(view="domains")["links"] == []


def test_an_unknown_view_is_rejected(config_store, tmp_path):
    graph = _make_graph(config_store, tmp_path)

    with pytest.raises(ValueError):
        graph.get_graph(view="everything")


def test_projection_views_cap_how_many_nodes_they_will_compare(config_store, tmp_path, monkeypatch):
    import app.graph as graph_module

    monkeypatch.setattr(graph_module, "_PROJECTION_MAX_NODES", 5)
    stats = FakeGraphStats()
    graph = _make_graph(config_store, tmp_path, stats)
    _seed(graph, stats, [(f"site{i}.com", "10.0.0.1", i + 1) for i in range(12)])

    for limit in (0, 1000):
        result = graph.get_graph(view="domains", limit_nodes=limit)
        assert len(result["domains"]) == 5
        assert result["truncated"] is True

    assert len(graph.get_graph(view="bipartite", limit_nodes=0)["domains"]) == 12
