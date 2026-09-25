from app.graph import ClientDomainGraph


class FakeGraphStats:
    """Minimal local stand-in for app.stats.Stats, scoped to this test file.

    Provides just the two methods ClientDomainGraph needs: max_query_id()
    and queries_since(last_id, limit=5000).
    """

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

    # First call after construction is a no-op: it only sets the cursor to
    # the current max_query_id, mirroring AnomalyDetector.check_new_dns_clients().
    graph._process_new_queries()
    result = graph.get_graph()
    assert result["clients"] == []
    assert result["domains"] == []
    assert result["edges"] == []

    # Only rows added after the cursor snapshot are processed on the next call.
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

    stats.add("example.com", "10.0.0.1")  # count 1
    stats.add("example.org", "10.0.0.2")
    stats.add("example.org", "10.0.0.2")  # count 2
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

    # None -> no restriction, sees everything.
    everyone = graph.get_graph(restrict_client_ips=None)
    assert {c["id"] for c in everyone["clients"]} == {"10.0.0.1", "10.0.0.2"}

    # [] -> sees nothing.
    nobody = graph.get_graph(restrict_client_ips=[])
    assert nobody["clients"] == []
    assert nobody["domains"] == []
    assert nobody["edges"] == []

    # A specific list filters to just those clients (and their domains/edges).
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

    # domain_detail filters clients rather than denying the whole call.
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

    # Five ordinary clients, each visiting exactly one domain (degree 1).
    for i in range(5):
        stats.add(f"site{i}.com", f"10.0.1.{i}")
    # One outlier client visiting ten distinct domains (degree 10).
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
