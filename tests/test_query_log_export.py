# SPDX-License-Identifier: BSD-3-Clause AND LicenseRef-Commons-Clause
# See the LICENSE file in the project root for full license terms.

"""Query log export (CSV / JSON lines) and syslog forwarding."""

import csv
import io
import json
import socket
import time

from fastapi.testclient import TestClient

from app.blocklist import BlocklistManager
from app.stats import Stats
from app.syslog_export import format_message
from app.web.server import CSRF_COOKIE_NAME, CSRF_HEADER_NAME, create_app


def _wait_for(check, timeout=5.0):
    deadline = time.time() + timeout
    while time.time() < deadline:
        if check():
            return True
        time.sleep(0.02)
    return False


def _client(config_store, tmp_path):
    config_store.mutate(lambda d: d.setdefault("web", {}).update({"https_enabled": False}))
    stats = Stats(tmp_path / "stats.db", config_store, flush_interval=0.05)
    app = create_app(
        config_store, BlocklistManager(config_store, tmp_path / "cache"), stats, started_at=0.0, data_dir=tmp_path
    )
    client = TestClient(app)
    assert client.post("/api/login", json={"username": "admin", "password": "changeme"}).status_code == 200
    client.headers[CSRF_HEADER_NAME] = client.cookies[CSRF_COOKIE_NAME]
    return client, stats


def test_csv_export_follows_filters_and_defuses_formulas(config_store, tmp_path):
    client, stats = _client(config_store, tmp_path)
    stats.record("ads.example", True, "192.168.1.50", "A", reason="Blocklist: test")
    stats.record("ok.example", False, "192.168.1.50", "AAAA")
    stats.record("=cmd.example", False, "192.168.1.51", "A")
    assert _wait_for(lambda: stats.query_log()[1] == 3)

    response = client.get("/api/query-log/export?format=csv")
    assert response.status_code == 200
    assert response.headers["content-type"].startswith("text/csv")
    assert "attachment" in response.headers["content-disposition"]
    rows = list(csv.DictReader(io.StringIO(response.text)))
    assert [r["domain"] for r in rows] == ["'=cmd.example", "ok.example", "ads.example"]
    assert rows[2]["blocked"] == "True" and rows[2]["reason"] == "Blocklist: test"
    assert rows[0]["time"].endswith("+00:00")

    blocked = list(csv.DictReader(io.StringIO(client.get("/api/query-log/export?blocked=true").text)))
    assert [r["domain"] for r in blocked] == ["ads.example"]

    limited = list(csv.DictReader(io.StringIO(client.get("/api/query-log/export?limit=2").text)))
    assert len(limited) == 2


def test_jsonl_export_streams_in_batches(config_store, tmp_path):
    client, stats = _client(config_store, tmp_path)
    for i in range(25):
        stats.record(f"d{i}.example", False, "192.168.1.50", "A")
    assert _wait_for(lambda: stats.query_log()[1] == 25)
    assert len(list(stats.iter_query_log(max_rows=100, batch=7))) == 25
    assert [r["domain"] for r in stats.iter_query_log(max_rows=3, batch=2)] == ["d24.example", "d23.example", "d22.example"]

    response = client.get("/api/query-log/export?format=jsonl&domain=d1")
    lines = [json.loads(line) for line in response.text.splitlines()]
    assert sorted(line["domain"] for line in lines) == sorted(f"d{i}.example" for i in [1, *range(10, 20)])
    assert client.get("/api/query-log/export?format=xml").status_code == 422


def test_syslog_message_format():
    entry = {"ts": 0, "client": "10.0.0.5", "domain": "ads.example", "qtype": "A", "blocked": True, "reason": 'Blocklist: "x"'}
    text = format_message(entry, "text", "box").decode()
    assert text.startswith("<133>1 1970-01-01T00:00:00.000Z box dns-shield ")
    assert 'client="10.0.0.5" domain="ads.example" qtype="A" blocked="1" reason="Blocklist: \\"x\\""' in text
    allowed = format_message({**entry, "blocked": False}, "json", "box").decode()
    assert allowed.startswith("<134>1 ")
    assert json.loads(allowed.split(" - ", 1)[1])["domain"] == "ads.example"


def test_queries_are_forwarded_over_udp(config_store, tmp_path):
    receiver = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    receiver.bind(("127.0.0.1", 0))
    receiver.settimeout(5)
    port = receiver.getsockname()[1]
    config_store.mutate(
        lambda d: d.setdefault("logging", {}).update(
            syslog_enabled=True, syslog_host="127.0.0.1", syslog_port=port, syslog_only_blocked=True
        )
    )
    stats = Stats(tmp_path / "stats.db", config_store, flush_interval=0.05)
    stats.record("fine.example", False, "192.168.1.50", "A")
    stats.record("ads.example", True, "192.168.1.50", "A", reason="Denylist (manually added)")
    message = receiver.recv(4096).decode()
    receiver.close()
    assert "ads.example" in message and message.startswith("<133>1 ")


def test_queries_are_forwarded_over_tcp(config_store, tmp_path):
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(("127.0.0.1", 0))
    server.listen(1)
    server.settimeout(5)
    port = server.getsockname()[1]
    config_store.mutate(
        lambda d: d.setdefault("logging", {}).update(
            syslog_enabled=True, syslog_host="127.0.0.1", syslog_port=port, syslog_protocol="tcp", syslog_format="json"
        )
    )
    stats = Stats(tmp_path / "stats.db", config_store, flush_interval=0.05)
    stats.record("one.example", False, "192.168.1.50", "A")
    conn, _ = server.accept()
    conn.settimeout(5)
    data = b""
    while b"one.example" not in data:
        data += conn.recv(4096)
    conn.close()
    server.close()
    length, _, rest = data.partition(b" ")
    assert int(length) == len(rest)
    assert json.loads(rest.decode().split(" - ", 1)[1])["domain"] == "one.example"


def test_syslog_settings_validation(config_store, tmp_path):
    client, _stats = _client(config_store, tmp_path)
    assert client.patch("/api/settings/logging", json={"syslog_protocol": "smoke"}).status_code == 422
    assert client.patch("/api/settings/logging", json={"syslog_port": 70000}).status_code == 422
    assert client.patch("/api/settings/logging", json={"syslog_host": "bad host"}).status_code == 422
    ok = client.patch("/api/settings/logging", json={"syslog_enabled": True, "syslog_host": "[fd00::5]", "syslog_protocol": "tcp"})
    assert ok.status_code == 200
    assert config_store.get("logging", "syslog_host") == "fd00::5"
