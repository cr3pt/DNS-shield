# SPDX-License-Identifier: BSD-3-Clause AND LicenseRef-Commons-Clause
# See the LICENSE file in the project root for full license terms.

import re
from pathlib import Path

INDEX_HTML = Path(__file__).resolve().parent.parent / "app" / "web" / "static" / "index.html"


def _function_source(name: str) -> str:
    source = INDEX_HTML.read_text(encoding="utf-8")
    match = re.search(rf"(?:const {name} =|function {name}\().*?(?=\n\n)", source, re.S)
    assert match, f"{name} not found in index.html"
    return match.group(0)


def test_log_time_column_includes_the_date():
    body = _function_source("fmtTime")

    assert "toLocaleTimeString" not in body
    for option in ("year", "month", "day", "hour", "minute", "second"):
        assert option in body


def test_every_time_cell_uses_the_shared_formatter():
    source = INDEX_HTML.read_text(encoding="utf-8")
    cells = re.findall(r'data-label": (?:t\("col\.time", "Time"\)|"Time")', source)

    assert cells
    assert "toLocaleTimeString()" not in source


def test_trend_tooltip_always_includes_the_date():
    body = _function_source("fmtTrendTooltipLabel")

    assert re.search(r'rangeKey === "24h"\s*\?\s*date\s*\+', body)
    assert re.search(r":\s*date\s*\+", body)


def test_client_group_editor_manages_match_patterns_and_filtering_with_explicit_calls():
    source = INDEX_HTML.read_text(encoding="utf-8")

    assert "/api/client-groups/${index}/match" in source
    assert "/api/client-groups/${index}/enabled" in source
    assert "/api/client-groups/${i}/toggle" not in source


def test_client_group_editor_can_rename_a_group():
    source = INDEX_HTML.read_text(encoding="utf-8")

    assert "/api/client-groups/${index}/name" in source
    assert 'method: "PUT"' in source


def test_query_log_can_be_filtered_by_client_group():
    source = INDEX_HTML.read_text(encoding="utf-8")

    assert 'id="ql-group"' in source
    assert 'params.set("group"' in source
    assert 'params.set("no_group"' in source
