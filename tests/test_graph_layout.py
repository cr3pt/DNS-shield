# SPDX-License-Identifier: BSD-3-Clause AND LicenseRef-Commons-Clause
# See the LICENSE file in the project root for full license terms.

import json
import re
import shutil
import subprocess
from pathlib import Path

import pytest

INDEX_HTML = Path(__file__).resolve().parent.parent / "app" / "web" / "static" / "index.html"

pytestmark = pytest.mark.skipif(shutil.which("node") is None, reason="node is required to run the graph simulation")

HARNESS = r"""
const fs = require("fs");
const vm = require("vm");
const html = fs.readFileSync(process.argv[2], "utf8");
const scenario = JSON.parse(process.argv[3]);

const slice = (from, to) => {
  const a = html.indexOf(from), b = html.indexOf(to);
  if (a < 0 || b < 0 || b < a) throw new Error("anchor missing: " + from + " .. " + to);
  return html.slice(a, b);
};
const radiusSrc = slice("function graphNodeRadius", "function graphNodeColor");
const physicsSrc = slice("const GRAPH_ALPHA_DECAY", "function graphNodeVisible");
const animateSrc = slice("function animateGraph", "function graphNodeAt");

const frames = [];
const sandbox = {
  Math, Map, Number, Infinity,
  requestAnimationFrame: (fn) => { frames.push(fn); return frames.length; },
  renderGraphFrame: () => {},
  graphState: {
    nodes: [], edges: [], width: scenario.w, height: scenario.h,
    alpha: 1, dragging: null, radiusCap: 20, animId: null, settled: false,
  },
};
vm.createContext(sandbox);
vm.runInContext(radiusSrc + physicsSrc + animateSrc, sandbox);

let seed = scenario.seed;
const rand = () => {
  seed = (seed + 0x6d2b79f5) | 0;
  let t = Math.imul(seed ^ (seed >>> 15), 1 | seed);
  t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
  return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
};

const build = vm.runInContext(`(function (sc, rand) {
  const total = sc.clients + sc.domains;
  graphState.radiusCap = graphRadiusCap(total, sc.w, sc.h);
  const nodes = [];
  for (let i = 0; i < total; i++) {
    const total_q = Math.floor(rand() * 5000) + 1;
    const start = sc.stacked ? { x: sc.w / 2, y: sc.h / 2 } : graphInitialPosition(i, total, sc.w, sc.h);
    const node = { type: i < sc.clients ? "client" : "domain", total: total_q, x: start.x, y: start.y, vx: 0, vy: 0 };
    node.r = graphNodeRadius(node);
    nodes.push(node);
  }
  const edges = [];
  for (let j = sc.clients; j < total; j++) {
    const links = 1 + Math.floor(rand() * Math.min(4, sc.clients));
    for (let k = 0; k < links; k++) {
      const c = Math.floor(rand() * sc.clients);
      const count = sc.minCount + Math.floor(rand() * (sc.maxCount - sc.minCount + 1));
      edges.push({ source: nodes[c], target: nodes[j], count, blocked: 0 });
    }
  }
  graphPrepareEdges(edges);
  graphState.nodes = nodes;
  graphState.edges = edges;
  graphState.alpha = 1;
  return nodes;
})`, sandbox);
const nodes = build(scenario, rand);

vm.runInContext("wakeGraphSimulation()", sandbox);
let ticks = 0, peak = 0;
while (frames.length && ticks < 2000) {
  frames.shift()();
  ticks++;
  for (const n of nodes) peak = Math.max(peak, Math.hypot(n.vx, n.vy));
}

const { width: w, height: h } = sandbox.graphState;
let nonFinite = 0, outOfBounds = 0, worstOverlap = Infinity;
for (const n of nodes) {
  if (!Number.isFinite(n.x) || !Number.isFinite(n.y)) nonFinite++;
  if (n.x < 0 || n.y < 0 || n.x > w || n.y > h) outOfBounds++;
}
for (let i = 0; i < nodes.length; i++) {
  for (let j = i + 1; j < nodes.length; j++) {
    const d = Math.hypot(nodes[i].x - nodes[j].x, nodes[i].y - nodes[j].y);
    worstOverlap = Math.min(worstOverlap, d / (nodes[i].r + nodes[j].r));
  }
}
console.log(JSON.stringify({ ticks, settled: sandbox.graphState.settled, peak, nonFinite, outOfBounds, worstOverlap, nodes: nodes.length }));
"""

SCENARIOS = {
    "small-counts": dict(clients=25, domains=120, minCount=1, maxCount=5, w=808, h=558),
    "huge-counts": dict(clients=25, domains=120, minCount=1, maxCount=200000, w=808, h=558),
    "hubs-with-huge-counts": dict(clients=12, domains=138, minCount=1000, maxCount=500000, w=808, h=558),
    "tiny-graph": dict(clients=3, domains=7, minCount=1, maxCount=50, w=808, h=558),
    "mobile": dict(clients=8, domains=32, minCount=1, maxCount=50000, w=303, h=418),
    "tablet": dict(clients=15, domains=65, minCount=1, maxCount=50000, w=668, h=418),
    "all-nodes-start-stacked": dict(clients=10, domains=40, minCount=1, maxCount=1000, w=808, h=558, stacked=True),
    "single-node": dict(clients=1, domains=0, minCount=1, maxCount=1, w=808, h=558),
}


def _run(name: str) -> dict:
    scenario = dict(SCENARIOS[name], seed=7)
    scenario.setdefault("stacked", False)
    result = subprocess.run(
        ["node", "-", str(INDEX_HTML), json.dumps(scenario)],
        input=HARNESS,
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert result.returncode == 0, result.stderr
    return json.loads(result.stdout.strip().splitlines()[-1])


@pytest.mark.parametrize("name", sorted(SCENARIOS))
def test_force_layout_settles_without_exploding(name):
    result = _run(name)

    assert result["settled"] is True
    assert result["ticks"] < 600
    assert result["nonFinite"] == 0
    assert result["outOfBounds"] == 0
    assert result["peak"] < 60


@pytest.mark.parametrize("name", ["small-counts", "huge-counts", "hubs-with-huge-counts", "mobile", "all-nodes-start-stacked"])
def test_force_layout_keeps_dots_from_piling_on_top_of_each_other(name):
    result = _run(name)

    assert result["worstOverlap"] > 0.9


def test_dragging_ends_when_the_button_is_released_outside_the_canvas():
    source = INDEX_HTML.read_text(encoding="utf-8")

    assert 'window.addEventListener("mouseup", pointerUp)' in source
    assert not re.search(r'canvas\.addEventListener\("mouseup"', source)
