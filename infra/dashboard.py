"""Live web dashboard — the demo centerpiece (spec C9).

A single dark-themed page plus a small JSON API, both served by
FastAPI/uvicorn. The page polls `/api/*` every 5 seconds and renders the
full red-to-blue lifecycle across eight views:

  1. Overview          — headline stats
  2. Coverage heatmap  — the 18 attack zones
  3. Finding timeline  — idea -> verdict -> repro -> patch
  4. Repro packages    — minimal steps, repro rate, cold-verify status
  5. Blue team         — patch candidates + regression tests
  6. Evidence timeline — triggered checks and alerts
  7. Search intel      — ideation cells, source modes, judge tiers
  8. Cost / model      — tokens and cost estimate

Everything is read straight from the persistent SQLite knowledge base
through read-only connections, one per request. The page builds its DOM
with `textContent` (never `innerHTML` with data), so LLM-authored text
in the KB cannot inject markup.

    monkeyclaw dashboard --port 8787
"""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from typing import Any

# Blended estimate for the NVIDIA Nemotron backend (USD per 1M tokens).
# Used only for the demo cost panel — not a billing figure.
_USD_PER_MTOKEN = 0.20


# ---------------------------------------------------------------------------
# DB access — read-only, one connection per request
# ---------------------------------------------------------------------------


def _query(db_path: str, sql: str, params: tuple = ()) -> list[dict[str, Any]]:
    if not Path(db_path).exists():
        return []
    conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
    conn.row_factory = sqlite3.Row
    try:
        return [dict(r) for r in conn.execute(sql, params).fetchall()]
    except sqlite3.Error:
        return []
    finally:
        conn.close()


def _scalar(db_path: str, sql: str, params: tuple = (), default: Any = 0) -> Any:
    rows = _query(db_path, sql, params)
    if not rows:
        return default
    val = next(iter(rows[0].values()))
    return val if val is not None else default


def _loads(blob: Any, fallback: Any) -> Any:
    if not blob:
        return fallback
    try:
        return json.loads(blob)
    except (ValueError, TypeError):
        return fallback


# ---------------------------------------------------------------------------
# View 1 — Overview
# ---------------------------------------------------------------------------


def _overview(db_path: str) -> dict[str, Any]:
    verdicts = {
        r["verdict"]: r["n"]
        for r in _query(
            db_path,
            "SELECT verdict, COUNT(*) AS n FROM findings GROUP BY verdict",
        )
    }
    patches = {
        r["status"]: r["n"]
        for r in _query(
            db_path,
            "SELECT status, COUNT(*) AS n FROM patches GROUP BY status",
        )
    }
    reg = _query(
        db_path,
        "SELECT last_run_result, COUNT(*) AS n FROM regression_tests "
        "WHERE deprecated = 0 GROUP BY last_run_result",
    )
    ran = sum(r["n"] for r in reg if r["last_run_result"] in ("pass", "fail"))
    passed = sum(r["n"] for r in reg if r["last_run_result"] == "pass")
    zones = _query(db_path, "SELECT coverage_score FROM surface_zones")
    return {
        "cycles": _scalar(db_path, "SELECT COUNT(*) FROM cycle_log"),
        "findings_confirmed": verdicts.get("confirmed", 0),
        "findings_suspicious": verdicts.get("suspicious", 0),
        "findings_total": sum(verdicts.values()),
        "patches_open": patches.get("proposed", 0) + patches.get("testing", 0),
        "patches_verified": patches.get("approved", 0),
        "patches_rejected": patches.get("rejected", 0),
        "regression_tests": ran,
        "regression_pass_rate": round(passed / ran, 4) if ran else 0.0,
        "mean_coverage": (
            round(sum(z["coverage_score"] for z in zones) / len(zones), 4)
            if zones else 0.0
        ),
    }


# ---------------------------------------------------------------------------
# View 2 — Coverage heatmap
# ---------------------------------------------------------------------------


def _zones(db_path: str) -> list[dict[str, Any]]:
    return _query(
        db_path,
        "SELECT zone_id, name, coverage_score, vulns_open, vulns_found, "
        "vulns_patched, last_tested_at FROM surface_zones "
        "ORDER BY coverage_score ASC, zone_id",
    )


# ---------------------------------------------------------------------------
# View 3 — Finding timeline
# ---------------------------------------------------------------------------


def _finding_timeline(db_path: str) -> list[dict[str, Any]]:
    findings = _query(
        db_path,
        "SELECT finding_id, cycle_id, zone_id, source_mode, idea_summary, "
        "verdict, tier_caught, failure_class, severity, evidence, "
        "repro_rate, patch_status, created_at FROM findings "
        "ORDER BY created_at DESC, finding_id DESC",
    )
    pkg_status = {
        r["finding_id"]: r["blue_team_status"]
        for r in _query(
            db_path,
            "SELECT finding_id, blue_team_status FROM repro_packages",
        )
    }
    queue_status = {
        r["finding_id"]: r["status"]
        for r in _query(db_path, "SELECT finding_id, status FROM repro_queue")
    }
    rows: list[dict[str, Any]] = []
    for f in findings:
        ev = _loads(f["evidence"], [])
        triggered = [c for c in ev if isinstance(c, dict) and c.get("triggered")]
        rows.append({
            "finding_id": f["finding_id"],
            "cycle_id": f["cycle_id"],
            "zone_id": f["zone_id"],
            "source_mode": f["source_mode"],
            "idea_summary": f["idea_summary"],
            "verdict": f["verdict"],
            "tier_caught": f["tier_caught"],
            "failure_class": f["failure_class"],
            "severity": f["severity"],
            "evidence_count": len(triggered),
            "repro_rate": f["repro_rate"],
            "repro_status": pkg_status.get(
                f["finding_id"], queue_status.get(f["finding_id"], "none")),
            "patch_status": f["patch_status"],
            "created_at": f["created_at"],
        })
    return rows


# ---------------------------------------------------------------------------
# View 4 — Repro package view
# ---------------------------------------------------------------------------


def _repro_packages(db_path: str) -> list[dict[str, Any]]:
    pkgs = _query(
        db_path,
        "SELECT package_id, vuln_id, title, severity, repro_rate, "
        "minimal_steps, affected_zone, affected_paths, cold_verified, "
        "ready_for_blue, blue_team_status, created_at FROM repro_packages "
        "ORDER BY created_at DESC, vuln_id DESC",
    )
    rows: list[dict[str, Any]] = []
    for p in pkgs:
        steps = _loads(p["minimal_steps"], [])
        paths = _loads(p["affected_paths"], [])
        rows.append({
            "package_id": p["package_id"],
            "vuln_id": p["vuln_id"],
            "title": p["title"],
            "severity": p["severity"],
            "repro_rate": p["repro_rate"],
            "step_count": len(steps) if isinstance(steps, list) else 0,
            "affected_zone": p["affected_zone"],
            "affected_path_count": len(paths) if isinstance(paths, list) else 0,
            "cold_verified": bool(p["cold_verified"]),
            "ready_for_blue": bool(p["ready_for_blue"]),
            "blue_team_status": p["blue_team_status"],
        })
    return rows


# ---------------------------------------------------------------------------
# View 5 — Blue team view
# ---------------------------------------------------------------------------


def _blue_team(db_path: str) -> dict[str, Any]:
    patches = [
        {
            "patch_id": p["patch_id"],
            "zone_id": p["zone_id"],
            "approach": p["approach"],
            "invasiveness": p["invasiveness"],
            "status": p["status"],
            "vuln_ids": _loads(p["vuln_ids"], []),
        }
        for p in _query(
            db_path,
            "SELECT patch_id, zone_id, approach, invasiveness, status, "
            "vuln_ids FROM patches ORDER BY created_at DESC, patch_id DESC",
        )
    ]
    tests = _query(
        db_path,
        "SELECT test_id, vuln_id, zone_id, expected_result, "
        "last_run_result, consecutive_passes, deprecated "
        "FROM regression_tests ORDER BY created_at DESC, test_id DESC",
    )
    return {"patches": patches, "regression_tests": tests}


# ---------------------------------------------------------------------------
# View 6 — Evidence timeline
# ---------------------------------------------------------------------------


def _evidence_timeline(db_path: str) -> list[dict[str, Any]]:
    """Best-effort security event stream from the data the KB persists:
    triggered Tier 1 checks (file/network/process evidence) and the
    outbound alert log."""
    rows: list[dict[str, Any]] = []
    for f in _query(
        db_path,
        "SELECT finding_id, zone_id, severity, evidence, created_at "
        "FROM findings ORDER BY created_at DESC",
    ):
        for c in _loads(f["evidence"], []):
            if not isinstance(c, dict) or not c.get("triggered"):
                continue
            rows.append({
                "kind": "check",
                "ts": f["created_at"],
                "zone_id": f["zone_id"],
                "severity": c.get("severity", f["severity"]),
                "label": c.get("check_name", "tier1_check"),
                "detail": c.get("evidence", {}),
                "finding_id": f["finding_id"],
            })
    for a in _query(
        db_path,
        "SELECT message, severity, channel, delivered, created_at "
        "FROM alerts ORDER BY created_at DESC",
    ):
        rows.append({
            "kind": "alert",
            "ts": a["created_at"],
            "zone_id": "",
            "severity": a["severity"],
            "label": f"alert via {a['channel']}",
            "detail": {"message": a["message"],
                       "delivered": bool(a["delivered"])},
            "finding_id": "",
        })
    rows.sort(key=lambda r: r["ts"] or "", reverse=True)
    return rows


# ---------------------------------------------------------------------------
# View 7 — Search intelligence
# ---------------------------------------------------------------------------


def _search_intel(db_path: str) -> dict[str, Any]:
    """Summarizes the red-team search: which zone 'cells' have been
    explored, the ideation source-mode mix (MonkeyClaw's mutation
    operators), the dedup rate, and the judge tier breakdown."""
    ideas = _query(
        db_path,
        "SELECT zone_id, source_mode, deduplicated FROM ideas",
    )
    source_modes: dict[str, int] = {}
    cells: set[str] = set()
    deduped = 0
    for i in ideas:
        source_modes[i["source_mode"]] = source_modes.get(
            i["source_mode"], 0) + 1
        cells.add(i["zone_id"])
        if i["deduplicated"]:
            deduped += 1
    tiers = {
        r["tier_caught"]: r["n"]
        for r in _query(
            db_path,
            "SELECT tier_caught, COUNT(*) AS n FROM findings "
            "GROUP BY tier_caught",
        )
    }
    total_zones = _scalar(
        db_path, "SELECT COUNT(*) FROM surface_zones", default=18)
    # MAP-Elites archive — the (zone, interaction_style, response_movement)
    # niche grid. Each occupied cell holds the best-scoring attempt seen.
    archive = _query(
        db_path,
        "SELECT zone_id, interaction_style, response_movement, "
        "best_score, occupancy FROM idea_archive_cells "
        "ORDER BY best_score DESC",
    )
    return {
        "cells_explored": len(cells),
        "cells_total": total_zones,
        "ideas_total": len(ideas),
        "source_modes": source_modes,
        "dedup_rate": round(deduped / len(ideas), 4) if ideas else 0.0,
        "tier_breakdown": tiers,
        "archive_niches_filled": len(archive),
        "archive_total_attempts": sum(c["occupancy"] for c in archive),
        "archive_top_niches": [
            {
                "zone": c["zone_id"],
                "interaction_style": c["interaction_style"],
                "response_movement": c["response_movement"],
                "best_score": round(c["best_score"], 3),
                "occupancy": c["occupancy"],
            }
            for c in archive[:8]
        ],
    }


# ---------------------------------------------------------------------------
# View 8 — Cost / model stats
# ---------------------------------------------------------------------------


def _cost_stats(db_path: str) -> dict[str, Any]:
    cycles = _query(
        db_path,
        "SELECT cycle_id, total_tokens_used, wall_time_seconds "
        "FROM cycle_log ORDER BY cycle_id",
    )
    total_tokens = sum(c["total_tokens_used"] or 0 for c in cycles)
    verdicts = {
        r["verdict"]: r["n"]
        for r in _query(
            db_path,
            "SELECT verdict, COUNT(*) AS n FROM findings GROUP BY verdict",
        )
    }
    confirmed = verdicts.get("confirmed", 0)
    attempts = sum(verdicts.values())
    return {
        "total_tokens": total_tokens,
        "cost_estimate_usd": round(
            total_tokens / 1_000_000 * _USD_PER_MTOKEN, 4),
        "tokens_per_cycle": [
            {"cycle_id": c["cycle_id"],
             "tokens": c["total_tokens_used"] or 0}
            for c in cycles
        ],
        "verdict_breakdown": verdicts,
        "confirm_rate": round(confirmed / attempts, 4) if attempts else 0.0,
    }


# ---------------------------------------------------------------------------
# The page — static structure; the script builds all data nodes with
# textContent, so KB content can never inject markup.
# ---------------------------------------------------------------------------


_PAGE = """<!doctype html>
<html lang="en"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>MonkeyClaw</title>
<style>
  :root { --bg:#0a0c10; --panel:#12161d; --line:#222a35; --txt:#e6edf3;
          --dim:#7d8a9c; --accent:#f5a623; --crit:#ff4d4d; --high:#ff8c42;
          --med:#ffd23f; --low:#5cc8ff; --ok:#3fb950; }
  * { box-sizing:border-box; margin:0; }
  body { background:var(--bg); color:var(--txt); font:14px/1.5 ui-monospace,
         "SF Mono",Menlo,Consolas,monospace; padding:20px 24px; }
  h1 { font-size:28px; letter-spacing:.5px; }
  h1 .sub { color:var(--dim); font-size:14px; font-weight:400; }
  h2 { font-size:12px; text-transform:uppercase; letter-spacing:1.5px;
       color:var(--dim); margin:0 0 10px; }
  .panel { background:var(--panel); border:1px solid var(--line);
           border-radius:10px; padding:16px; margin-top:16px; }
  .stats { display:flex; gap:12px; flex-wrap:wrap; }
  .stat { background:var(--panel); border:1px solid var(--line);
          border-radius:10px; padding:12px 18px; flex:1; min-width:130px; }
  .stat .v { font-size:30px; font-weight:700; color:var(--accent); }
  .stat .l { color:var(--dim); font-size:11px; text-transform:uppercase;
             letter-spacing:1px; }
  .grid { display:grid; grid-template-columns:repeat(auto-fill,minmax(168px,1fr));
          gap:9px; }
  .zone { border:1px solid var(--line); border-radius:8px; padding:10px 12px; }
  .zone .id { font-weight:700; font-size:13px; }
  .zone .meta { color:var(--dim); font-size:11px; margin-top:3px; }
  .bar { height:6px; border-radius:4px; background:#1c2530; margin-top:8px;
         overflow:hidden; }
  .bar > i { display:block; height:100%; }
  .cols { display:grid; grid-template-columns:1fr 1fr; gap:16px; }
  table { width:100%; border-collapse:collapse; font-size:12px; }
  th { text-align:left; color:var(--dim); font-weight:600; padding:5px 8px;
       border-bottom:1px solid var(--line); text-transform:uppercase;
       font-size:10px; letter-spacing:1px; }
  td { padding:5px 8px; border-bottom:1px solid #0e1218; }
  tr:hover td { background:#0e1218; }
  .badge { display:inline-block; padding:1px 7px; border-radius:5px;
           font-size:10px; font-weight:700; text-transform:uppercase;
           color:#000; }
  .evt { border-left:3px solid var(--line); padding:6px 11px; margin-bottom:6px;
         background:#0e1218; border-radius:0 6px 6px 0; font-size:12px; }
  .empty { color:var(--dim); padding:12px 0; }
  .pill { font-size:11px; color:var(--dim); }
  .line { margin:2px 0; }
  #dot { color:var(--ok); }
</style></head><body>
<h1>MonkeyClaw <span class="sub">&mdash; autonomous red/blue agent-security loop &nbsp;<span id="dot">&#9679;</span> live</span></h1>

<div class="stats" id="overview"></div>

<div class="panel">
  <h2>Attack Surface &mdash; coverage heatmap (18 zones)</h2>
  <div class="grid" id="zones"></div>
</div>

<div class="panel">
  <h2>Finding Timeline &mdash; idea &rarr; verdict &rarr; repro &rarr; patch</h2>
  <div id="timeline"></div>
</div>

<div class="cols">
  <div class="panel"><h2>Repro Packages</h2><div id="repro"></div></div>
  <div class="panel"><h2>Blue Team &mdash; patches &amp; regression tests</h2>
    <div id="blue"></div></div>
</div>

<div class="cols">
  <div class="panel"><h2>Evidence Timeline</h2><div id="evidence"></div></div>
  <div class="panel"><h2>Search Intelligence</h2><div id="search"></div></div>
</div>

<div class="panel"><h2>Cost &amp; Model Stats</h2><div id="cost"></div></div>

<script>
// --- safe DOM builders: every data value goes through textContent ---
const SEV = {critical:"var(--crit)",high:"var(--high)",medium:"var(--med)",low:"var(--low)"};
const sevColor = s => SEV[s] || "var(--line)";
const heat = c => `hsl(${Math.round(c*120)},70%,45%)`;

function h(tag, opts, kids){
  const e = document.createElement(tag);
  opts = opts || {};
  if(opts.cls) e.className = opts.cls;
  if(opts.style) e.style.cssText = opts.style;
  if(opts.text != null) e.textContent = String(opts.text);
  (kids || []).forEach(k => { if(k) e.appendChild(k); });
  return e;
}
function mount(id, node){
  const host = document.getElementById(id);
  while(host.firstChild) host.removeChild(host.firstChild);
  host.appendChild(node);
}
function empty(msg){ return h('div', {cls:'empty', text:msg}); }
function badge(text, color){
  return h('span', {cls:'badge', style:`background:${color}`, text:text});
}
function td(content){
  const e = h('td');
  if(content instanceof Node) e.appendChild(content);
  else e.textContent = content == null ? '' : String(content);
  return e;
}
function table(headers, rows){
  const t = h('table');
  t.appendChild(h('tr', null, headers.map(x => h('th', {text:x}))));
  rows.forEach(cells => t.appendChild(h('tr', null, cells.map(td))));
  return t;
}
async function j(u){ try { return await (await fetch(u)).json(); } catch(e){ return null; } }

async function tick(){
  const ov = await j('/api/overview');
  if(ov){
    const stats = [
      ['cycles', ov.cycles], ['confirmed', ov.findings_confirmed],
      ['suspicious', ov.findings_suspicious],
      ['verified patches', ov.patches_verified],
      ['open patches', ov.patches_open],
      ['regression pass', (ov.regression_pass_rate*100).toFixed(0)+'%'],
      ['mean coverage', (ov.mean_coverage*100).toFixed(0)+'%'],
    ];
    const host = document.getElementById('overview');
    while(host.firstChild) host.removeChild(host.firstChild);
    stats.forEach(([l,v]) => host.appendChild(
      h('div', {cls:'stat'}, [
        h('div', {cls:'v', text:v}), h('div', {cls:'l', text:l})])));
  }

  const z = await j('/api/zones') || [];
  if(z.length){
    mount('zones', h('div', {cls:'grid'}, z.map(x => {
      const bar = h('div', {cls:'bar'}, [h('i', {style:
        `width:${Math.max(3,x.coverage_score*100)}%;background:${heat(x.coverage_score)}`})]);
      return h('div', {cls:'zone'}, [
        h('div', {cls:'id', text:x.zone_id}),
        h('div', {cls:'meta',
          text:`${x.name} · open ${x.vulns_open} · patched ${x.vulns_patched}`}),
        bar]);
    })));
  } else { mount('zones', empty('no zones loaded')); }

  const tl = await j('/api/finding-timeline') || [];
  mount('timeline', tl.length ? table(
    ['finding','zone','mode','verdict','severity','evidence','repro','patch'],
    tl.map(x => [
      x.finding_id, x.zone_id, x.source_mode, x.verdict,
      badge(x.severity, sevColor(x.severity)),
      `${x.evidence_count} chk`, x.repro_status, x.patch_status])))
    : empty('no findings yet'));

  const rp = await j('/api/repro-packages') || [];
  mount('repro', rp.length ? table(
    ['vuln','title','rate','steps','cold','status'],
    rp.map(x => [
      x.vuln_id, (x.title||'').slice(0,38),
      `${(x.repro_rate*100).toFixed(0)}%`, x.step_count,
      x.cold_verified ? '✓' : '—', x.blue_team_status])))
    : empty('no repro packages yet'));

  const bt = await j('/api/blue-team') || {patches:[], regression_tests:[]};
  const blueHost = document.createElement('div');
  blueHost.appendChild((bt.patches||[]).length ? table(
    ['patch','zone','approach','invasive','status'],
    bt.patches.map(x => [
      x.patch_id, x.zone_id, (x.approach||'').slice(0,30),
      x.invasiveness, x.status]))
    : empty('no patch candidates yet'));
  if((bt.regression_tests||[]).length){
    const rt = table(['test','zone','last run','streak'],
      bt.regression_tests.map(x => [
        x.test_id, x.zone_id, x.last_run_result || '—',
        `${x.consecutive_passes}×`]));
    rt.style.marginTop = '10px';
    blueHost.appendChild(rt);
  }
  mount('blue', blueHost);

  const ev = await j('/api/evidence-timeline') || [];
  if(ev.length){
    const host = document.createElement('div');
    ev.slice(0,30).forEach(x => {
      host.appendChild(h('div',
        {cls:'evt', style:`border-left-color:${sevColor(x.severity)}`}, [
          badge(x.kind, sevColor(x.severity)),
          h('b', {text:` ${x.label} `}),
          h('span', {text:x.zone_id}),
          h('div', {cls:'pill', text:JSON.stringify(x.detail).slice(0,120)})]));
    });
    mount('evidence', host);
  } else { mount('evidence', empty('no evidence recorded yet')); }

  const si = await j('/api/search-intel');
  if(si){
    const modes = Object.entries(si.source_modes||{})
      .map(([k,v]) => `${k}: ${v}`).join('  ·  ') || 'none';
    const tiers = Object.entries(si.tier_breakdown||{})
      .map(([k,v]) => `${k}: ${v}`).join('  ·  ') || 'none';
    const niches = (si.archive_top_niches||[])
      .map(n => `${n.zone}/${n.interaction_style}/${n.response_movement} `
        + `(${n.best_score})`).join('  ·  ') || 'none';
    mount('search', h('div', null, [
      h('div', {cls:'line', text:
        `cells explored: ${si.cells_explored}/${si.cells_total}`}),
      h('div', {cls:'line', text:
        `ideas generated: ${si.ideas_total}  ·  dedup rate: ${(si.dedup_rate*100).toFixed(0)}%`}),
      h('div', {cls:'line pill', text:`mutation operators (source modes): ${modes}`}),
      h('div', {cls:'line pill', text:`judge tiers: ${tiers}`}),
      h('div', {cls:'line', text:
        `MAP-Elites archive: ${si.archive_niches_filled||0} niches filled  ·  `
        + `${si.archive_total_attempts||0} attempts archived`}),
      h('div', {cls:'line pill', text:`top niches: ${niches}`})]));
  }

  const cs = await j('/api/cost-stats');
  if(cs){
    const perCycle = (cs.tokens_per_cycle||[])
      .map(c => `c${c.cycle_id}: ${(c.tokens/1000).toFixed(0)}k`)
      .join('  ·  ') || 'none';
    const verdicts = Object.entries(cs.verdict_breakdown||{})
      .map(([k,v]) => `${k}: ${v}`).join('  ·  ') || 'none';
    mount('cost', h('div', null, [
      h('div', {cls:'line', text:
        `total tokens: ${cs.total_tokens.toLocaleString()}  ·  est. cost: $${cs.cost_estimate_usd.toFixed(2)}`}),
      h('div', {cls:'line pill', text:`per cycle: ${perCycle}`}),
      h('div', {cls:'line pill', text:
        `verdicts: ${verdicts}  ·  confirm rate: ${(cs.confirm_rate*100).toFixed(0)}%`})]));
  }
}
tick(); setInterval(tick, 5000);
</script>
</body></html>
"""


# ---------------------------------------------------------------------------
# App + server
# ---------------------------------------------------------------------------


def build_dashboard_app(db_path: str):
    from fastapi import FastAPI
    from fastapi.responses import HTMLResponse

    app = FastAPI(title="MonkeyClaw Dashboard")

    @app.get("/", response_class=HTMLResponse)
    def index() -> str:
        return _PAGE

    @app.get("/api/overview")
    def api_overview() -> dict[str, Any]:
        return _overview(db_path)

    @app.get("/api/zones")
    def api_zones() -> list[dict[str, Any]]:
        return _zones(db_path)

    @app.get("/api/finding-timeline")
    def api_finding_timeline() -> list[dict[str, Any]]:
        return _finding_timeline(db_path)

    @app.get("/api/repro-packages")
    def api_repro_packages() -> list[dict[str, Any]]:
        return _repro_packages(db_path)

    @app.get("/api/blue-team")
    def api_blue_team() -> dict[str, Any]:
        return _blue_team(db_path)

    @app.get("/api/evidence-timeline")
    def api_evidence_timeline() -> list[dict[str, Any]]:
        return _evidence_timeline(db_path)

    @app.get("/api/search-intel")
    def api_search_intel() -> dict[str, Any]:
        return _search_intel(db_path)

    @app.get("/api/cost-stats")
    def api_cost_stats() -> dict[str, Any]:
        return _cost_stats(db_path)

    return app


def serve(db_path: str = "data/monkeyclaw.db", port: int = 8787) -> None:
    import uvicorn

    print(f"MonkeyClaw dashboard — http://127.0.0.1:{port}  (db: {db_path})")
    uvicorn.run(build_dashboard_app(db_path), host="127.0.0.1", port=port,
                log_level="warning")
