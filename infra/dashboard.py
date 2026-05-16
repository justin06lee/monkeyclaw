"""Live web dashboard — the demo centerpiece.

A single dark-themed page plus a small JSON API, both served by FastAPI/uvicorn.
The page polls `/api/*` every few seconds and renders: a live "what it's doing
right now" banner, headline stats, the attack-surface heatmap, the
Nemotron-generated attack ideas, confirmed findings, a chronological activity
feed, and the cycle history. Everything is read straight from the persistent
SQLite knowledge base.

    monkeyclaw dashboard --port 8787
"""

from __future__ import annotations

import sqlite3
from pathlib import Path
from typing import Any


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


def _scalar(db_path: str, sql: str, params: tuple = ()) -> Any:
    rows = _query(db_path, sql, params)
    if not rows:
        return None
    return next(iter(rows[0].values()))


def _zones(db_path: str) -> list[dict[str, Any]]:
    return _query(
        db_path,
        "SELECT zone_id, name, coverage_score, vulns_open, vulns_found, "
        "unique_ideas_tried, last_tested_at "
        "FROM surface_zones ORDER BY coverage_score ASC, zone_id",
    )


def _findings(db_path: str) -> list[dict[str, Any]]:
    return _query(
        db_path,
        "SELECT finding_id, zone_id, verdict, severity, failure_class, "
        "tier_caught, idea_summary, created_at FROM findings "
        "WHERE verdict IN ('confirmed', 'suspicious') "
        "ORDER BY CASE severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 "
        "WHEN 'medium' THEN 2 ELSE 3 END, created_at DESC",
    )


def _cycles(db_path: str) -> list[dict[str, Any]]:
    return _query(
        db_path,
        "SELECT cycle_id, summary, ideas_generated, ideas_executed, "
        "vulns_confirmed, vulns_suspicious, total_tokens_used, "
        "wall_time_seconds, created_at FROM cycle_log "
        "ORDER BY cycle_id DESC LIMIT 25",
    )


def _ideas(db_path: str) -> list[dict[str, Any]]:
    return _query(
        db_path,
        "SELECT idea_id, cycle_id, zone_id, source_mode, title, approach, "
        "priority_score, deduplicated, created_at FROM ideas "
        "ORDER BY created_at DESC, priority_score DESC LIMIT 30",
    )


def _activity(db_path: str) -> list[dict[str, Any]]:
    return _query(
        db_path,
        "SELECT alert_id, message, severity, channel, delivered, created_at "
        "FROM alerts ORDER BY alert_id DESC LIMIT 40",
    )


def _status(db_path: str) -> dict[str, Any]:
    zones = _zones(db_path)
    findings = _findings(db_path)
    cycles = _cycles(db_path)
    tests = _scalar(
        db_path, "SELECT COUNT(*) AS n FROM regression_tests WHERE deprecated = 0") or 0
    ideas_total = _scalar(db_path, "SELECT COUNT(*) AS n FROM ideas") or 0
    repro_queued = _scalar(
        db_path, "SELECT COUNT(*) AS n FROM repro_queue WHERE status = 'queued'") or 0
    repro_active = _scalar(
        db_path, "SELECT COUNT(*) AS n FROM repro_queue WHERE status = 'processing'") or 0
    blue_queued = _scalar(
        db_path, "SELECT COUNT(*) AS n FROM repro_packages "
                 "WHERE ready_for_blue = 1 AND blue_team_status = 'queued'") or 0
    tokens = sum(c.get("total_tokens_used") or 0 for c in cycles)

    # "What it's doing now": cycle_log is written only when a cycle finishes,
    # so a higher max idea-cycle means a cycle is mid-flight.
    last_done = _scalar(db_path, "SELECT MAX(cycle_id) FROM cycle_log") or 0
    max_idea_cycle = _scalar(db_path, "SELECT MAX(cycle_id) FROM ideas") or 0
    current: dict[str, Any] | None = None
    if max_idea_cycle > last_done:
        cyc = max_idea_cycle
        current = {
            "cycle": cyc,
            "ideas": _scalar(db_path,
                             "SELECT COUNT(*) FROM ideas WHERE cycle_id = ?", (cyc,)) or 0,
            "lanes_judged": _scalar(db_path,
                                    "SELECT COUNT(*) FROM findings WHERE cycle_id = ?",
                                    (cyc,)) or 0,
            "zones": [r["zone_id"] for r in _query(
                db_path,
                "SELECT DISTINCT zone_id FROM ideas WHERE cycle_id = ?", (cyc,))],
        }

    return {
        "cycles": len(_query(db_path, "SELECT cycle_id FROM cycle_log")),
        "confirmed": sum(1 for f in findings if f["verdict"] == "confirmed"),
        "suspicious": sum(1 for f in findings if f["verdict"] == "suspicious"),
        "regression_tests": tests,
        "coverage": (sum(z["coverage_score"] for z in zones) / len(zones))
        if zones else 0.0,
        "zone_count": len(zones),
        "tokens_used": tokens,
        "ideas_generated": ideas_total,
        "repro_queued": repro_queued,
        "repro_active": repro_active,
        "blue_queued": blue_queued,
        "current": current,
    }


# ---------------------------------------------------------------------------
# The page
# ---------------------------------------------------------------------------


_PAGE = """<!doctype html>
<html lang="en"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>MonkeyClaw</title>
<style>
  :root { --bg:#0a0c10; --panel:#12161d; --line:#222a35; --txt:#e6edf3;
          --dim:#7d8a9c; --accent:#f5a623; --crit:#ff4d4d; --high:#ff8c42;
          --med:#ffd23f; --low:#5cc8ff; --ok:#3fb950;
          --creative:#c792ea; --code:#5cc8ff; --history:#3fb950; }
  * { box-sizing:border-box; margin:0; }
  body { background:var(--bg); color:var(--txt); font:14px/1.5 ui-monospace,
         "SF Mono",Menlo,Consolas,monospace; padding:20px 24px; }
  h1 { font-size:28px; letter-spacing:.5px; }
  h1 .sub { color:var(--dim); font-size:14px; font-weight:400; }
  h2 { font-size:12px; text-transform:uppercase; letter-spacing:1.5px;
       color:var(--dim); margin:0 0 10px; }
  .panel { background:var(--panel); border:1px solid var(--line);
           border-radius:10px; padding:16px; margin-top:16px; }
  /* live banner */
  #live { margin-top:12px; padding:12px 18px; border-radius:10px;
          border:1px solid var(--line); background:var(--panel);
          font-size:16px; display:flex; align-items:center; gap:12px; }
  #live .pulse { width:11px; height:11px; border-radius:50%; background:var(--ok);
                 box-shadow:0 0 0 0 var(--ok); animation:p 1.6s infinite; }
  #live.idle .pulse { background:var(--dim); animation:none; }
  @keyframes p { 0%{box-shadow:0 0 0 0 rgba(63,185,80,.6)}
                 70%{box-shadow:0 0 0 12px rgba(63,185,80,0)} 100%{box-shadow:0 0 0 0} }
  .stats { display:flex; gap:12px; flex-wrap:wrap; margin-top:14px; }
  .stat { background:var(--panel); border:1px solid var(--line);
          border-radius:10px; padding:12px 18px; flex:1; min-width:120px; }
  .stat .v { font-size:32px; font-weight:700; color:var(--accent); }
  .stat .l { color:var(--dim); font-size:11px; text-transform:uppercase;
             letter-spacing:1px; }
  .grid { display:grid; grid-template-columns:repeat(auto-fill,minmax(165px,1fr));
          gap:9px; }
  .zone { border:1px solid var(--line); border-radius:8px; padding:10px 12px; }
  .zone .id { font-weight:700; font-size:13px; }
  .zone .meta { color:var(--dim); font-size:11px; margin-top:3px; }
  .bar { height:7px; border-radius:4px; background:#1c2530; margin-top:8px;
         overflow:hidden; }
  .bar > i { display:block; height:100%; }
  .cols { display:grid; grid-template-columns:1fr 1fr; gap:16px; }
  .scroll { max-height:340px; overflow-y:auto; }
  .idea { border-left:3px solid var(--line); padding:8px 12px; margin-bottom:8px;
          background:#0e1218; border-radius:0 6px 6px 0; }
  .idea .t { font-size:13px; font-weight:600; }
  .idea .a { color:var(--dim); font-size:12px; margin-top:3px; }
  .find { border-left:4px solid var(--line); padding:8px 12px; margin-bottom:8px;
          background:#0e1218; border-radius:0 6px 6px 0; }
  .find .m { color:var(--dim); font-size:12px; margin-top:3px; }
  .badge { display:inline-block; padding:1px 7px; border-radius:5px;
           font-size:10px; font-weight:700; text-transform:uppercase; }
  .evt { padding:6px 0; border-bottom:1px solid var(--line); font-size:12px;
         display:flex; gap:8px; }
  .evt:last-child { border:0; }
  .evt .ts { color:var(--dim); white-space:nowrap; }
  .cyc { border-bottom:1px solid var(--line); padding:7px 0; font-size:12px; }
  .cyc:last-child { border:0; }
  .dedup { opacity:.5; }
  .empty { color:var(--dim); padding:12px 0; }
</style></head><body>
<h1>MonkeyClaw <span class="sub">— autonomous NemoClaw red team</span></h1>
<div id="live" class="idle"><span class="pulse"></span><span id="liveText">connecting…</span></div>

<div class="stats" id="stats"></div>

<div class="panel">
  <h2>Attack Surface — coverage heatmap</h2>
  <div class="grid" id="zones"></div>
</div>

<div class="cols">
  <div class="panel">
    <h2>Generated Attack Ideas — Nemotron</h2>
    <div class="scroll" id="ideas"></div>
  </div>
  <div class="panel">
    <h2>Activity Feed</h2>
    <div class="scroll" id="activity"></div>
  </div>
</div>

<div class="cols">
  <div class="panel">
    <h2>Findings</h2>
    <div class="scroll" id="findings"></div>
  </div>
  <div class="panel">
    <h2>Cycle History</h2>
    <div class="scroll" id="cycles"></div>
  </div>
</div>

<script>
const SEV = {critical:"var(--crit)",high:"var(--high)",medium:"var(--med)",
             low:"var(--low)",info:"var(--dim)"};
const MODE = {creative:"var(--creative)",code_grounded:"var(--code)",
              history_informed:"var(--history)"};
function heat(c){ return `hsl(${Math.round(c*120)},70%,45%)`; }
function ts(s){ return (s||"").replace("T"," ").slice(5,19); }
async function j(u){ try { return await (await fetch(u)).json(); } catch(e){ return null; } }

async function tick(){
  const s = await j('/api/status');
  if(s){
    const live = document.getElementById('live');
    if(s.current){
      live.className = "";
      document.getElementById('liveText').textContent =
        `Cycle ${s.current.cycle} in progress — ${s.current.ideas} ideas generated, `
        + `${s.current.lanes_judged} lane(s) judged · zones: `
        + (s.current.zones.join(", ") || "—");
    } else {
      live.className = "idle";
      document.getElementById('liveText').textContent =
        `idle — ${s.cycles} cycle(s) completed, waiting for the next`;
    }
    document.getElementById('stats').innerHTML = [
      ['cycles',s.cycles],['ideas generated',s.ideas_generated],
      ['confirmed',s.confirmed],['suspicious',s.suspicious],
      ['repro queue',s.repro_queued],['blue queue',s.blue_queued],
      ['coverage',(s.coverage*100).toFixed(0)+'%'],
      ['regression tests',s.regression_tests],
      ['tokens',(s.tokens_used||0).toLocaleString()],
    ].map(([l,v])=>`<div class="stat"><div class="v">${v}</div><div class="l">${l}</div></div>`).join('');
  }
  const z = await j('/api/zones') || [];
  document.getElementById('zones').innerHTML = z.length ? z.map(x=>`
    <div class="zone">
      <div class="id">${x.zone_id}</div>
      <div class="meta">${x.name} · ${x.unique_ideas_tried||0} ideas tried · `
        + `found ${x.vulns_found}</div>
      <div class="bar"><i style="width:${Math.max(3,x.coverage_score*100)}%;
        background:${heat(x.coverage_score)}"></i></div>
    </div>`).join('') : '<div class="empty">no zones</div>';
  const ideas = await j('/api/ideas') || [];
  document.getElementById('ideas').innerHTML = ideas.length ? ideas.map(x=>`
    <div class="idea ${x.deduplicated?'dedup':''}"
         style="border-left-color:${MODE[x.source_mode]||'var(--line)'}">
      <div class="t"><span class="badge" style="background:${MODE[x.source_mode]||'#333'};
        color:#000">${(x.source_mode||'').replace('_',' ')}</span>
        ${x.zone_id} · c${x.cycle_id} · p=${(x.priority_score||0).toFixed(2)}
        ${x.deduplicated?'· <span style="color:var(--dim)">duplicate</span>':''}</div>
      <div class="t" style="margin-top:4px">${x.title}</div>
      <div class="a">${(x.approach||'').slice(0,160)}</div>
    </div>`).join('') : '<div class="empty">no ideas generated yet</div>';
  const act = await j('/api/activity') || [];
  document.getElementById('activity').innerHTML = act.length ? act.map(x=>`
    <div class="evt">
      <span class="ts">${ts(x.created_at)}</span>
      <span><span class="badge" style="background:${SEV[x.severity]||'#333'};
        color:#000">${x.severity}</span> ${x.message}</span>
    </div>`).join('') : '<div class="empty">no activity yet</div>';
  const f = await j('/api/findings') || [];
  document.getElementById('findings').innerHTML = f.length ? f.map(x=>`
    <div class="find" style="border-left-color:${SEV[x.severity]||'var(--line)'}">
      <div><span class="badge" style="background:${SEV[x.severity]||'#333'};
        color:#000">${x.severity}</span> ${x.zone_id} · ${x.failure_class}
        <span style="color:var(--dim)">${x.verdict} / ${x.tier_caught}</span></div>
      <div class="m">${(x.idea_summary||'').slice(0,140)}</div>
    </div>`).join('') : '<div class="empty">no findings yet</div>';
  const c = await j('/api/cycles') || [];
  document.getElementById('cycles').innerHTML = c.length ? c.map(x=>`
    <div class="cyc"><b>Cycle ${x.cycle_id}</b>
      <span style="color:var(--crit)">${x.vulns_confirmed}✓</span>
      <span style="color:var(--med)">${x.vulns_suspicious}?</span>
      <span style="color:var(--dim)">· ${x.ideas_generated} ideas · `
      + `${Math.round(x.wall_time_seconds||0)}s</span><br>
      <span style="color:var(--dim)">${(x.summary||'').slice(0,150)}</span></div>`).join('')
    : '<div class="empty">no cycles completed yet</div>';
}
tick(); setInterval(tick, 4000);
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

    @app.get("/api/status")
    def api_status() -> dict[str, Any]:
        return _status(db_path)

    @app.get("/api/zones")
    def api_zones() -> list[dict[str, Any]]:
        return _zones(db_path)

    @app.get("/api/ideas")
    def api_ideas() -> list[dict[str, Any]]:
        return _ideas(db_path)

    @app.get("/api/activity")
    def api_activity() -> list[dict[str, Any]]:
        return _activity(db_path)

    @app.get("/api/findings")
    def api_findings() -> list[dict[str, Any]]:
        return _findings(db_path)

    @app.get("/api/cycles")
    def api_cycles() -> list[dict[str, Any]]:
        return _cycles(db_path)

    @app.get("/api/current")
    def api_current() -> dict[str, Any]:
        """Most recent cycle + the freshest ideas/findings — the 'live' view."""
        return {
            "status": _status(db_path),
            "latest_cycle": (_cycles(db_path) or [None])[0],
            "recent_ideas": _ideas(db_path)[:5],
            "recent_findings": _findings(db_path)[:5],
        }

    return app


def serve(db_path: str = "data/monkeyclaw.db", port: int = 8787) -> None:
    import uvicorn

    print(f"MonkeyClaw dashboard — http://127.0.0.1:{port}  (db: {db_path})")
    uvicorn.run(build_dashboard_app(db_path), host="127.0.0.1", port=port,
                log_level="warning")
