"""Live web dashboard — the demo centerpiece.

A single dark-themed page plus a small JSON API, both served by FastAPI/uvicorn.
The page polls `/api/*` every 5 seconds and renders the attack-surface heatmap,
the findings list, the cycle feed, and headline stats. Everything is read
straight from the persistent SQLite knowledge base.

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


def _zones(db_path: str) -> list[dict[str, Any]]:
    return _query(
        db_path,
        "SELECT zone_id, name, coverage_score, vulns_open, vulns_found "
        "FROM surface_zones ORDER BY coverage_score ASC, zone_id",
    )


def _findings(db_path: str) -> list[dict[str, Any]]:
    return _query(
        db_path,
        "SELECT finding_id, zone_id, verdict, severity, failure_class, "
        "idea_summary, created_at FROM findings "
        "WHERE verdict IN ('confirmed', 'suspicious') "
        "ORDER BY CASE severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 "
        "WHEN 'medium' THEN 2 ELSE 3 END, created_at DESC",
    )


def _cycles(db_path: str) -> list[dict[str, Any]]:
    return _query(
        db_path,
        "SELECT cycle_id, summary, vulns_confirmed, vulns_suspicious, "
        "total_tokens_used, created_at FROM cycle_log "
        "ORDER BY cycle_id DESC LIMIT 25",
    )


def _status(db_path: str) -> dict[str, Any]:
    zones = _zones(db_path)
    findings = _findings(db_path)
    cycles = _cycles(db_path)
    tests = _query(
        db_path, "SELECT COUNT(*) AS n FROM regression_tests WHERE deprecated = 0"
    )
    tokens = sum(c.get("total_tokens_used") or 0 for c in cycles)
    return {
        "cycles": len(_query(db_path, "SELECT cycle_id FROM cycle_log")),
        "confirmed": sum(1 for f in findings if f["verdict"] == "confirmed"),
        "suspicious": sum(1 for f in findings if f["verdict"] == "suspicious"),
        "regression_tests": tests[0]["n"] if tests else 0,
        "coverage": (sum(z["coverage_score"] for z in zones) / len(zones))
        if zones else 0.0,
        "zone_count": len(zones),
        "tokens_used": tokens,
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
          --med:#ffd23f; --low:#5cc8ff; --ok:#3fb950; }
  * { box-sizing:border-box; margin:0; }
  body { background:var(--bg); color:var(--txt); font:15px/1.5 ui-monospace,
         "SF Mono",Menlo,Consolas,monospace; padding:22px 26px; }
  h1 { font-size:30px; letter-spacing:.5px; }
  h1 .sub { color:var(--dim); font-size:15px; font-weight:400; }
  h2 { font-size:13px; text-transform:uppercase; letter-spacing:1.5px;
       color:var(--dim); margin:0 0 10px; }
  .panel { background:var(--panel); border:1px solid var(--line);
           border-radius:10px; padding:18px; margin-top:18px; }
  .stats { display:flex; gap:14px; flex-wrap:wrap; }
  .stat { background:var(--panel); border:1px solid var(--line);
          border-radius:10px; padding:14px 22px; flex:1; min-width:150px; }
  .stat .v { font-size:38px; font-weight:700; color:var(--accent); }
  .stat .l { color:var(--dim); font-size:12px; text-transform:uppercase;
             letter-spacing:1px; }
  .grid { display:grid; grid-template-columns:repeat(auto-fill,minmax(168px,1fr));
          gap:10px; }
  .zone { border:1px solid var(--line); border-radius:8px; padding:11px 13px; }
  .zone .id { font-weight:700; font-size:14px; }
  .zone .meta { color:var(--dim); font-size:12px; margin-top:3px; }
  .bar { height:7px; border-radius:4px; background:#1c2530; margin-top:9px;
         overflow:hidden; }
  .bar > i { display:block; height:100%; }
  .cols { display:grid; grid-template-columns:1.3fr 1fr; gap:18px; }
  .find { border-left:4px solid var(--line); padding:9px 13px; margin-bottom:9px;
          background:#0e1218; border-radius:0 6px 6px 0; }
  .find .t { font-size:13px; }
  .find .m { color:var(--dim); font-size:12px; margin-top:3px; }
  .badge { display:inline-block; padding:1px 8px; border-radius:5px;
           font-size:11px; font-weight:700; text-transform:uppercase; }
  .cyc { border-bottom:1px solid var(--line); padding:8px 0; font-size:13px; }
  .cyc:last-child { border:0; }
  .empty { color:var(--dim); padding:14px 0; }
  #dot { color:var(--ok); }
</style></head><body>
<h1>MonkeyClaw <span class="sub">— autonomous NemoClaw red team &nbsp;<span id="dot">●</span> live</span></h1>

<div class="stats" id="stats"></div>

<div class="panel">
  <h2>Attack Surface — coverage heatmap</h2>
  <div class="grid" id="zones"></div>
</div>

<div class="cols">
  <div class="panel">
    <h2>Findings</h2>
    <div id="findings"></div>
  </div>
  <div class="panel">
    <h2>Cycle Feed</h2>
    <div id="cycles"></div>
  </div>
</div>

<script>
const SEV = {critical:"var(--crit)",high:"var(--high)",medium:"var(--med)",low:"var(--low)"};
function heat(c){ // coverage 0..1 -> red..green
  const h = Math.round(c*120); return `hsl(${h},70%,45%)`;
}
async function j(u){ try { return await (await fetch(u)).json(); } catch(e){ return null; } }
async function tick(){
  const s = await j('/api/status');
  if(s){
    document.getElementById('stats').innerHTML = [
      ['cycles',s.cycles],['confirmed vulns',s.confirmed],
      ['suspicious',s.suspicious],['coverage',(s.coverage*100).toFixed(0)+'%'],
      ['regression tests',s.regression_tests],['tokens',s.tokens_used.toLocaleString()],
    ].map(([l,v])=>`<div class="stat"><div class="v">${v}</div><div class="l">${l}</div></div>`).join('');
  }
  const z = await j('/api/zones') || [];
  document.getElementById('zones').innerHTML = z.length ? z.map(x=>`
    <div class="zone">
      <div class="id">${x.zone_id}</div>
      <div class="meta">${x.name} · open ${x.vulns_open} · found ${x.vulns_found}</div>
      <div class="bar"><i style="width:${Math.max(3,x.coverage_score*100)}%;
        background:${heat(x.coverage_score)}"></i></div>
    </div>`).join('') : '<div class="empty">no zones loaded</div>';
  const f = await j('/api/findings') || [];
  document.getElementById('findings').innerHTML = f.length ? f.map(x=>`
    <div class="find" style="border-left-color:${SEV[x.severity]||'var(--line)'}">
      <div class="t"><span class="badge" style="background:${SEV[x.severity]||'#333'};
        color:#000">${x.severity}</span> ${x.zone_id} · ${x.failure_class}
        <span style="color:var(--dim)">${x.verdict}</span></div>
      <div class="m">${(x.idea_summary||'').slice(0,150)}</div>
    </div>`).join('') : '<div class="empty">no findings yet</div>';
  const c = await j('/api/cycles') || [];
  document.getElementById('cycles').innerHTML = c.length ? c.map(x=>`
    <div class="cyc"><b>Cycle ${x.cycle_id}</b> &nbsp;
      <span style="color:var(--crit)">${x.vulns_confirmed}✓</span>
      <span style="color:var(--med)">${x.vulns_suspicious}?</span><br>
      <span style="color:var(--dim)">${(x.summary||'').slice(0,160)}</span></div>`).join('')
    : '<div class="empty">no cycles run yet</div>';
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

    @app.get("/api/status")
    def api_status() -> dict[str, Any]:
        return _status(db_path)

    @app.get("/api/zones")
    def api_zones() -> list[dict[str, Any]]:
        return _zones(db_path)

    @app.get("/api/findings")
    def api_findings() -> list[dict[str, Any]]:
        return _findings(db_path)

    @app.get("/api/cycles")
    def api_cycles() -> list[dict[str, Any]]:
        return _cycles(db_path)

    @app.get("/api/current")
    def api_current() -> dict[str, Any]:
        """Most recent cycle + the freshest findings — the 'live' view."""
        cycles = _cycles(db_path)
        findings = _findings(db_path)
        return {
            "latest_cycle": cycles[0] if cycles else None,
            "recent_findings": findings[:5],
        }

    return app


def serve(db_path: str = "data/monkeyclaw.db", port: int = 8787) -> None:
    import uvicorn

    print(f"MonkeyClaw dashboard — http://127.0.0.1:{port}  (db: {db_path})")
    uvicorn.run(build_dashboard_app(db_path), host="127.0.0.1", port=port,
                log_level="warning")
