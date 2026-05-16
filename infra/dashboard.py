"""Live web dashboard — the demo centerpiece.

A single dark "mission-control" page plus a small JSON API, served by
FastAPI/uvicorn. The page polls `/api/all` every few seconds and lays the
run out as a red-to-blue narrative: a live status line and pipeline ribbon
up top (the project understood in 30 seconds), then the attack-surface
heatmap, findings, reproduction, blue team, search intelligence, the
evidence timeline, and model cost — each section with room to breathe.

Everything is read straight from the persistent SQLite knowledge base, so
the dashboard works against an empty DB and a live or pre-seeded one alike.

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
    """Confirmed/suspicious findings, joined to their repro + patch status so
    the timeline shows the whole red-to-blue lifecycle of each finding.

    Each finding also carries an `executed_path` HTML fragment (real-root-cause
    spec §9 finding-detail view) rendered from the latest `executed_paths` row.
    """
    findings = _query(
        db_path,
        "SELECT f.finding_id, f.zone_id, f.verdict, f.severity, "
        "f.failure_class, f.tier_caught, f.idea_summary, f.patch_status, "
        "f.created_at, q.status AS repro_status "
        "FROM findings f "
        "LEFT JOIN repro_queue q ON q.finding_id = f.finding_id "
        "WHERE f.verdict IN ('confirmed', 'suspicious') "
        "ORDER BY CASE f.severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 "
        "WHEN 'medium' THEN 2 ELSE 3 END, f.created_at DESC LIMIT 40",
    )
    for f in findings:
        f["executed_path"] = _render_executed_path_html(
            _query(
                db_path,
                "SELECT * FROM executed_paths WHERE finding_id = ? "
                "ORDER BY created_at DESC LIMIT 1",
                (f["finding_id"],),
            )
        )
    return findings


def _cycles(db_path: str) -> list[dict[str, Any]]:
    return _query(
        db_path,
        "SELECT cycle_id, summary, ideas_generated, ideas_executed, "
        "vulns_confirmed, vulns_suspicious, total_tokens_used, "
        "wall_time_seconds, created_at FROM cycle_log "
        "ORDER BY cycle_id DESC LIMIT 16",
    )


def _ideas(db_path: str) -> list[dict[str, Any]]:
    return _query(
        db_path,
        "SELECT idea_id, cycle_id, zone_id, source_mode, title, approach, "
        "priority_score, deduplicated, created_at FROM ideas "
        "ORDER BY created_at DESC, priority_score DESC LIMIT 24",
    )


def _activity(db_path: str) -> list[dict[str, Any]]:
    return _query(
        db_path,
        "SELECT alert_id, message, severity, channel, delivered, created_at "
        "FROM alerts ORDER BY alert_id DESC LIMIT 24",
    )


def _telemetry(db_path: str) -> list[dict[str, Any]]:
    """Evidence timeline — tool requests, file/network/process events, MCP
    calls, and approval decisions, newest first."""
    return _query(
        db_path,
        "SELECT event_type, actor, action_class, target, decision, "
        "reason_code, data_class, timestamp FROM telemetry_events "
        "ORDER BY event_id DESC LIMIT 36",
    )


def _judges(db_path: str) -> list[dict[str, Any]]:
    """Judge-ensemble vote summary, per role."""
    return _query(
        db_path,
        "SELECT judge_role, COUNT(*) AS votes, AVG(confidence) AS confidence, "
        "AVG(score) AS score, "
        "SUM(CASE WHEN verdict='confirmed' THEN 1 ELSE 0 END) AS confirmed, "
        "SUM(CASE WHEN verdict='suspicious' THEN 1 ELSE 0 END) AS suspicious, "
        "SUM(CASE WHEN verdict='clean' THEN 1 ELSE 0 END) AS clean "
        "FROM judge_votes GROUP BY judge_role ORDER BY votes DESC",
    )


def _repro_queue(db_path: str) -> list[dict[str, Any]]:
    return _query(
        db_path,
        "SELECT q.finding_id, q.priority, q.status, q.worker_id, q.enqueued_at, "
        "f.severity, f.failure_class, f.zone_id "
        "FROM repro_queue q LEFT JOIN findings f ON f.finding_id = q.finding_id "
        "ORDER BY CASE q.status WHEN 'processing' THEN 0 WHEN 'queued' THEN 1 "
        "ELSE 2 END, q.priority DESC, q.enqueued_at LIMIT 24",
    )


def _packages(db_path: str) -> list[dict[str, Any]]:
    """Repro packages ready for (or moving through) the blue team."""
    return _query(
        db_path,
        "SELECT package_id, vuln_id, title, severity, affected_zone, "
        "blue_team_status, cold_verified, repro_rate, created_at "
        "FROM repro_packages WHERE ready_for_blue = 1 "
        "ORDER BY CASE blue_team_status WHEN 'patching' THEN 0 "
        "WHEN 'triaged' THEN 1 WHEN 'queued' THEN 2 ELSE 3 END, "
        "created_at DESC LIMIT 24",
    )


def _patches(db_path: str) -> list[dict[str, Any]]:
    """Blue-team patch candidates."""
    return _query(
        db_path,
        "SELECT patch_id, zone_id, approach, invasiveness, status, created_at "
        "FROM patches ORDER BY created_at DESC LIMIT 20",
    )


def _regression(db_path: str) -> list[dict[str, Any]]:
    return _query(
        db_path,
        "SELECT test_id, vuln_id, zone_id, last_run_result, last_run_at, "
        "consecutive_passes, deprecated FROM regression_tests "
        "ORDER BY deprecated, last_run_at DESC LIMIT 40",
    )


def _model_usage(db_path: str) -> list[dict[str, Any]]:
    """Per-role LLM accounting — tokens, cost, latency, success rate."""
    return _query(
        db_path,
        "SELECT role, COUNT(*) AS runs, "
        "SUM(input_tokens + output_tokens) AS tokens, "
        "SUM(COALESCE(cost_usd, 0)) AS cost, AVG(latency_ms) AS latency, "
        "SUM(success) AS ok, GROUP_CONCAT(DISTINCT model) AS models "
        "FROM model_runs GROUP BY role ORDER BY tokens DESC",
    )


def _archive(db_path: str) -> list[dict[str, Any]]:
    """MAP-Elites quality-diversity grid cells."""
    return _query(
        db_path,
        "SELECT zone_id, interaction_style, response_movement, best_score, "
        "occupancy FROM idea_archive_cells "
        "ORDER BY best_score DESC, zone_id LIMIT 48",
    )


def _operators(db_path: str) -> list[dict[str, Any]]:
    return _query(
        db_path,
        "SELECT operator, uses, successes, avg_score FROM mutation_operator_stats "
        "ORDER BY successes DESC, uses DESC",
    )


def _status(db_path: str) -> dict[str, Any]:
    zones = _zones(db_path)
    findings = _findings(db_path)
    cycles = _cycles(db_path)
    tests = _query(
        db_path,
        "SELECT last_run_result FROM regression_tests WHERE deprecated = 0")
    reg_pass = sum(1 for t in tests
                   if "pass" in (t.get("last_run_result") or "").lower())
    ideas_total = _scalar(db_path, "SELECT COUNT(*) AS n FROM ideas") or 0
    repro_queued = _scalar(
        db_path, "SELECT COUNT(*) AS n FROM repro_queue WHERE status='queued'") or 0
    repro_active = _scalar(
        db_path,
        "SELECT COUNT(*) AS n FROM repro_queue WHERE status='processing'") or 0
    blue_queued = _scalar(
        db_path, "SELECT COUNT(*) AS n FROM repro_packages "
                 "WHERE ready_for_blue = 1 AND blue_team_status = 'queued'") or 0
    tokens = sum(c.get("total_tokens_used") or 0 for c in cycles)
    patches_total = _scalar(db_path, "SELECT COUNT(*) AS n FROM patches") or 0
    patches_verified = _scalar(
        db_path,
        "SELECT COUNT(*) AS n FROM patches WHERE status='approved'") or 0
    cost = _scalar(db_path, "SELECT SUM(COALESCE(cost_usd, 0)) FROM model_runs") or 0.0

    # "What it's doing now": cycle_log is written only when a cycle finishes,
    # so a higher max idea-cycle means a cycle is mid-flight.
    last_done = _scalar(db_path, "SELECT MAX(cycle_id) FROM cycle_log") or 0
    max_idea_cycle = _scalar(db_path, "SELECT MAX(cycle_id) FROM ideas") or 0
    current: dict[str, Any] | None = None
    if max_idea_cycle > last_done:
        cyc = max_idea_cycle
        current = {
            "cycle": cyc,
            "ideas": _scalar(
                db_path,
                "SELECT COUNT(*) FROM ideas WHERE cycle_id = ?", (cyc,)) or 0,
            "lanes_judged": _scalar(
                db_path, "SELECT COUNT(*) FROM findings WHERE cycle_id = ?",
                (cyc,)) or 0,
            "zones": [r["zone_id"] for r in _query(
                db_path,
                "SELECT DISTINCT zone_id FROM ideas WHERE cycle_id = ?", (cyc,))],
        }

    return {
        "cycles": len(_query(db_path, "SELECT cycle_id FROM cycle_log")),
        "confirmed": sum(1 for f in findings if f["verdict"] == "confirmed"),
        "suspicious": sum(1 for f in findings if f["verdict"] == "suspicious"),
        "regression_tests": len(tests),
        "regression_pass": reg_pass,
        "regression_rate": (reg_pass / len(tests)) if tests else 0.0,
        "coverage": (sum(z["coverage_score"] for z in zones) / len(zones))
        if zones else 0.0,
        "zone_count": len(zones),
        "tokens_used": tokens,
        "cost_usd": cost,
        "patches": patches_total,
        "patches_verified": patches_verified,
        "patches_open": max(0, patches_total - patches_verified),
        "ideas_generated": ideas_total,
        "repro_queued": repro_queued,
        "repro_active": repro_active,
        "blue_queued": blue_queued,
        "current": current,
    }


def _render_executed_path_html(rows: list) -> str:  # noqa: ANN001
    """Build the executed-path HTML fragment from executed_paths rows."""
    if not rows:
        return "<div class='exec-path empty'>No executed path traced.</div>"
    r = rows[0]
    badge = "degraded" if r["degraded"] else "traced"
    return (
        f"<div class='exec-path {badge}'>"
        f"<h4>Executed path — zone {r['zone_id']}</h4>"
        f"<p>backend: {r['backend']} · nodes: {r['node_count']} · "
        f"status: {badge}</p></div>"
    )


def render_executed_path(db, finding_id: str) -> str:  # noqa: ANN001
    """Render the executed path for one finding as an HTML fragment.

    Real-root-cause spec §9 finding-detail view. Takes a Database handle (the
    finding-detail consumer holds one). The SPA dashboard consumes the same
    fragment per finding via `_findings`, which calls `_render_executed_path_html`
    directly off its read-only connection.
    """
    rows = db.fetchall(
        "SELECT * FROM executed_paths WHERE finding_id = ? "
        "ORDER BY created_at DESC LIMIT 1", (finding_id,))
    return _render_executed_path_html(rows)


def _all(db_path: str) -> dict[str, Any]:
    """Single atomic snapshot — the page renders from one fetch."""
    return {
        "status": _status(db_path),
        "zones": _zones(db_path),
        "findings": _findings(db_path),
        "cycles": _cycles(db_path),
        "ideas": _ideas(db_path),
        "repro": _repro_queue(db_path),
        "packages": _packages(db_path),
        "patches": _patches(db_path),
        "regression": _regression(db_path),
        "models": _model_usage(db_path),
        "archive": _archive(db_path),
        "operators": _operators(db_path),
        "telemetry": _telemetry(db_path),
        "judges": _judges(db_path),
        "activity": _activity(db_path),
    }


# ---------------------------------------------------------------------------
# The page
# ---------------------------------------------------------------------------


_PAGE = r"""<!doctype html>
<html lang="en"><head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>MonkeyClaw — autonomous red-team console</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=IBM+Plex+Mono:wght@400;500;600;700&family=IBM+Plex+Sans:wght@400;500;600&display=swap" rel="stylesheet">
<style>
  :root{
    --bg:#0b0b0d; --bg-2:#0e0e12; --panel:#131318; --panel-2:#17171e;
    --line:#26262f; --line-2:#34343f;
    --txt:#ece9e4; --dim:#9a9aa6; --faint:#62626e;
    --accent:#f5a623; --accent-soft:#ffce7a;
    --crit:#ff5c5c; --high:#ff9f43; --med:#ffd23f; --low:#54b8ff; --ok:#36d399;
    --creative:#c792ea; --code_grounded:#54b8ff; --history_informed:#36d399;
    --playbook:#f5a623; --strategist:#ff9f43; --policy_corpus:#c792ea;
    --mono:'IBM Plex Mono',ui-monospace,'SF Mono',Menlo,Consolas,monospace;
    --sans:'IBM Plex Sans',-apple-system,system-ui,Segoe UI,sans-serif;
  }
  *{box-sizing:border-box;margin:0;padding:0;}
  html{scroll-behavior:smooth;}
  body{
    background:var(--bg); color:var(--txt);
    font:14px/1.6 var(--sans);
    -webkit-font-smoothing:antialiased;
    background-image:
      radial-gradient(900px 520px at 80% -8%, rgba(245,166,35,.10), transparent 70%),
      radial-gradient(700px 480px at 8% 4%, rgba(84,184,255,.05), transparent 70%);
    background-attachment:fixed;
  }
  /* faint dot grid for console depth */
  body::before{
    content:""; position:fixed; inset:0; z-index:0; pointer-events:none;
    background-image:radial-gradient(rgba(255,255,255,.022) 1px, transparent 1px);
    background-size:38px 38px;
  }
  .wrap{position:relative; z-index:1; max-width:1240px; margin:0 auto;
        padding:0 28px 90px;}
  a{color:inherit;}

  /* ---- header — just the mark, centered, blended into the page ---- */
  header{display:flex; justify-content:center; padding:60px 28px 24px;}
  header img{height:340px; width:auto; max-width:94%;
    filter:drop-shadow(0 0 56px rgba(245,166,35,.24));}
  @keyframes pulse{
    0%{box-shadow:0 0 0 0 rgba(54,211,147,.55);}
    70%{box-shadow:0 0 0 12px rgba(54,211,147,0);}
    100%{box-shadow:0 0 0 0 rgba(54,211,147,0);}
  }

  /* ---- sections ---- */
  section{margin-top:62px; opacity:0; transform:translateY(14px);
    animation:rise .6s cubic-bezier(.2,.7,.2,1) forwards;}
  section:nth-of-type(1){margin-top:40px;}
  section:nth-of-type(2){animation-delay:.06s;}
  section:nth-of-type(3){animation-delay:.12s;}
  section:nth-of-type(4){animation-delay:.18s;}
  section:nth-of-type(5){animation-delay:.24s;}
  section:nth-of-type(6){animation-delay:.30s;}
  section:nth-of-type(7){animation-delay:.36s;}
  section:nth-of-type(8){animation-delay:.42s;}
  @keyframes rise{to{opacity:1; transform:none;}}
  .kicker{font:600 11px/1 var(--mono); letter-spacing:.22em;
    text-transform:uppercase; color:var(--accent);}
  .kicker::before{content:"// ";color:var(--faint);}
  h2{font:600 25px/1.2 var(--mono); letter-spacing:-.01em; margin:11px 0 5px;}
  .desc{color:var(--dim); font-size:13px; max-width:62ch; margin-bottom:20px;}

  /* ---- live overview ---- */
  .live{
    display:flex; align-items:flex-start; gap:14px;
    border:1px solid var(--line); border-radius:12px;
    background:linear-gradient(100deg,var(--panel-2),var(--panel));
    padding:18px 22px; font:500 15px/1.5 var(--mono);
  }
  .live .dot{flex:none; width:13px; height:13px; border-radius:50%;
    margin-top:5px; background:var(--ok); box-shadow:0 0 0 0 var(--ok);
    animation:pulse 1.9s infinite;}
  .live.idle .dot{background:var(--faint); animation:none;}
  .live.idle{color:var(--dim);}
  .live .lt{flex:1; min-width:0;}
  .live b{color:var(--accent);}
  .live .zones{color:var(--dim); font-size:13px;}

  /* pipeline ribbon */
  .flow{display:flex; align-items:stretch; gap:0; margin-top:16px;
    flex-wrap:wrap;}
  .flow .node{
    flex:1; min-width:128px; border:1px solid var(--line);
    background:var(--panel); border-radius:12px; padding:16px 18px;
  }
  .flow .node .n{font:700 30px/1 var(--mono); color:var(--txt);}
  .flow .node .k{font-size:11px; letter-spacing:.13em; text-transform:uppercase;
    color:var(--dim); margin-top:7px;}
  .flow .node .s{font-size:11px; color:var(--faint); margin-top:3px;}
  .flow .arrow{display:flex; align-items:center; color:var(--faint);
    font:700 18px/1 var(--mono); padding:0 6px;}
  .flow .node.red{border-top:2px solid var(--high);}
  .flow .node.blue{border-top:2px solid var(--low);}
  .flow .node.win{border-top:2px solid var(--ok);}

  /* metric strip */
  .metrics{display:grid; gap:12px; margin-top:14px;
    grid-template-columns:repeat(auto-fit,minmax(160px,1fr));}
  .metric{border:1px solid var(--line); background:var(--panel);
    border-radius:12px; padding:16px 18px;}
  .metric .v{font:700 33px/1 var(--mono); color:var(--accent);}
  .metric .v small{font-size:15px; color:var(--dim); font-weight:500;}
  .metric .l{font-size:11px; letter-spacing:.1em; text-transform:uppercase;
    color:var(--dim); margin-top:8px;}
  .metric .sub{font-size:11px; color:var(--faint); margin-top:3px;}

  /* generic grids + cards */
  .cols{display:grid; grid-template-columns:1fr 1fr; gap:18px;}
  .cols-3{display:grid; grid-template-columns:1fr 1fr 1fr; gap:18px;}
  @media(max-width:860px){.cols,.cols-3{grid-template-columns:1fr;}}
  .card{border:1px solid var(--line); background:var(--panel);
    border-radius:12px; padding:18px;}
  .card > h3{font:600 12px/1 var(--mono); letter-spacing:.12em;
    text-transform:uppercase; color:var(--dim); margin-bottom:14px;}
  .scroll{max-height:392px; overflow-y:auto; margin-right:-6px;
    padding-right:6px;}
  .scroll::-webkit-scrollbar{width:7px;}
  .scroll::-webkit-scrollbar-thumb{background:var(--line-2); border-radius:4px;}
  .empty{color:var(--faint); font:400 13px/1.5 var(--mono);
    padding:22px 6px; text-align:center;}

  /* heatmap */
  .heat{display:grid; gap:9px;
    grid-template-columns:repeat(auto-fill,minmax(186px,1fr));}
  .zone{border:1px solid var(--line); border-radius:10px; padding:12px 13px;
    background:var(--panel); transition:border-color .2s,transform .2s;}
  .zone:hover{border-color:var(--line-2); transform:translateY(-2px);}
  .zone .top{display:flex; justify-content:space-between; align-items:baseline;}
  .zone .id{font:700 13px/1 var(--mono); letter-spacing:.02em;}
  .zone .pct{font:700 13px/1 var(--mono);}
  .zone .nm{color:var(--dim); font-size:11.5px; margin-top:3px;
    white-space:nowrap; overflow:hidden; text-overflow:ellipsis;}
  .bar{height:6px; border-radius:4px; background:#1d1d25; margin-top:9px;
    overflow:hidden;}
  .bar > i{display:block; height:100%; border-radius:4px;
    transition:width .6s cubic-bezier(.2,.7,.2,1);}
  .zone .ft{display:flex; justify-content:space-between; margin-top:8px;
    font-size:10.5px; color:var(--faint); letter-spacing:.02em;}

  /* list rows */
  .row{border-left:3px solid var(--line); background:var(--bg-2);
    border-radius:0 8px 8px 0; padding:11px 14px; margin-bottom:9px;}
  .row:last-child{margin-bottom:0;}
  .row .hd{display:flex; align-items:center; gap:8px; flex-wrap:wrap;}
  .row .ti{font:600 13px/1.4 var(--sans);}
  .row .mt{color:var(--dim); font-size:12px; margin-top:5px;
    font-family:var(--mono);}
  .row .ap{color:var(--faint); font-size:12px; margin-top:4px;}
  .badge{display:inline-flex; align-items:center; padding:2px 8px;
    border-radius:5px; font:700 10px/1.5 var(--mono); letter-spacing:.05em;
    text-transform:uppercase;}
  .chip{display:inline-flex; align-items:center; gap:5px; padding:2px 8px;
    border:1px solid var(--line-2); border-radius:5px;
    font:500 10.5px/1.6 var(--mono); color:var(--dim); letter-spacing:.03em;}
  .chip b{color:var(--txt); font-weight:600;}
  .mono{font-family:var(--mono);}
  .dim{color:var(--dim);} .faint{color:var(--faint);}
  .dedup{opacity:.45;}

  /* evidence timeline */
  .tl .ev{display:grid; grid-template-columns:84px 1fr; gap:12px;
    padding:8px 0; border-bottom:1px solid var(--line); font-size:12px;}
  .tl .ev:last-child{border-bottom:0;}
  .tl .ev .ts{color:var(--faint); font-family:var(--mono); font-size:11px;}
  .tl .ev .et{font-family:var(--mono); color:var(--txt);}
  .tl .ev .em{color:var(--dim); margin-top:2px;}

  /* judge bars */
  .judge{margin-bottom:13px;}
  .judge:last-child{margin-bottom:0;}
  .judge .jh{display:flex; justify-content:space-between; font-size:12px;
    font-family:var(--mono);}
  .judge .seg{display:flex; height:7px; border-radius:4px; overflow:hidden;
    margin-top:6px; background:#1d1d25;}
  .judge .seg > i{height:100%;}

  footer{margin-top:70px; padding-top:22px; border-top:1px solid var(--line);
    color:var(--faint); font:400 11px/1.6 var(--mono); letter-spacing:.04em;
    display:flex; justify-content:space-between; flex-wrap:wrap; gap:10px;}
</style></head><body>

<header><img src="/logo.png" alt="MonkeyClaw"></header>

<div class="wrap">

  <section>
    <div class="kicker">Overview</div>
    <h2>Run status</h2>
    <div class="desc">What the agent is doing right now, and the run reduced
      to one number per stage of the red-to-blue pipeline.</div>
    <div id="live" class="live idle"><span class="dot"></span>
      <div class="lt" id="liveText">connecting to the knowledge base…</div></div>
    <div class="flow" id="flow"></div>
    <div class="metrics" id="metrics"></div>
  </section>

  <section>
    <div class="kicker">Attack surface</div>
    <h2>Coverage heatmap</h2>
    <div class="desc">All 18 attack-surface zones. Greener means better tested;
      red zones are where the red team is still blind.</div>
    <div class="heat" id="zones"></div>
  </section>

  <section>
    <div class="kicker">Red team</div>
    <h2>Ideas &amp; findings</h2>
    <div class="desc">The freshest Nemotron-generated attack ideas on the left,
      and the confirmed / suspicious findings they produced on the right —
      each finding with its repro and patch status.</div>
    <div class="cols">
      <div class="card"><h3>Generated attack ideas</h3>
        <div class="scroll" id="ideas"></div></div>
      <div class="card"><h3>Finding timeline</h3>
        <div class="scroll" id="findings"></div></div>
    </div>
  </section>

  <section>
    <div class="kicker">Reproduction</div>
    <h2>Repro pipeline</h2>
    <div class="desc">Findings handed to the repro pipeline, and the minimal
      repro packages it has cold-verified and passed to the blue team.</div>
    <div class="cols">
      <div class="card"><h3>Repro queue</h3>
        <div class="scroll" id="repro"></div></div>
      <div class="card"><h3>Repro packages</h3>
        <div class="scroll" id="packages"></div></div>
    </div>
  </section>

  <section>
    <div class="kicker">Blue team</div>
    <h2>Patches &amp; regression</h2>
    <div class="desc">Candidate fixes generated for confirmed vulnerabilities,
      and the permanent regression suite guarding against their return.</div>
    <div class="cols">
      <div class="card"><h3>Patch candidates</h3>
        <div class="scroll" id="patches"></div></div>
      <div class="card"><h3>Regression suite</h3>
        <div class="scroll" id="regression"></div></div>
    </div>
  </section>

  <section>
    <div class="kicker">Search intelligence</div>
    <h2>How the search is learning</h2>
    <div class="desc">The MAP-Elites archive preserves diverse elite attacks;
      mutation operators and the judge ensemble show what is working.</div>
    <div class="cols-3">
      <div class="card"><h3>MAP-Elites archive</h3>
        <div class="scroll" id="archive"></div></div>
      <div class="card"><h3>Mutation operators</h3>
        <div class="scroll" id="operators"></div></div>
      <div class="card"><h3>Judge ensemble</h3>
        <div class="scroll" id="judges"></div></div>
    </div>
  </section>

  <section>
    <div class="kicker">Evidence</div>
    <h2>Telemetry timeline</h2>
    <div class="desc">Tool requests, file / network / process events, MCP calls
      and approval decisions — the recorded evidence trail.</div>
    <div class="cols">
      <div class="card"><h3>Evidence timeline</h3>
        <div class="scroll tl" id="telemetry"></div></div>
      <div class="card"><h3>Cycle history</h3>
        <div class="scroll" id="cycles"></div></div>
    </div>
  </section>

  <section>
    <div class="kicker">Cost</div>
    <h2>Model usage</h2>
    <div class="desc">Token spend, latency and success rate for every model
      role driving the run.</div>
    <div class="card"><div id="models" class="heat"></div></div>
  </section>

  <footer>
    <span>MonkeyClaw — autonomous security hardening for NemoClaw / OpenClaw</span>
    <span id="stamp">live · polling every 5s</span>
  </footer>
</div>

<script>
const SEV={critical:"var(--crit)",high:"var(--high)",medium:"var(--med)",
  low:"var(--low)",info:"var(--dim)"};
const MODE={creative:"var(--creative)",code_grounded:"var(--code_grounded)",
  history_informed:"var(--history_informed)",playbook:"var(--playbook)",
  strategist:"var(--strategist)",policy_corpus:"var(--policy_corpus)"};
const STATUS_C={confirmed:"var(--crit)",processing:"var(--low)",
  patching:"var(--low)",queued:"var(--med)",triaged:"var(--accent)",
  approved:"var(--ok)",verified:"var(--ok)",patched:"var(--ok)",
  rejected:"var(--faint)",failed:"var(--crit)",completed:"var(--ok)"};

function heat(c){return `hsl(${Math.round(Math.max(0,Math.min(1,c))*125)},68%,46%)`;}
function ts(s){return (s||"").replace("T"," ").slice(5,19);}
function esc(s){return (s||"").replace(/[&<>]/g,c=>(
  {"&":"&amp;","<":"&lt;",">":"&gt;"}[c]));}
function trunc(s,n){s=esc(s);return s.length>n?s.slice(0,n)+"…":s;}
function num(n){return (n||0).toLocaleString();}
function badge(txt,col){return `<span class="badge" style="background:${col};`
  +`color:#0b0b0d">${esc(txt)}</span>`;}
function set(id,html){const el=document.getElementById(id);if(el)el.innerHTML=html;}
async function j(u){try{return await (await fetch(u)).json();}catch(e){return null;}}

function renderLive(s){
  const live=document.getElementById('live');
  const lt=document.getElementById('liveText');
  if(s && s.current){
    live.className="live";
    lt.innerHTML=`<b>Cycle ${s.current.cycle} running.</b> `
      +`${s.current.ideas} ideas generated · ${s.current.lanes_judged} lane(s) `
      +`judged.<div class="zones">targeting: `
      +`${esc((s.current.zones||[]).join(" · "))||"—"}</div>`;
  }else{
    live.className="live idle";
    lt.textContent= s && s.cycles
      ? `Idle — ${s.cycles} cycle(s) complete. Waiting for the next cycle.`
      : `Idle — no cycles yet. The orchestrator has not run.`;
  }
}

function renderFlow(s){
  if(!s){set('flow','');return;}
  const findings=(s.confirmed||0)+(s.suspicious||0);
  const nodes=[
    ["red",s.ideas_generated,"Ideas","generated"],
    ["red",findings,"Findings",`${s.confirmed||0} confirmed`],
    ["red",(s.repro_queued||0)+(s.repro_active||0),"In repro",
      `${s.repro_active||0} active`],
    ["blue",s.patches||0,"Patches",`${s.patches_open||0} open`],
    ["win",s.patches_verified||0,"Verified","fixes approved"],
  ];
  set('flow',nodes.map((n,i)=>
    `<div class="node ${n[0]}"><div class="n">${num(n[1])}</div>`
    +`<div class="k">${n[2]}</div><div class="s">${esc(n[3])}</div></div>`
    +(i<nodes.length-1?'<div class="arrow">→</div>':'')).join(''));
}

function renderMetrics(s){
  if(!s){set('metrics','');return;}
  const cov=Math.round((s.coverage||0)*100);
  const reg=Math.round((s.regression_rate||0)*100);
  const m=[
    [s.cycles||0,"Cycles completed",""],
    [`${s.confirmed||0}`,"Confirmed findings",`${s.suspicious||0} suspicious`],
    [`${s.patches_verified||0}<small> / ${s.patches||0}</small>`,
      "Patches verified",`${s.patches_open||0} still open`],
    [`${reg}<small>%</small>`,"Regression pass rate",
      `${s.regression_pass||0} / ${s.regression_tests||0} tests`],
    [`${cov}<small>%</small>`,"Mean zone coverage",`${s.zone_count||0} zones`],
    [`$${(s.cost_usd||0).toFixed(2)}`,"Model cost",
      `${num(s.tokens_used)} tokens`],
  ];
  set('metrics',m.map(x=>
    `<div class="metric"><div class="v">${x[0]}</div>`
    +`<div class="l">${x[1]}</div>`
    +(x[2]?`<div class="sub">${esc(x[2])}</div>`:'')+`</div>`).join(''));
}

function renderZones(z){
  if(!z||!z.length){set('zones','<div class="empty">no zones loaded</div>');return;}
  set('zones',z.map(x=>{
    const c=x.coverage_score||0, col=heat(c);
    return `<div class="zone">
      <div class="top"><span class="id">${esc(x.zone_id)}</span>
        <span class="pct" style="color:${col}">${Math.round(c*100)}%</span></div>
      <div class="nm">${esc(x.name||'')}</div>
      <div class="bar"><i style="width:${Math.max(3,c*100)}%;`
        +`background:${col}"></i></div>
      <div class="ft"><span>${x.vulns_open||0} open · `
        +`${x.unique_ideas_tried||0} ideas</span>`
      +`<span>${x.last_tested_at?ts(x.last_tested_at):'never tested'}</span></div>
    </div>`;}).join(''));
}

function renderFindings(f){
  if(!f||!f.length){set('findings',
    '<div class="empty">no findings yet — the red team has not confirmed a '
    +'vulnerability</div>');return;}
  set('findings',f.map(x=>{
    const col=SEV[x.severity]||"var(--line)";
    const repro=x.repro_status?`<span class="chip">repro `
      +`<b style="color:${STATUS_C[x.repro_status]||'var(--dim)'}">`
      +`${esc(x.repro_status)}</b></span>`:'';
    const patch=`<span class="chip">patch <b style="color:`
      +`${STATUS_C[x.patch_status]||'var(--faint)'}">`
      +`${esc(x.patch_status||'open')}</b></span>`;
    return `<div class="row" style="border-left-color:${col}">
      <div class="hd">${badge(x.severity,col)}
        <span class="ti">${esc(x.zone_id)} · ${esc(x.failure_class)}</span></div>
      <div class="ap">${trunc(x.idea_summary,148)}</div>
      <div class="hd" style="margin-top:7px">
        <span class="chip">${esc(x.verdict)} · ${esc(x.tier_caught)}</span>
        ${repro}${patch}</div>
    </div>`;}).join(''));
}

function renderIdeas(items){
  if(!items||!items.length){set('ideas',
    '<div class="empty">no ideas generated yet</div>');return;}
  set('ideas',items.map(x=>{
    const col=MODE[x.source_mode]||"var(--line)";
    return `<div class="row ${x.deduplicated?'dedup':''}" `
      +`style="border-left-color:${col}">
      <div class="hd">${badge((x.source_mode||'').replace(/_/g,' '),col)}
        <span class="dim mono" style="font-size:11px">${esc(x.zone_id)} · `
        +`c${x.cycle_id} · p=${(x.priority_score||0).toFixed(2)}`
        +`${x.deduplicated?' · duplicate':''}</span></div>
      <div class="ti" style="margin-top:5px">${trunc(x.title,80)}</div>
      <div class="ap">${trunc(x.approach,130)}</div>
    </div>`;}).join(''));
}

function renderRepro(r){
  if(!r||!r.length){set('repro',
    '<div class="empty">repro queue empty</div>');return;}
  set('repro',r.map(x=>{
    const col=SEV[x.severity]||"var(--line)";
    return `<div class="row" style="border-left-color:${col}">
      <div class="hd">${badge(x.status,STATUS_C[x.status]||'var(--dim)')}
        <span class="ti mono" style="font-size:12px">${esc(x.finding_id)}</span>
        <span class="chip">${esc(x.priority||'')} priority</span></div>
      <div class="mt">${esc(x.zone_id||'—')} · ${esc(x.failure_class||'')} · `
        +`${x.worker_id?('worker '+esc(x.worker_id)):'unassigned'}</div>
    </div>`;}).join(''));
}

function renderPackages(p){
  if(!p||!p.length){set('packages',
    '<div class="empty">no repro packages ready for blue team</div>');return;}
  set('packages',p.map(x=>{
    const col=SEV[x.severity]||"var(--line)";
    return `<div class="row" style="border-left-color:${col}">
      <div class="hd">${badge(x.blue_team_status,
        STATUS_C[x.blue_team_status]||'var(--dim)')}
        <span class="ti mono" style="font-size:12px">${esc(x.vuln_id)}</span></div>
      <div class="ap">${trunc(x.title,120)}</div>
      <div class="hd" style="margin-top:7px">
        <span class="chip">${esc(x.affected_zone||'—')}</span>
        <span class="chip">repro <b>${Math.round((x.repro_rate||0)*100)}%</b></span>
        <span class="chip">${x.cold_verified
          ?'<b style="color:var(--ok)">cold-verified</b>':'unverified'}</span>
      </div></div>`;}).join(''));
}

function renderPatches(p){
  if(!p||!p.length){set('patches',
    '<div class="empty">no patch candidates yet</div>');return;}
  set('patches',p.map(x=>{
    const col=STATUS_C[x.status]||"var(--line)";
    return `<div class="row" style="border-left-color:${col}">
      <div class="hd">${badge(x.status,col)}
        <span class="ti mono" style="font-size:12px">${esc(x.zone_id)}</span>
        <span class="chip">${esc(x.invasiveness||'')} invasiveness</span></div>
      <div class="ap">${trunc(x.approach,138)}</div>
    </div>`;}).join(''));
}

function renderRegression(rg){
  if(!rg||!rg.length){set('regression',
    '<div class="empty">no regression tests yet</div>');return;}
  const active=rg.filter(x=>!x.deprecated);
  const pass=active.filter(x=>/pass/i.test(x.last_run_result||'')).length;
  const rate=active.length?Math.round(pass/active.length*100):0;
  const head=`<div class="row" style="border-left-color:var(--ok)">
    <div class="hd"><span class="ti">${pass} / ${active.length} passing</span>
    <span class="chip">${rate}% suite pass rate</span></div></div>`;
  set('regression',head+rg.map(x=>{
    const ok=/pass/i.test(x.last_run_result||'');
    const col=ok?"var(--ok)":(x.last_run_result?"var(--crit)":"var(--line)");
    return `<div class="row ${x.deprecated?'dedup':''}" `
      +`style="border-left-color:${col}">
      <div class="hd">${badge(x.last_run_result||'not run',col)}
        <span class="ti mono" style="font-size:12px">${esc(x.zone_id)}</span>
        <span class="chip">${x.consecutive_passes||0}× consecutive</span>
        ${x.deprecated?'<span class="chip">deprecated</span>':''}</div>
      <div class="mt">${esc(x.test_id)} · ${esc(x.vuln_id||'')}</div>
    </div>`;}).join(''));
}

function renderArchive(a){
  if(!a||!a.length){set('archive',
    '<div class="empty">MAP-Elites grid not yet populated</div>');return;}
  set('archive',a.map(x=>{
    const sc=x.best_score||0, col=heat(Math.min(1,sc/12));
    return `<div class="row" style="border-left-color:${col}">
      <div class="hd"><span class="ti mono" style="font-size:12px">`
        +`${esc(x.zone_id)}</span></div>
      <div class="mt">${esc(x.interaction_style)} / `
        +`${esc(x.response_movement)}</div>
      <div class="hd" style="margin-top:6px">
        <span class="chip">elite <b>${sc.toFixed(2)}</b></span>
        <span class="chip">occ ${x.occupancy||0}</span></div>
    </div>`;}).join(''));
}

function renderOperators(o){
  if(!o||!o.length){set('operators',
    '<div class="empty">no mutation-operator stats yet</div>');return;}
  set('operators',o.map(x=>{
    const r=x.uses?x.successes/x.uses:0;
    return `<div style="margin-bottom:13px">
      <div class="jh"><span>${esc(x.operator)}</span>
        <span class="dim">${x.successes||0}/${x.uses||0} · `
        +`${Math.round(r*100)}%</span></div>
      <div class="bar" style="margin-top:6px"><i style="width:`
        +`${Math.max(3,r*100)}%;background:${heat(r)}"></i></div>
    </div>`;}).join(''));
}

function renderJudges(jd){
  if(!jd||!jd.length){set('judges',
    '<div class="empty">no judge votes yet</div>');return;}
  set('judges',jd.map(x=>{
    const tot=(x.confirmed||0)+(x.suspicious||0)+(x.clean||0)||1;
    const seg=(n,c)=>n?`<i style="width:${n/tot*100}%;background:${c}"></i>`:'';
    return `<div class="judge">
      <div class="jh"><span>${esc(x.judge_role)}</span>
        <span class="dim">${x.votes||0} votes · `
        +`conf ${((x.confidence||0)).toFixed(2)}</span></div>
      <div class="seg">${seg(x.confirmed,'var(--crit)')}`
        +`${seg(x.suspicious,'var(--med)')}${seg(x.clean,'var(--ok)')}</div>
    </div>`;}).join(''));
}

function renderTelemetry(t){
  if(!t||!t.length){set('telemetry',
    '<div class="empty">no telemetry events recorded yet</div>');return;}
  const DC={deny:"var(--crit)",ask:"var(--med)",allow:"var(--ok)"};
  set('telemetry',t.map(x=>{
    const dec=x.decision?`<span style="color:${DC[x.decision]||'var(--dim)'}">`
      +`${esc(x.decision)}</span>`:'';
    return `<div class="ev"><span class="ts">${ts(x.timestamp)}</span>
      <div><div class="et">${esc(x.event_type)} ${dec}</div>
      <div class="em">${esc(x.actor||'')}`
      +`${x.target?(' → '+trunc(x.target,52)):''}`
      +`${x.reason_code?(' · '+esc(x.reason_code)):''}</div></div></div>`;
  }).join(''));
}

function renderCycles(c){
  if(!c||!c.length){set('cycles',
    '<div class="empty">no cycles completed yet</div>');return;}
  set('cycles',c.map(x=>
    `<div class="row" style="border-left-color:var(--accent)">
      <div class="hd"><span class="ti">Cycle ${x.cycle_id}</span>
        <span class="chip"><b style="color:var(--crit)">`
        +`${x.vulns_confirmed||0}</b> confirmed</span>
        <span class="chip"><b style="color:var(--med)">`
        +`${x.vulns_suspicious||0}</b> suspicious</span>
        <span class="chip">${x.ideas_generated||0} ideas</span>
        <span class="chip">${Math.round(x.wall_time_seconds||0)}s</span></div>
      <div class="ap">${trunc(x.summary,150)}</div></div>`).join(''));
}

function renderModels(m){
  if(!m||!m.length){set('models',
    '<div class="empty">no model runs recorded yet</div>');return;}
  set('models',m.map(x=>{
    const r=x.runs?x.ok/x.runs:0;
    return `<div class="zone">
      <div class="top"><span class="id">${esc(x.role)}</span>
        <span class="pct" style="color:${heat(r)}">`
        +`${Math.round(r*100)}%</span></div>
      <div class="nm">${esc((x.models||'').split(',')[0]||'')}</div>
      <div class="bar"><i style="width:${Math.max(3,r*100)}%;`
        +`background:${heat(r)}"></i></div>
      <div class="ft"><span>${num(x.tokens)} tok · `
        +`$${(x.cost||0).toFixed(2)}</span>`
      +`<span>${x.runs||0} runs · ${Math.round(x.latency||0)}ms</span></div>
    </div>`;}).join(''));
}

async function tick(){
  const d=await j('/api/all');
  if(!d){document.getElementById('liveText').textContent=
    "no data — knowledge base unreachable";return;}
  renderLive(d.status); renderFlow(d.status); renderMetrics(d.status);
  renderZones(d.zones); renderFindings(d.findings); renderIdeas(d.ideas);
  renderRepro(d.repro); renderPackages(d.packages); renderPatches(d.patches);
  renderRegression(d.regression); renderArchive(d.archive);
  renderOperators(d.operators); renderJudges(d.judges);
  renderTelemetry(d.telemetry); renderCycles(d.cycles);
  renderModels(d.models);
  document.getElementById('stamp').textContent=
    'live · updated '+new Date().toLocaleTimeString();
}
tick(); setInterval(tick,5000);
</script>
</body></html>
"""


# ---------------------------------------------------------------------------
# App + server
# ---------------------------------------------------------------------------


_LOGO_PATH = Path(__file__).resolve().parent.parent / "assets" / "monkeyclaw-dark.png"


def build_dashboard_app(db_path: str):
    from fastapi import FastAPI
    from fastapi.responses import FileResponse, HTMLResponse, Response

    app = FastAPI(title="MonkeyClaw Dashboard")

    @app.get("/", response_class=HTMLResponse)
    def index() -> str:
        return _PAGE

    @app.get("/logo.png")
    def logo() -> Response:
        if _LOGO_PATH.exists():
            return FileResponse(_LOGO_PATH, media_type="image/png")
        return Response(status_code=404)

    @app.get("/api/all")
    def api_all() -> dict[str, Any]:
        """One atomic snapshot — the page renders everything from this."""
        return _all(db_path)

    # Individual endpoints retained for ad-hoc queries / backward compatibility.
    @app.get("/api/status")
    def api_status() -> dict[str, Any]:
        return _status(db_path)

    @app.get("/api/zones")
    def api_zones() -> list[dict[str, Any]]:
        return _zones(db_path)

    @app.get("/api/ideas")
    def api_ideas() -> list[dict[str, Any]]:
        return _ideas(db_path)

    @app.get("/api/findings")
    def api_findings() -> list[dict[str, Any]]:
        return _findings(db_path)

    @app.get("/api/cycles")
    def api_cycles() -> list[dict[str, Any]]:
        return _cycles(db_path)

    @app.get("/api/repro")
    def api_repro() -> list[dict[str, Any]]:
        return _repro_queue(db_path)

    @app.get("/api/packages")
    def api_packages() -> list[dict[str, Any]]:
        return _packages(db_path)

    @app.get("/api/patches")
    def api_patches() -> list[dict[str, Any]]:
        return _patches(db_path)

    @app.get("/api/regression")
    def api_regression() -> list[dict[str, Any]]:
        return _regression(db_path)

    @app.get("/api/models")
    def api_models() -> list[dict[str, Any]]:
        return _model_usage(db_path)

    @app.get("/api/archive")
    def api_archive() -> list[dict[str, Any]]:
        return _archive(db_path)

    @app.get("/api/operators")
    def api_operators() -> list[dict[str, Any]]:
        return _operators(db_path)

    @app.get("/api/judges")
    def api_judges() -> list[dict[str, Any]]:
        return _judges(db_path)

    @app.get("/api/telemetry")
    def api_telemetry() -> list[dict[str, Any]]:
        return _telemetry(db_path)

    @app.get("/api/activity")
    def api_activity() -> list[dict[str, Any]]:
        return _activity(db_path)

    return app


def serve(db_path: str = "data/monkeyclaw.db", port: int = 8787) -> None:
    import uvicorn

    print(f"MonkeyClaw dashboard — http://127.0.0.1:{port}  (db: {db_path})")
    uvicorn.run(build_dashboard_app(db_path), host="127.0.0.1", port=port,
                log_level="warning")
