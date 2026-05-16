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
    the timeline shows the whole red-to-blue lifecycle of each finding."""
    return _query(
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
        "ELSE 2 END, CASE q.priority WHEN 'high' THEN 0 ELSE 1 END, "
        "q.enqueued_at LIMIT 24",
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


def _agent_events(db_path: str) -> list[dict[str, Any]]:
    """Recent LLM prompts/responses, lane messages, and tool events."""
    return _query(
        db_path,
        "SELECT event_id, session_id, agent_id, agent_kind, event_type, role, "
        "cycle_id, lane_id, idea_id, model, provider, text, tool_name, status, "
        "metadata, created_at FROM agent_events "
        "ORDER BY created_at DESC, event_id DESC LIMIT 160",
    )


def _agent_tool_events(db_path: str) -> list[dict[str, Any]]:
    """Tool-like telemetry not already captured in agent_events."""
    return _query(
        db_path,
        "SELECT event_id, session_id, event_type, actor, action_class, target, "
        "decision, reason_code, excerpt, metadata, timestamp AS created_at "
        "FROM telemetry_events "
        "WHERE event_type IN ('agent.tool.requested', 'agent.tool.decision', "
        "'agent.shell.started', 'agent.shell.finished', 'agent.network.request', "
        "'agent.mcp.invoked', 'agent.file.read', 'agent.file.write') "
        "ORDER BY timestamp DESC, event_id DESC LIMIT 80",
    )


def _agents(db_path: str) -> dict[str, Any]:
    events = _agent_events(db_path)
    tools = _agent_tool_events(db_path)
    grouped: dict[str, dict[str, Any]] = {}
    for ev in events:
        aid = ev.get("agent_id") or ev.get("session_id") or "unknown"
        g = grouped.setdefault(aid, {
            "agent_id": aid,
            "agent_kind": ev.get("agent_kind"),
            "session_id": ev.get("session_id"),
            "latest_at": ev.get("created_at"),
            "model": ev.get("model"),
            "provider": ev.get("provider"),
            "llm_calls": 0,
            "messages": 0,
            "tool_events": 0,
            "last_text": "",
            "last_event": ev.get("event_type"),
        })
        if (ev.get("created_at") or "") > (g.get("latest_at") or ""):
            g["latest_at"] = ev.get("created_at")
            g["last_event"] = ev.get("event_type")
        if ev.get("model") and not g.get("model"):
            g["model"] = ev.get("model")
        if ev.get("provider") and not g.get("provider"):
            g["provider"] = ev.get("provider")
        et = ev.get("event_type") or ""
        if et == "llm.response":
            g["llm_calls"] += 1
        if et.endswith(".message"):
            g["messages"] += 1
        if et == "tool.event":
            g["tool_events"] += 1
        if ev.get("text") and not g.get("last_text"):
            g["last_text"] = ev.get("text")
    return {
        "summary": sorted(
            grouped.values(),
            key=lambda x: x.get("latest_at") or "",
            reverse=True,
        )[:24],
        "events": events,
        "tools": tools,
    }


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


def _status(
    db_path: str,
    zones: list[dict[str, Any]] | None = None,
    findings: list[dict[str, Any]] | None = None,
    cycles: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    # Accept precomputed lists so /api/all does not run these queries twice.
    if zones is None:
        zones = _zones(db_path)
    if findings is None:
        findings = _findings(db_path)
    if cycles is None:
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
    tokens = _scalar(
        db_path,
        "SELECT SUM(COALESCE(total_tokens_used, 0)) FROM cycle_log") or 0
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
        "cycles": _scalar(db_path, "SELECT COUNT(*) FROM cycle_log") or 0,
        "confirmed": _scalar(
            db_path,
            "SELECT COUNT(*) FROM findings WHERE verdict = ?",
            ("confirmed",)) or 0,
        "suspicious": _scalar(
            db_path,
            "SELECT COUNT(*) FROM findings WHERE verdict = ?",
            ("suspicious",)) or 0,
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


def _all(db_path: str) -> dict[str, Any]:
    """Single atomic snapshot — the page renders from one fetch."""
    zones = _zones(db_path)
    findings = _findings(db_path)
    cycles = _cycles(db_path)
    return {
        "status": _status(db_path, zones=zones, findings=findings, cycles=cycles),
        "zones": zones,
        "findings": findings,
        "cycles": cycles,
        "ideas": _ideas(db_path),
        "repro": _repro_queue(db_path),
        "packages": _packages(db_path),
        "patches": _patches(db_path),
        "regression": _regression(db_path),
        "models": _model_usage(db_path),
        "agents": _agents(db_path),
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

  /* ---- live agents — conversation & tool stream ---- */
  .agentgrid{display:grid; grid-template-columns:minmax(178px,.6fr) 2fr;
    gap:18px;}
  @media(max-width:960px){.agentgrid{grid-template-columns:1fr;}}

  /* agent rail — click a card to follow one agent's thread */
  .agentrail{display:flex; flex-direction:column; gap:7px;}
  .arow{border:1px solid var(--line); background:var(--bg-2); border-radius:9px;
    padding:10px 12px; cursor:pointer;
    transition:border-color .15s,background .15s,transform .15s;}
  .arow:hover{border-color:var(--line-2); transform:translateX(2px);}
  .arow.sel{border-color:var(--accent);
    background:linear-gradient(100deg,var(--panel-2),var(--panel));}
  .arow.all{border-style:dashed; background:transparent;}
  .arow .anm{font:700 12px/1.35 var(--mono); color:var(--txt);
    display:flex; align-items:center; gap:7px;}
  .arow .adot{flex:none; width:7px; height:7px; border-radius:50%;
    background:var(--accent);}
  .arow.sel .adot{box-shadow:0 0 0 0 var(--accent);
    animation:pulse 1.9s infinite;}
  .arow .ak{font-size:10.5px; color:var(--dim); margin-top:4px;
    white-space:nowrap; overflow:hidden; text-overflow:ellipsis;}
  .arow .amini{margin-top:8px; display:flex; gap:5px; flex-wrap:wrap;}
  .ministat{display:inline-flex; align-items:center; gap:4px; padding:2px 6px;
    border:1px solid var(--line-2); border-radius:5px;
    font:600 10px/1.5 var(--mono); color:var(--dim);}
  .ministat b{color:var(--txt);}

  /* stream header */
  .streamhd{display:flex; align-items:baseline; justify-content:space-between;
    gap:10px; margin-bottom:6px;}
  .streamhd h3{margin:0; font:600 12px/1 var(--mono); letter-spacing:.12em;
    text-transform:uppercase; color:var(--dim);}
  .streamfilter{font:700 10px/1 var(--mono); letter-spacing:.04em;
    color:var(--accent);}

  /* the transcript — text renders like an article, not bubbles */
  .stream{display:flex; flex-direction:column; gap:3px; padding-top:6px;}
  .ic{width:15px; height:15px; flex:none;}
  .chev{width:14px; height:14px; flex:none; transition:transform .18s;}

  /* conversation turn — plain rendered text */
  .cmsg{margin:15px 2px; max-width:74ch;}
  .cmsg .who{display:flex; align-items:center; gap:8px; margin-bottom:5px;
    font:700 9.5px/1 var(--mono); letter-spacing:.14em;
    text-transform:uppercase;}
  .cmsg.attacker .who{color:var(--high);}
  .cmsg.victim .who{color:var(--low);}
  .cmsg .who .wt{color:var(--faint); font-weight:500; letter-spacing:.04em;}
  .cmsg .body{font:14px/1.72 var(--sans); color:var(--txt);
    white-space:pre-wrap; overflow-wrap:anywhere;}

  /* activity row — LLM calls & tool calls, collapsible */
  details.act{align-self:stretch;}
  .actrow{display:flex; align-items:flex-start; gap:9px; padding:7px 8px;
    border-radius:8px; transition:background .12s;}
  details.act > summary.actrow{list-style:none; cursor:pointer;}
  details.act > summary.actrow::-webkit-details-marker{display:none;}
  details.act > summary.actrow:hover{background:var(--bg-2);}
  .actrow > .ic{margin-top:1px; color:var(--faint);}
  .actrow.llm > .ic{color:var(--accent);}
  .actrow.err > .ic{color:var(--crit);}
  .actlabel{flex:1; min-width:0; display:flex; align-items:baseline; gap:7px;
    flex-wrap:wrap; font:13.5px/1.5 var(--sans); color:var(--dim);}
  .actlabel .who{font:600 12.5px/1.45 var(--mono); color:var(--txt);}
  .actlabel .tgt{font:12px/1.5 var(--mono); color:var(--dim);
    overflow-wrap:anywhere;}
  .actlabel .dec{font:700 10px/1.5 var(--mono); letter-spacing:.05em;
    text-transform:uppercase; color:var(--ok);}
  .actlabel .dec.deny{color:var(--crit);}
  .actstat{flex:none; display:flex; gap:9px; align-items:center;
    font:11px/1.6 var(--mono); color:var(--faint);}
  .actrow .chev{margin-top:3px; color:var(--faint);}
  details.act[open] > summary.actrow .chev{transform:rotate(180deg);}
  .livein{display:inline-flex; align-items:center; gap:6px; color:var(--low);
    font:600 12px/1.5 var(--mono);}
  .livein .pd{width:6px; height:6px; border-radius:50%; background:var(--low);
    animation:pulse 1.4s infinite;}
  .actbody{margin:2px 0 12px 32px; display:flex; flex-direction:column;
    gap:8px;}

  /* code block — prompt / response inside an expanded activity */
  .cblk{border:1px solid var(--line); border-radius:8px;
    background:var(--panel); overflow:hidden;}
  .cblk > .cbh{font:700 9px/1 var(--mono); letter-spacing:.13em;
    text-transform:uppercase; color:var(--faint); padding:7px 11px;
    background:var(--panel-2); border-bottom:1px solid var(--line);}
  .cblk > .cbt{padding:9px 11px; font:12px/1.62 var(--mono); color:var(--dim);
    white-space:pre-wrap; overflow-wrap:anywhere;}
  .cblk.resp{border-color:var(--line-2);}
  .cblk.resp > .cbt{color:var(--txt);}
  .cblk.err > .cbh{color:var(--crit);}
  .tn{padding:8px 11px; border-top:1px solid var(--line);}
  .tn:first-of-type{border-top:0;}
  .tn > .tnr{display:block; margin-bottom:5px; font:700 8.5px/1 var(--mono);
    letter-spacing:.14em; text-transform:uppercase; color:var(--faint);}
  .tn.user > .tnr{color:var(--low);}
  .tn.assistant > .tnr{color:var(--accent);}
  .tn > .tnt{font:12px/1.62 var(--mono); color:var(--dim);
    white-space:pre-wrap; overflow-wrap:anywhere;}

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
      <div class="kicker">Agents</div>
      <h2>Live LLM &amp; tool stream</h2>
      <div class="desc">Every deployed agent's reasoning, turn by turn — each
        LLM call paired prompt-to-response with its model, latency, and token
        cost, next to the tool calls and messages it drove in the victim lane.
        Pick an agent on the left to follow just its thread.</div>
      <div class="agentgrid">
        <div class="card"><h3>Active agents</h3>
          <div class="scroll agentrail" id="agentSummary"></div></div>
        <div class="card">
          <div class="streamhd">
            <h3>Conversation &amp; tool stream</h3>
            <span class="streamfilter" id="streamFilter"></span>
          </div>
          <div class="scroll stream" id="agentEvents"></div>
        </div>
      </div>
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

  // ---- live LLM & tool stream --------------------------------------------
  let STREAM_FILTER=null, LAST_AGENTS=null;
  const OPEN=new Set();              // prompt <details> kept open across polls
  function dtoggle(d){
    if(d.open)OPEN.add(d.dataset.k); else OPEN.delete(d.dataset.k);
  }
  function emeta(x){
    let m=x&&x.metadata;
    if(typeof m==='string'){try{m=JSON.parse(m);}catch(e){m=null;}}
    return m||{};
  }
  function kfmt(n){n=+n||0;
    return n>=1000?(n/1000).toFixed(n>=10000?0:1)+'k':String(n);}
  function latfmt(ms){ms=+ms||0;
    return ms>=1000?(ms/1000).toFixed(1)+'s':Math.round(ms)+'ms';}

  // Split a rendered prompt ("[SYSTEM]\n..\n\n[USER]\n..") into role turns.
  function parseTurns(t){
    t=t||'';const parts=[];const re=/\[(SYSTEM|USER|ASSISTANT)\]\n?/g;
    let m,prev=null,idx=0;
    while((m=re.exec(t))){
      if(prev!==null)parts.push({role:prev,text:t.slice(idx,m.index).trim()});
      prev=m[1].toLowerCase();idx=re.lastIndex;
    }
    if(prev!==null)parts.push({role:prev,text:t.slice(idx).trim()});
    if(!parts.length&&t.trim())parts.push({role:'prompt',text:t.trim()});
    return parts.filter(p=>p.text);
  }

  // Pair each llm.request with its llm.response/llm.error (events are DESC,
  // so a response is seen just before its request).
  function pairEvents(events){
    const entries=[],pending={};
    for(const e of events){
      const et=e.event_type||'',key=e.agent_id||e.session_id||'?';
      if(et==='llm.response'||et==='llm.error'){pending[key]=e;continue;}
      if(et==='llm.request'){
        const resp=pending[key]||null;delete pending[key];
        entries.push({type:'llm',req:e,resp:resp,
          created_at:(resp&&resp.created_at)||e.created_at});
        continue;
      }
      if(et==='tool.event'){
        entries.push({type:'tool',ev:e,created_at:e.created_at});continue;
      }
      entries.push({type:'msg',ev:e,created_at:e.created_at});
    }
    for(const k in pending){            // response whose request scrolled off
      const r=pending[k];
      entries.push({type:'llm',req:null,resp:r,created_at:r.created_at});
    }
    return entries;
  }

  // minimal line icons (Claude-style activity rows)
  const ICONS={
    llm:'<svg viewBox="0 0 16 16" class="ic" fill="currentColor"><path d="M8 '
      +'.8l1.8 4.9 4.9 1.8-4.9 1.8L8 15.2 6.2 9.3 1.3 7.5 6.2 5.7z"/></svg>',
    net:'<svg viewBox="0 0 16 16" class="ic" fill="none" stroke="currentColor"'
      +' stroke-width="1.3"><circle cx="8" cy="8" r="6.3"/><path d="M1.7 8h12.6'
      +'M8 1.7c2.2 2 2.2 10.6 0 12.6M8 1.7c-2.2 2-2.2 10.6 0 12.6"/></svg>',
    file:'<svg viewBox="0 0 16 16" class="ic" fill="none" stroke="currentColor"'
      +' stroke-width="1.3"><path d="M9 1.8H4.4c-.7 0-1.2.6-1.2 1.2v10c0 .7.5 '
      +'1.2 1.2 1.2h7.2c.7 0 1.2-.5 1.2-1.2V5.8z"/><path d="M9 1.8v4h4"/></svg>',
    shell:'<svg viewBox="0 0 16 16" class="ic" fill="none" stroke="currentColor'
      +'" stroke-width="1.3"><rect x="1.8" y="3" width="12.4" height="10" rx="'
      +'1.5"/><path d="M4.7 6.6L7 8.6 4.7 10.6M8.7 10.6h3"/></svg>',
    mcp:'<svg viewBox="0 0 16 16" class="ic" fill="none" stroke="currentColor" '
      +'stroke-width="1.3"><path d="M8 1.4l5.7 3.3v6.6L8 14.6 2.3 11.3V4.7z"/>'
      +'<circle cx="8" cy="8" r="2.2"/></svg>',
    err:'<svg viewBox="0 0 16 16" class="ic" fill="none" stroke="currentColor" '
      +'stroke-width="1.4"><path d="M8 2.3l6.2 10.9H1.8z"/><path d="M8 6.4v3.3'
      +'M8 11.4v.2"/></svg>',
    dot:'<svg viewBox="0 0 16 16" class="ic" fill="currentColor"><circle cx="8"'
      +' cy="8" r="3"/></svg>',
  };
  const CHEV='<svg viewBox="0 0 16 16" class="chev" fill="none" stroke="curren'
    +'tColor" stroke-width="1.7"><path d="M4.5 6.5L8 10l3.5-3.5"/></svg>';
  const VERBS={ideation:'generating ideas',judge:'judging the transcript',
    strategist:'synthesising chains',execution:'planning the next move',
    triage:'triaging the finding',patch:'drafting a patch',
    repro:'reproducing the finding',cold:'cold-verifying'};
  function verbFor(kind,role){
    const s=((kind||'')+' '+(role||'')).toLowerCase();
    for(const k in VERBS)if(s.indexOf(k)>=0)return VERBS[k];
    return 'reasoning';
  }
  function toolIcon(t){
    const s=((t.event_type||'')+' '+(t.action_class||'')).toLowerCase();
    if(/mcp/.test(s))return ICONS.mcp;
    if(/net/.test(s))return ICONS.net;
    if(/shell|process|exec/.test(s))return ICONS.shell;
    if(/file|fs|read|write/.test(s))return ICONS.file;
    return ICONS.dot;
  }
  function turnsBlock(text){
    const rows=parseTurns(text).map(t=>`<div class="tn ${esc(t.role)}">`
      +`<span class="tnr">${esc(t.role)}</span>`
      +`<div class="tnt">${trunc(t.text,2200)}</div></div>`).join('');
    return `<div class="cblk"><div class="cbh">prompt</div>${rows}</div>`;
  }

  // LLM call -> a collapsible activity row
  function actLLM(en){
    const req=en.req,resp=en.resp,isErr=!!resp&&resp.event_type==='llm.error';
    const ref=req||resp||{};
    const agent=ref.agent_id||ref.session_id||'agent';
    const model=(resp&&resp.model)||(req&&req.model)||'';
    const rm=emeta(resp),k='a'+(ref.event_id||(resp&&resp.event_id)||'');
    const live=!resp;
    let stat='';
    if(model)stat+=`<span>${esc(model)}</span>`;
    if(resp&&!isErr&&rm.output_tokens)
      stat+=`<span>${kfmt(rm.output_tokens)} tok</span>`;
    if(rm.latency_ms)stat+=`<span>${latfmt(rm.latency_ms)}</span>`;
    stat+=`<span>${ts(en.created_at)}</span>`;
    let body='';
    if(req&&req.text)body+=turnsBlock(req.text);
    if(isErr)body+=`<div class="cblk err"><div class="cbh">error</div>`
      +`<div class="cbt">${trunc(resp.text||'(no detail)',1200)}</div></div>`;
    else if(resp&&resp.text)body+=`<div class="cblk resp">`
      +`<div class="cbh">response</div>`
      +`<div class="cbt">${trunc(resp.text,2600)}</div></div>`;
    else body+=`<div class="cblk"><div class="cbh">response</div>`
      +`<div class="cbt">waiting for the model to reply&#8230;</div></div>`;
    const verb=isErr?'model error'
      :(live?`<span class="livein"><span class="pd"></span>`
        +`${esc(verbFor(ref.agent_kind,ref.role))}&#8230;</span>`
        :esc(verbFor(ref.agent_kind,ref.role)));
    return `<details class="act" data-k="${k}" ontoggle="dtoggle(this)"`
      +`${OPEN.has(k)?' open':''}><summary class="actrow llm `
      +`${isErr?'err':''}">${isErr?ICONS.err:ICONS.llm}`
      +`<span class="actlabel"><span class="who">${esc(agent)}</span>`
      +`<span>${verb}</span></span>`
      +`<span class="actstat">${stat}</span>${CHEV}</summary>`
      +`<div class="actbody">${body}</div></details>`;
  }

  // tool / MCP / file / network call -> a minimal activity row
  function actTool(t){
    const dec=(t.decision||t.status||'').toString();
    const deny=/(den|block|reject|fail)/i.test(dec);
    const et=(t.event_type||'event').replace(/^agent\./,'').replace(/\./g,' ');
    const target=t.target||t.tool_name||'';
    const exc=t.excerpt||t.text||'';
    const k='t'+(t.event_id||target||'');
    const label=`<span class="actlabel"><span class="who">`
      +`${esc(t.actor||t.agent_id||'agent')}</span><span>${esc(et)}</span>`
      +(target?`<span class="tgt">${esc(target)}</span>`:'')
      +(dec?`<span class="dec ${deny?'deny':''}">${esc(dec)}</span>`:'')
      +`</span><span class="actstat"><span>${ts(t.created_at)}</span></span>`;
    if(!exc)
      return `<div class="actrow">${toolIcon(t)}${label}</div>`;
    return `<details class="act" data-k="${k}" ontoggle="dtoggle(this)"`
      +`${OPEN.has(k)?' open':''}><summary class="actrow">${toolIcon(t)}`
      +`${label}${CHEV}</summary><div class="actbody"><div class="cblk">`
      +`<div class="cbt">${trunc(exc,700)}</div></div></div></details>`;
  }

  // attacker / victim turn -> plain rendered text (article-style)
  function chatMsg(e){
    const tag=((e.role||'')+' '+(e.event_type||'')).toLowerCase();
    const att=/attack/.test(tag),vic=/victim/.test(tag);
    const who=att?'attacker':(vic?'victim':'message');
    return `<div class="cmsg ${att?'attacker':'victim'}"><div class="who">`
      +`${esc(who)}<span class="wt">${esc(e.agent_id||e.session_id||'')}`
      +` &middot; ${ts(e.created_at)}</span></div>`
      +`<div class="body">${trunc(e.text||'(no text)',2000)}</div></div>`;
  }

  function entryAgent(en){
    if(en.type==='llm')return((en.req&&en.req.agent_id)
      ||(en.resp&&en.resp.agent_id)||null);
    if(en.type==='tool')return(en.ev.actor||en.ev.agent_id||null);
    return(en.ev.agent_id||en.ev.session_id||null);
  }

  function renderAgents(a){
    LAST_AGENTS=a;
    if(!renderAgents._bound){          // one-time: click a rail card to filter
      renderAgents._bound=true;
      const rail=document.getElementById('agentSummary');
      if(rail)rail.addEventListener('click',ev=>{
        const row=ev.target.closest('.arow');if(!row)return;
        STREAM_FILTER=row.dataset.agent||null;
        if(LAST_AGENTS)renderAgents(LAST_AGENTS);
      });
    }
    const summary=(a&&a.summary)||[];
    const events=(a&&a.events)||[];
    const tools=(a&&a.tools)||[];

    // agent rail
    if(!summary.length){
      STREAM_FILTER=null;
      set('agentSummary','<div class="empty">no agents deployed yet</div>');
    }else{
      const totLlm=summary.reduce((s,x)=>s+(x.llm_calls||0),0);
      let rail=`<div class="arow all ${STREAM_FILTER?'':'sel'}" data-agent="">`
        +`<div class="anm">All agents</div>`
        +`<div class="ak">${summary.length} active &middot; `
        +`${num(totLlm)} llm call(s)</div></div>`;
      rail+=summary.map(x=>{
        const sel=STREAM_FILTER===x.agent_id;
        const model=x.model?`${esc(x.provider||'')}/${esc(x.model)}`:'';
        return `<div class="arow ${sel?'sel':''}" data-agent="${esc(x.agent_id)}">`
          +`<div class="anm"><span class="adot"></span>${esc(x.agent_id)}</div>`
          +`<div class="ak">${esc(x.agent_kind||'agent')}`
          +`${model?' &middot; '+model:''}</div><div class="amini">`
          +`<span class="ministat"><b>${x.llm_calls||0}</b> llm</span>`
          +`<span class="ministat"><b>${x.messages||0}</b> msg</span>`
          +`<span class="ministat"><b>${x.tool_events||0}</b> tool</span>`
          +`</div></div>`;
      }).join('');
      set('agentSummary',rail);
    }
    set('streamFilter',STREAM_FILTER
      ? `&#9656; following ${esc(STREAM_FILTER)}` : '');

    // timeline — paired exchanges + tool rows, newest first
    let entries=pairEvents(events);
    for(const t of tools)entries.push({type:'tool',ev:t,
      created_at:t.created_at});
    entries.sort((p,q)=>(q.created_at||'').localeCompare(p.created_at||''));
    if(STREAM_FILTER)
      entries=entries.filter(en=>entryAgent(en)===STREAM_FILTER);
    entries=entries.slice(0,80);
    if(!entries.length){
      set('agentEvents','<div class="empty">'+(STREAM_FILTER
        ?'no activity for this agent yet'
        :'no LLM or tool activity recorded yet')+'</div>');
      return;
    }
    set('agentEvents',entries.map(en=>
      en.type==='llm'?actLLM(en)
      :en.type==='tool'?actTool(en.ev)
      :chatMsg(en.ev)).join(''));
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
    renderAgents(d.agents);
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

    @app.get("/api/agents")
    def api_agents() -> dict[str, Any]:
        return _agents(db_path)

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
