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

import re
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
    rows = _query(
        db_path,
        "SELECT idea_id, cycle_id, zone_id, source_mode, title, approach, "
        "novelty_notes, priority_score, deduplicated, created_at FROM ideas "
        "ORDER BY created_at DESC, priority_score DESC LIMIT 24",
    )
    for row in rows:
        row["derived_from_skill"] = _derived_from_skill(
            row.get("novelty_notes")
        )
    return rows


def _derived_from_skill(novelty_notes: str | None) -> str:
    if not novelty_notes:
        return ""
    match = re.search(r"\[skill=([A-Z0-9-]+)\]", novelty_notes)
    return match.group(1) if match else ""


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


def _judge_appeals(db_path: str) -> dict[str, Any]:
    """Frontier-model appeal summary: appeal rate + override rate (§7.2)."""
    appeals = _query(
        db_path,
        "SELECT lane_id, ensemble_verdict, appeal_verdict, disagreement "
        "FROM appeal_verdicts ORDER BY created_at DESC",
    )
    overrides = sum(
        1 for a in appeals if a["appeal_verdict"] != a["ensemble_verdict"])
    return {
        "appeal_count": len(appeals),
        "override_count": overrides,
        "override_rate": overrides / len(appeals) if appeals else 0.0,
        "recent": [
            {"lane_id": a["lane_id"], "ensemble": a["ensemble_verdict"],
             "appeal": a["appeal_verdict"], "disagreement": a["disagreement"]}
            for a in appeals[:10]
        ],
    }


def _attack_elo(db_path: str) -> list[dict[str, Any]]:
    """Per-zone attack Elo leaderboard, rating-sorted descending (§7.3)."""
    return _query(
        db_path,
        "SELECT zone_id, attack_id, rating, comparisons, wins, losses "
        "FROM attack_elo ORDER BY rating DESC",
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


def patch_isolation_badge(mode: str | None) -> str:
    """Render the isolation-mode badge for the patch panel — a reviewer sees
    at a glance whether a verdict was proven against a real build or the mock
    surface (patch-isolation spec §9)."""
    return mode if mode in ("live", "mock") else "mock"


def _patches(db_path: str) -> list[dict[str, Any]]:
    """Blue-team patch candidates, joined to their latest isolation build."""
    rows = _query(
        db_path,
        "SELECT p.patch_id, p.zone_id, p.approach, p.invasiveness, p.status, "
        "p.created_at, ("
        "  SELECT pb.isolation_mode FROM patch_builds pb "
        "  WHERE pb.patch_id = p.patch_id "
        "  ORDER BY pb.created_at DESC LIMIT 1) AS isolation_mode "
        "FROM patches p ORDER BY p.created_at DESC LIMIT 20",
    )
    for row in rows:
        row["isolation_mode"] = patch_isolation_badge(row.get("isolation_mode"))
    return rows


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


def _kill_chains(db_path: str) -> list[dict[str, Any]]:
    """Cross-zone kill chains with their ordered, per-step execution trace.

    Each chain's steps are joined to the chain_step_results rows so the
    timeline shows which steps landed and what tokens they produced.
    """
    import json as _json

    chains = _query(
        db_path,
        "SELECT chain_id, cycle_id, title, zones, primary_zone, steps "
        "FROM attack_chains ORDER BY created_at DESC LIMIT 24",
    )
    step_rows = _query(
        db_path,
        "SELECT chain_id, step_index, zone_id, landed, produced_tokens "
        "FROM chain_step_results",
    )
    results: dict[tuple[str, int], dict[str, Any]] = {
        (r["chain_id"], r["step_index"]): r for r in step_rows
    }
    out: list[dict[str, Any]] = []
    for c in chains:
        try:
            steps = _json.loads(c.get("steps") or "[]")
        except (ValueError, TypeError):
            steps = []
        timeline: list[dict[str, Any]] = []
        for s in steps:
            idx = s.get("step_index", 0)
            res = results.get((c["chain_id"], idx))
            landed = bool(res["landed"]) if res else False
            try:
                produced = (_json.loads(res["produced_tokens"])
                            if res else [])
            except (ValueError, TypeError):
                produced = []
            timeline.append({
                "step_index": idx,
                "zone_id": s.get("zone_id", ""),
                "objective": s.get("objective", ""),
                "landed": landed,
                "produced_tokens": produced,
            })
        out.append({
            "chain_id": c["chain_id"],
            "cycle_id": c["cycle_id"],
            "title": c["title"],
            "primary_zone": c["primary_zone"],
            "timeline": timeline,
        })
    return out


def _render_kill_chains_html(chains: list[dict[str, Any]]) -> str:
    """Render the kill-chain timeline view — one ordered row per chain."""
    if not chains:
        return ("<div class='kill-chains empty'>"
                "No cross-zone kill chains composed yet.</div>")
    parts = ["<div class='kill-chains'><h3>Kill-chain timeline</h3>"]
    for c in chains:
        parts.append(
            f"<div class='kill-chain' data-chain='{c['chain_id']}'>"
            f"<h4>{c['chain_id']} — {c['title']}</h4>"
            f"<p>cycle {c['cycle_id']} · terminal zone "
            f"{c['primary_zone']}</p><ol class='chain-steps'>")
        for step in c["timeline"]:
            state = "landed" if step["landed"] else "missed"
            tokens = ", ".join(step["produced_tokens"]) or "(none)"
            parts.append(
                f"<li class='chain-step {state}'>"
                f"<span class='zone'>{step['zone_id']}</span> "
                f"<span class='objective'>{step['objective']}</span> "
                f"<span class='state'>{state}</span> "
                f"<span class='tokens'>{tokens}</span></li>")
        parts.append("</ol></div>")
    parts.append("</div>")
    return "".join(parts)


def _niche_heatmap(db_path: str) -> dict[str, Any]:
    """B5 MAP-Elites niche heatmap — a zone × interaction_style occupancy grid.

    Rows are zones, columns the six interaction styles. Each cell carries the
    elite score, occupancy and the elite's turn_bucket niche descriptor so the
    page can colour-scale by best_score and show empty cells blank.
    """
    import json as _json

    from red_team.archive import INTERACTION_STYLES

    rows = _query(
        db_path,
        "SELECT zone_id, interaction_style, response_movement, best_score, "
        "occupancy, niche_descriptors FROM idea_archive_cells",
    )
    # Aggregate to one (zone, style) cell — the strongest elite in the column.
    grid: dict[tuple[str, str], dict[str, Any]] = {}
    for r in rows:
        key = (r["zone_id"], r["interaction_style"])
        prev = grid.get(key)
        if prev is not None and prev["best_score"] >= r["best_score"]:
            continue
        try:
            nd = _json.loads(r["niche_descriptors"] or "{}")
        except (TypeError, ValueError):
            nd = {}
        grid[key] = {
            "best_score": r["best_score"],
            "occupancy": r["occupancy"],
            "turn_bucket": nd.get("turn_bucket", ""),
        }
    zones = sorted({r["zone_id"] for r in rows})
    return {
        "styles": list(INTERACTION_STYLES),
        "rows": [
            {
                "zone_id": zone,
                "cells": [grid.get((zone, style)) for style in INTERACTION_STYLES],
            }
            for zone in zones
        ],
    }


def _operators(db_path: str) -> list[dict[str, Any]]:
    rows = _query(
        db_path,
        "SELECT operator, uses, successes, avg_score, last_lift "
        "FROM mutation_operator_stats ORDER BY successes DESC, uses DESC",
    )
    for r in rows:
        uses = r.get("uses") or 0
        r["success_rate"] = (r.get("successes") or 0) / uses if uses else 0.0
    return rows


def _operators_by_zone(db_path: str) -> list[dict[str, Any]]:
    """Per-zone mutation-operator breakdown — the global rollup's companion."""
    rows = _query(
        db_path,
        "SELECT zone_id, operator, uses, successes, avg_score, last_lift "
        "FROM mutation_operator_stats_by_zone "
        "ORDER BY zone_id, successes DESC, uses DESC",
    )
    for r in rows:
        uses = r.get("uses") or 0
        r["success_rate"] = (r.get("successes") or 0) / uses if uses else 0.0
    return rows


def _model_tournament(db_path: str) -> dict[str, Any]:
    """Per-zone model win-rate + recent head-to-head rounds
    (model-ideation-tournament spec §9). Additive, read-only."""
    winrates = _query(
        db_path,
        "SELECT zone_id, model_label, role, winrate, h2h_wins, "
        "h2h_comparisons, confirmed, suspicious, ideas_executed "
        "FROM model_zone_winrate ORDER BY winrate DESC",
    )
    rounds = _query(
        db_path,
        "SELECT zone_id, cycle_id, winner_label, created_at "
        "FROM model_tournament_rounds ORDER BY created_at DESC LIMIT 10",
    )
    return {
        "winrates": winrates,
        "recent_rounds": [
            {"zone_id": r["zone_id"], "cycle_id": r["cycle_id"],
             "winner": r["winner_label"]}
            for r in rounds
        ],
    }


def _purple_heatmap(db_path: str) -> list[dict[str, Any]]:
    """Joint attack-coverage x detection-coverage, one cell per zone."""
    return _query(db_path,
        "SELECT z.zone_id AS zone_id, z.name AS zone_name, "
        "z.coverage_score AS attack_coverage, "
        "COALESCE(c.coverage_score, 0.0) AS detection_coverage, "
        "COALESCE(c.sample_count, 0) AS detection_samples "
        "FROM surface_zones z "
        "LEFT JOIN detection_coverage c ON c.zone_id = z.zone_id "
        "ORDER BY z.zone_id")


def _purple_report_card(db_path: str) -> dict[str, Any]:
    """The most recent report card, decoded for the dashboard."""
    rows = _query(db_path,
        "SELECT card_id, generated_at, dimensions, summary "
        "FROM report_cards ORDER BY generated_at DESC LIMIT 1")
    if not rows:
        return {}
    import json
    card = dict(rows[0])
    card["dimensions"] = json.loads(card.get("dimensions") or "[]")
    return card


def _purple_timeline(db_path: str) -> list[dict[str, Any]]:
    """Recent detection results — the evidence-timeline feed."""
    return _query(db_path,
        "SELECT result_id, session_id, execution_id, zone_id, quadrant, "
        "prevention, observability, created_at "
        "FROM detection_results ORDER BY created_at DESC LIMIT 50")


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


def build_sandbox_runs_view(db) -> dict:
    """Operational view: per-lane victim mode and whether the run was
    deterministic (real-nemoclaw-provisioner spec §10). Accepts a Database."""
    rows = db.fetchall(
        "SELECT run_id, instance_id, lane_id, mode, deterministic, "
        "patch_applied, provisioned_at, torn_down_at "
        "FROM sandbox_runs ORDER BY provisioned_at DESC LIMIT 100")
    return {
        "total": len(rows),
        "rows": [
            {
                "run_id": r["run_id"],
                "instance_id": r["instance_id"],
                "lane_id": r["lane_id"],
                "mode": r["mode"],
                "deterministic": bool(r["deterministic"]),
                "patch_applied": bool(r["patch_applied"]),
                "provisioned_at": r["provisioned_at"],
                "torn_down_at": r["torn_down_at"],
            }
            for r in rows
        ],
    }


def _sandbox_runs(db_path: str) -> list[dict[str, Any]]:
    """Sandbox-run audit rows for the dashboard snapshot, newest first."""
    return _query(
        db_path,
        "SELECT run_id, instance_id, lane_id, mode, deterministic, "
        "patch_applied, provisioned_at, torn_down_at FROM sandbox_runs "
        "ORDER BY provisioned_at DESC LIMIT 36",
    )


def render_technique_coverage(mcp) -> str:
    """The technique-coverage heatmap — zones x ATLAS techniques, additive
    alongside the existing attack-coverage heatmap (corpus-ideation §9)."""
    from red_team.taxonomy import load_taxonomy
    from red_team.technique_coverage import TechniqueCoverageModel

    model = TechniqueCoverageModel(mcp, load_taxonomy())
    rows = []
    for cov in model.map():
        rows.append(
            f"<tr><td>{cov.zone_id}</td>"
            f"<td>{cov.exercised}/{cov.total}</td>"
            f"<td>{cov.confirmed}/{cov.total}</td>"
            f"<td>{cov.exercised_ratio:.0%}</td>"
            f"<td>{', '.join(cov.gap_technique_ids) or '—'}</td></tr>")
    return (
        "<section><h2>Technique Coverage (MITRE ATLAS / OWASP LLM)</h2>"
        "<table><thead><tr><th>Zone</th><th>Exercised</th>"
        "<th>Confirmed</th><th>Exercised %</th><th>Gap techniques</th>"
        "</tr></thead><tbody>" + "".join(rows) + "</tbody></table></section>"
    )


def render_patch_hardening(mcp, patch_id: str) -> str:  # noqa: ANN001
    """The patch panel's gate-hardening breakdown — the gate1b variant
    pass/fail matrix and the gate_detection quadrant (verifier-hardening §9)."""
    variants = mcp.get_patch_variant_results(patch_id)
    detections = mcp.get_patch_detection_results(patch_id)
    vrows = "".join(
        f"<tr><td>{v['operator']}</td>"
        f"<td>{'BLOCKED' if v['blocked'] else 'LEAKED'}</td>"
        f"<td>{v['judge_verdict']}</td></tr>"
        for v in variants) or "<tr><td colspan=3>no variants</td></tr>"
    drows = "".join(
        f"<tr><td>{d['zone_id']}</td><td>{d['quadrant']}</td>"
        f"<td>{d['observability']}</td>"
        f"<td>{'pass' if d['passed'] else 'fail'}</td></tr>"
        for d in detections) or "<tr><td colspan=4>not scored</td></tr>"
    return (
        "<section><h3>Gate 1b — Mutation Robustness</h3>"
        "<table><thead><tr><th>Operator</th><th>Result</th>"
        "<th>Verdict</th></tr></thead><tbody>" + vrows + "</tbody></table>"
        "<h3>Gate 7 — Detection</h3>"
        "<table><thead><tr><th>Zone</th><th>Quadrant</th>"
        "<th>Observability</th><th>Gate</th></tr></thead><tbody>"
        + drows + "</tbody></table></section>"
    )


def render_generalization(db_path: str) -> str:
    """The patch-generalization-loop panel — one row per patch with round
    count, the union of operators tried, total bypasses found and the final
    generalization status (patch-generalization-loop §10)."""
    import json

    rows = _query(
        db_path,
        "SELECT * FROM generalization_rounds ORDER BY created_at")
    by_patch: dict[str, list[dict[str, Any]]] = {}
    for r in rows:
        by_patch.setdefault(r["patch_id"], []).append(r)

    out_rows = []
    for patch_id, prounds in sorted(by_patch.items()):
        ordered = sorted(prounds, key=lambda r: r["round_index"])
        operators: list[str] = []
        seen: set[str] = set()
        bypasses = 0
        for r in ordered:
            for op in json.loads(r["operators_tried"] or "[]"):
                if op not in seen:
                    seen.add(op)
                    operators.append(op)
            bypasses += int(r["variants_bypassed"] or 0)
        last_outcome = ordered[-1]["outcome"]
        status = ("GENERALIZED" if last_outcome == "generalized"
                  else "UNCONVERGED")
        out_rows.append(
            f"<tr><td>{patch_id}</td><td>{len(ordered)}</td>"
            f"<td>{', '.join(operators) or '—'}</td>"
            f"<td>{bypasses}</td><td>{last_outcome} ({status})</td></tr>")
    body = "".join(out_rows) or (
        "<tr><td colspan=5>no generalization rounds yet</td></tr>")
    return (
        "<section><h2>Patch Generalization</h2>"
        "<table><thead><tr><th>Patch</th><th>Rounds</th>"
        "<th>Operators tried</th><th>Bypasses found</th>"
        "<th>Status</th></tr></thead><tbody>"
        + body + "</tbody></table></section>"
    )


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
        "model_tournament": _model_tournament(db_path),
        "telemetry": _telemetry(db_path),
        "judges": _judges(db_path),
        "judge_appeals": _judge_appeals(db_path),
        "attack_elo": _attack_elo(db_path),
        "activity": _activity(db_path),
        "purple_heatmap": _purple_heatmap(db_path),
        "purple_report_card": _purple_report_card(db_path),
        "purple_timeline": _purple_timeline(db_path),
        "sandbox_runs": _sandbox_runs(db_path),
    }


# ---------------------------------------------------------------------------
# Trajectory & near-miss views (trajectory spec §6, additive)
# ---------------------------------------------------------------------------


def render_trajectory_ribbon(mcp) -> str:
    """Per-lane harm-ladder stage over turns — a compact ribbon per lane."""
    trajectories = mcp.get_trajectories()
    rows = []
    for t in trajectories[:50]:
        cells = "".join(
            f"<span class='stage stage-{ts.stage}'>{ts.stage}</span>"
            for ts in t.turn_scores)
        rows.append(
            f"<tr><td>{t.zone_id}</td><td>{t.lane_id}</td>"
            f"<td>{cells}</td><td>slope {t.erosion_slope:+.2f}</td></tr>")
    body = "".join(rows) or "<tr><td colspan=4>no trajectories yet</td></tr>"
    return ("<h2>Trajectory ribbon</h2><table>"
            "<tr><th>zone</th><th>lane</th><th>stage over turns</th>"
            f"<th>erosion</th></tr>{body}</table>")


def render_near_miss_queue(mcp) -> str:
    """Unconsumed near misses — attacks that almost worked, with seeds."""
    misses = mcp.search_near_misses(zone=None, only_unconsumed=True, top_k=50)
    rows = []
    for nm in misses:
        rows.append(
            f"<tr><td>{nm.zone_id}</td><td>stage {nm.max_stage}</td>"
            f"<td>turn {nm.stalled_at_turn}</td>"
            f"<td>{nm.erosion_excerpt[:120]}</td>"
            f"<td>{', '.join(nm.mutation_seeds)}</td></tr>")
    body = "".join(rows) or "<tr><td colspan=5>no near misses yet</td></tr>"
    return ("<h2>Near-miss queue</h2><table>"
            "<tr><th>zone</th><th>peak</th><th>stalled</th>"
            f"<th>erosion excerpt</th><th>seeds</th></tr>{body}</table>")


def render_dataset_readiness(mcp) -> str:
    """The dataset-readiness panel — when is learned-ranker training viable."""
    from red_team.dataset_readiness import evaluate_readiness

    traces = mcp.get_attempt_traces()
    pairs = mcp.get_pairwise_labels()
    result = evaluate_readiness(traces, pairs)
    status = "READY" if result.ready else "NOT READY"
    metric_rows = "".join(
        f"<tr><td>{k}</td><td>{v}</td></tr>"
        for k, v in sorted(result.metrics.items()))
    failure_rows = "".join(
        f"<li>{f}</li>" for f in result.failures) or "<li>none</li>"
    return ("<h2>Dataset readiness</h2>"
            f"<p>status: <b>{status}</b></p>"
            f"<table>{metric_rows}</table>"
            f"<h3>failing criteria</h3><ul>{failure_rows}</ul>")


def render_approvals_panel(mcp) -> str:  # noqa: ANN001
    """Render the approvals panel: pending requests + posture legend."""
    pending = mcp.get_pending_approvals()
    pending_rows = "".join(
        f"<tr><td>{r.request_id}</td><td>{r.patch_id}</td>"
        f"<td>{r.severity}</td><td>{r.zone_id}</td>"
        f"<td>{r.ask_expiry or '—'}</td></tr>"
        for r in pending
    ) or "<tr><td colspan='5'>no pending requests</td></tr>"
    return (
        "<section class='approvals-panel'>"
        "<h3>Approvals</h3>"
        "<p>posture: auto_allow (low/medium) · "
        "require_approval (high/critical)</p>"
        "<table><thead><tr><th>request</th><th>patch</th>"
        "<th>severity</th><th>zone</th><th>ask expiry</th></tr></thead>"
        f"<tbody>{pending_rows}</tbody></table>"
        "</section>"
    )


def _approvals_panel(db_path: str) -> str:
    """Render the approvals panel from a database path. Best-effort."""
    try:
        from infra.database import Database
        from infra.mcp_server import MCPServer
        db = Database(Path(db_path))
        try:
            return render_approvals_panel(MCPServer(db))
        finally:
            db.close()
    except Exception:  # noqa: BLE001
        return render_approvals_panel(_EmptyMCP())


def _trajectory_views(db_path: str) -> dict[str, str]:
    """Render both trajectory views from a database path. Best-effort —
    returns empty placeholders when the DB or its tables are absent."""
    try:
        from infra.database import Database
        from infra.mcp_server import MCPServer
        db = Database(Path(db_path))
        try:
            mcp = MCPServer(db)
            return {
                "trajectory_ribbon": render_trajectory_ribbon(mcp),
                "near_miss_queue": render_near_miss_queue(mcp),
                "dataset_readiness": render_dataset_readiness(mcp),
            }
        finally:
            db.close()
    except Exception:  # noqa: BLE001
        return {
            "trajectory_ribbon": render_trajectory_ribbon(_EmptyMCP()),
            "near_miss_queue": render_near_miss_queue(_EmptyMCP()),
            "dataset_readiness": render_dataset_readiness(_EmptyMCP()),
        }


class _EmptyMCP:
    """Stand-in used when the dashboard DB cannot be opened."""

    def get_trajectories(self, zone_id=None):
        return []

    def search_near_misses(self, zone, *, only_unconsumed, top_k):
        return []

    def get_attempt_traces(self, zone_id=None):
        return []

    def get_pairwise_labels(self):
        return []

    def get_pending_approvals(self):
        return []


# ---------------------------------------------------------------------------
# The page
# ---------------------------------------------------------------------------


_PAGE = r"""<!doctype html>
<html lang="en"><head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>MonkeyClaw — autonomous red-team console</title>
<link rel="icon" type="image/png" href="/logo.png">
<link rel="apple-touch-icon" href="/logo.png">
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
    --research_grounded:#ff6ac1;
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
  header{display:flex; justify-content:center; padding:34px 28px 6px;}
  header img{height:116px; width:auto; max-width:62%;
    filter:drop-shadow(0 0 30px rgba(245,166,35,.22));}

  /* ---- sticky section nav + live status pill ---- */
  nav.secnav{position:sticky; top:0; z-index:30;
    background:rgba(11,11,13,.86); backdrop-filter:blur(10px);
    -webkit-backdrop-filter:blur(10px);
    border-bottom:1px solid var(--line);}
  nav.secnav .navinner{max-width:1240px; margin:0 auto; padding:8px 24px;
    display:flex; align-items:center; gap:10px; flex-wrap:wrap;}
  nav.secnav .links{display:flex; gap:1px; flex-wrap:wrap; flex:1;}
  nav.secnav a{font:600 10.5px/1 var(--mono); letter-spacing:.11em;
    text-transform:uppercase; color:var(--faint); text-decoration:none;
    padding:7px 9px; border-radius:6px;
    transition:color .15s,background .15s;}
  nav.secnav a:hover{color:var(--dim); background:var(--panel);}
  nav.secnav a.on{color:var(--accent);}
  .navstat{display:flex; align-items:center; gap:7px; white-space:nowrap;
    font:600 11px/1 var(--mono); color:var(--dim);
    padding:6px 11px; border:1px solid var(--line); border-radius:7px;}
  .navstat .dot{flex:none; width:8px; height:8px; border-radius:50%;
    background:var(--ok); animation:pulse 1.9s infinite;}
  .navstat.idle .dot{background:var(--faint); animation:none;}
  .navstat b{color:var(--accent); font-weight:700;}

  /* ---- metric-card sparkline + delta ---- */
  .spark{display:block; width:100%; height:22px; margin-top:10px;}
  .spark polyline{fill:none; stroke:var(--accent); stroke-width:1.5;
    stroke-linejoin:round; stroke-linecap:round;}
  .metric .v .dlt{font:700 13px/1 var(--mono); margin-left:7px;}
  .dlt.up{color:var(--ok);} .dlt.dn{color:var(--crit);}

  /* ---- stale-connection notice ---- */
  .stale{position:fixed; left:50%; bottom:22px; transform:translateX(-50%);
    z-index:60; display:none; padding:9px 18px; border-radius:9px;
    background:var(--crit); color:#0b0b0d;
    box-shadow:0 10px 34px rgba(0,0,0,.55);
    font:700 11.5px/1.4 var(--mono); letter-spacing:.04em;}
  .stale.show{display:block;}

  /* ---- new-row flash — a fresh row glows briefly then settles ---- */
  @keyframes flashin{
    0%{box-shadow:inset 0 0 0 999px rgba(245,166,35,.15);}
    100%{box-shadow:inset 0 0 0 999px rgba(245,166,35,0);}}
  .flash{animation:flashin 1.7s ease-out;}

  @keyframes pulse{
    0%{box-shadow:0 0 0 0 rgba(54,211,147,.55);}
    70%{box-shadow:0 0 0 12px rgba(54,211,147,0);}
    100%{box-shadow:0 0 0 0 rgba(54,211,147,0);}
  }

  /* ---- sections ---- */
  section{margin-top:62px; scroll-margin-top:62px; opacity:0;
    transform:translateY(14px);
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
    transition:transform .2s,border-color .2s;
  }
  .flow .node:hover{transform:translateY(-2px); border-color:var(--line-2);}
  .flow .node .n{font:700 32px/1 var(--mono); color:var(--txt);
    font-variant-numeric:tabular-nums;}
  .flow .node .k{font-size:11px; letter-spacing:.13em; text-transform:uppercase;
    color:var(--dim); margin-top:7px;}
  .flow .node .s{font-size:11px; color:var(--faint); margin-top:3px;}
  .flow .arrow{display:flex; align-items:center; color:var(--line-2);
    font:700 21px/1 var(--mono); padding:0 7px;}
  .flow .node.red{border-top:2px solid var(--high);
    background:linear-gradient(165deg,rgba(255,159,67,.06),var(--panel));}
  .flow .node.blue{border-top:2px solid var(--low);
    background:linear-gradient(165deg,rgba(84,184,255,.06),var(--panel));}
  .flow .node.win{border-top:2px solid var(--ok);
    background:linear-gradient(165deg,rgba(54,211,147,.09),var(--panel));}

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
  .scroll{max-height:392px; min-height:208px; overflow-y:auto;
    margin-right:-6px; padding-right:6px;}
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

<nav class="secnav"><div class="navinner">
  <div class="links">
    <a href="#sec-overview">Overview</a>
    <a href="#sec-attack">Attack</a>
    <a href="#sec-agents">Agents</a>
    <a href="#sec-red">Red</a>
    <a href="#sec-repro">Repro</a>
    <a href="#sec-blue">Blue</a>
    <a href="#sec-search">Search</a>
    <a href="#sec-judge">Judgment</a>
    <a href="#sec-evidence">Evidence</a>
    <a href="#sec-sandbox">Sandbox</a>
    <a href="#sec-cost">Cost</a>
    <a href="#sec-purple">Purple</a>
  </div>
  <div class="navstat idle" id="navstat"><span class="dot"></span><span
    id="navtxt">connecting…</span></div>
</div></nav>

<div class="stale" id="stale"></div>

<div class="wrap">

  <section id="sec-overview">
    <div class="kicker">Overview</div>
    <h2>Run status</h2>
    <div class="desc">What the agent is doing right now, and the run reduced
      to one number per stage of the red-to-blue pipeline.</div>
    <div id="live" class="live idle"><span class="dot"></span>
      <div class="lt" id="liveText">connecting to the knowledge base…</div></div>
    <div class="flow" id="flow"></div>
    <div class="metrics" id="metrics"></div>
  </section>

    <section id="sec-attack">
      <div class="kicker">Attack surface</div>
    <h2>Coverage heatmap</h2>
    <div class="desc">All 18 attack-surface zones. Greener means better tested;
      red zones are where the red team is still blind.</div>
    <div class="heat" id="zones"></div>
    </section>

    <section id="sec-agents">
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

    <section id="sec-red">
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

  <section id="sec-repro">
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

  <section id="sec-blue">
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

  <section id="sec-search">
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

  <section id="sec-judge">
    <div class="kicker">Judgment quality</div>
    <h2>Appeals &amp; attack Elo</h2>
    <div class="desc">Frontier-model appeal outcomes and per-zone attack Elo
      ratings used to steer future red-team ideation.</div>
    <div class="cols">
      <div class="card"><h3>Judge appeals</h3>
        <div class="scroll" id="judgeAppeals"></div></div>
      <div class="card"><h3>Attack Elo</h3>
        <div class="scroll" id="attackElo"></div></div>
    </div>
  </section>

  <section id="sec-evidence">
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

  <section id="sec-sandbox">
    <div class="kicker">Sandbox</div>
    <h2>Provisioned runs</h2>
    <div class="desc">Recent sandbox/victim sessions, their deterministic
      capability posture, and teardown state.</div>
    <div class="card"><div class="scroll" id="sandboxRuns"></div></div>
  </section>

  <section id="sec-cost">
    <div class="kicker">Cost</div>
    <h2>Model usage</h2>
    <div class="desc">Token spend, latency and success rate for every model
      role driving the run.</div>
    <div class="card"><div id="models" class="heat"></div></div>
  </section>

  <section id="sec-purple">
    <div class="kicker">Purple</div>
    <h2>Detection coverage &amp; report card</h2>
    <div class="desc">Joint attack-coverage x detection-coverage per zone, the
      measured-vs-target security report card, and the recent detection
      verdict timeline.</div>
    <div class="card"><h3>Joint coverage heatmap</h3>
      <div id="purpleHeatmap" class="heat"></div></div>
    <div class="cols">
      <div class="card"><h3>Security report card</h3>
        <div class="scroll" id="purpleReportCard"></div></div>
      <div class="card"><h3>Detection timeline</h3>
        <div class="scroll tl" id="purpleTimeline"></div></div>
    </div>
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
  strategist:"var(--strategist)",policy_corpus:"var(--policy_corpus)",
  research_grounded:"var(--research_grounded)"};
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
// Diff-render: skip the DOM write when a section's markup is unchanged, and
// preserve scroll position when it is not — kills the 5s flicker / jump.
// HTML is parsed into a fragment (scripts inert) rather than assigned raw.
const _LAST={}, _KEYS={}, _RANGE=document.createRange();
function paint(el,html){
  el.replaceChildren(_RANGE.createContextualFragment(html));
}
function set(id,html){
  const el=document.getElementById(id);
  if(!el||_LAST[id]===html)return;
  const first=!(id in _LAST);
  _LAST[id]=html;
  const sc=el.closest('.scroll');
  const top=sc?sc.scrollTop:0;
  paint(el,html);
  if(sc&&sc.scrollTop!==top)sc.scrollTop=top;
  // flash any row carrying a data-rk key not seen on the previous render
  const keyed=el.querySelectorAll('[data-rk]');
  if(keyed.length){
    const seen=_KEYS[id]||new Set(), now=new Set();
    keyed.forEach(n=>{
      const k=n.getAttribute('data-rk'); now.add(k);
      if(!first&&k&&!seen.has(k))n.classList.add('flash');
    });
    _KEYS[id]=now;
  }
}

// one-shot count-up — eases a number from 0 to its value (rec #3)
function countUp(el,to){
  to=+to||0;
  if(to<=0){el.textContent='0';return;}
  const dur=680,t0=performance.now();
  (function step(now){
    const p=Math.min(1,(now-t0)/dur);
    el.textContent=Math.round(to*(1-Math.pow(1-p,3))).toLocaleString();
    if(p<1)requestAnimationFrame(step);
  })(performance.now());
}
async function j(u){try{return await (await fetch(u)).json();}catch(e){return null;}}

// Relative time — "2m ago"; falls back to the absolute stamp if unparseable.
function rel(s){
  if(!s)return'—';
  const t=Date.parse(String(s).replace(' ','T'));
  if(isNaN(t))return ts(s);
  let d=(Date.now()-t)/1000; if(d<0)d=0;
  if(d<60)return Math.floor(d)+'s ago';
  if(d<3600)return Math.floor(d/60)+'m ago';
  if(d<86400)return Math.floor(d/3600)+'h ago';
  return Math.floor(d/86400)+'d ago';
}

// Inline SVG sparkline — single stroked polyline, no axes/fill (rec #5).
function spark(vals,col){
  vals=(vals||[]).filter(v=>v!=null);
  if(vals.length<2)return'';
  const w=100,h=22,p=2;
  const mx=Math.max(...vals),mn=Math.min(...vals),rng=(mx-mn)||1;
  const pts=vals.map((v,i)=>{
    const x=p+i*(w-2*p)/(vals.length-1);
    const y=h-p-((v-mn)/rng)*(h-2*p);
    return x.toFixed(1)+','+y.toFixed(1);
  }).join(' ');
  return `<svg class="spark" viewBox="0 0 ${w} ${h}" preserveAspectRatio="none">`
    +`<polyline points="${pts}" vector-effect="non-scaling-stroke"`
    +(col?` style="stroke:${col}"`:'')+`/></svg>`;
}

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

let FIRST_FLOW=true;
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
    `<div class="node ${n[0]}"><div class="n" data-v="${n[1]||0}">`
    +`${num(n[1])}</div>`
    +`<div class="k">${n[2]}</div><div class="s">${esc(n[3])}</div></div>`
    +(i<nodes.length-1?'<div class="arrow">→</div>':'')).join(''));
  if(FIRST_FLOW){
    FIRST_FLOW=false;
    document.querySelectorAll('#flow .n').forEach((el,i)=>
      setTimeout(()=>countUp(el,+el.dataset.v||0),140+i*100));
  }
}

function renderMetrics(s,cycles){
  if(!s){set('metrics','');return;}
  const cov=Math.round((s.coverage||0)*100);
  const reg=Math.round((s.regression_rate||0)*100);
  // cycle_log arrives newest-first — reverse for a chronological series.
  const cyc=(cycles||[]).slice().reverse();
  const confSeries=cyc.map(c=>c.vulns_confirmed||0);
  const tokSeries=cyc.map(c=>c.total_tokens_used||0);
  const lastConf=confSeries.length?confSeries[confSeries.length-1]:0;
  const dlt=lastConf>0
    ? ` <span class="dlt up">&#9650;${lastConf}</span>` : '';
  const m=[
    [`${s.cycles||0}`,"Cycles completed","",''],
    [`${s.confirmed||0}${dlt}`,"Confirmed findings",
      `${s.suspicious||0} suspicious · +${lastConf} last cycle`,
      spark(confSeries,'var(--crit)')],
    [`${s.patches_verified||0}<small> / ${s.patches||0}</small>`,
      "Patches verified",`${s.patches_open||0} still open`,''],
    [`${reg}<small>%</small>`,"Regression pass rate",
      `${s.regression_pass||0} / ${s.regression_tests||0} tests`,''],
    [`${cov}<small>%</small>`,"Mean zone coverage",`${s.zone_count||0} zones`,''],
    [`$${(s.cost_usd||0).toFixed(2)}`,"Model cost",
      `${num(s.tokens_used)} tokens`,spark(tokSeries,'var(--accent)')],
  ];
    set('metrics',m.map(x=>
      `<div class="metric"><div class="v">${x[0]}</div>`
      +`<div class="l">${x[1]}</div>`
      +(x[2]?`<div class="sub">${esc(x[2])}</div>`:'')
      +(x[3]||'')+`</div>`).join(''));
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
      +`<span>${x.last_tested_at?rel(x.last_tested_at):'never tested'}</span></div>
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
    return `<div class="row" data-rk="${esc(x.finding_id||'')}" `
      +`style="border-left-color:${col}">
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
    const skill=x.derived_from_skill
      ?`<span class="chip mono">${esc(x.derived_from_skill)}</span>`:"";
    return `<div class="row ${x.deduplicated?'dedup':''}" `
      +`data-rk="${esc(x.idea_id||'')}" style="border-left-color:${col}">
      <div class="hd">${badge((x.source_mode||'').replace(/_/g,' '),col)}
        <span class="dim mono" style="font-size:11px">${esc(x.zone_id)} · `
        +`c${x.cycle_id} · p=${(x.priority_score||0).toFixed(2)}`
        +`${x.deduplicated?' · duplicate':''}</span>${skill}</div>
      <div class="ti" style="margin-top:5px">${trunc(x.title,80)}</div>
      <div class="ap">${trunc(x.approach,130)}</div>
    </div>`;}).join(''));
}

function renderRepro(r){
  if(!r||!r.length){set('repro',
    '<div class="empty">repro queue empty</div>');return;}
  set('repro',r.map(x=>{
    const col=SEV[x.severity]||"var(--line)";
    return `<div class="row" data-rk="${esc(x.finding_id||'')}" `
      +`style="border-left-color:${col}">
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
    return `<div class="row" data-rk="${esc(x.package_id||x.vuln_id||'')}" `
      +`style="border-left-color:${col}">
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
    return `<div class="row" data-rk="${esc(x.patch_id||'')}" `
      +`style="border-left-color:${col}">
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
    '<div class="empty">Mutation-operator stats build up once the '
    +'evolutionary search runs across multiple cycles.</div>');return;}
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

function renderJudgeAppeals(a){
  if(!a||!a.appeal_count){set('judgeAppeals',
    '<div class="empty">No appeals — the judge ensemble reached '
    +'consensus on every lane this cycle.</div>');return;}
  const rate=Math.round((a.override_rate||0)*100);
  const head=`<div class="row" style="border-left-color:var(--accent)">
    <div class="hd"><span class="ti">${a.appeal_count||0} appeals</span>
      <span class="chip"><b>${a.override_count||0}</b> overrides</span>
      <span class="chip">${rate}% override rate</span></div></div>`;
  const rows=(a.recent||[]).map(x=>
    `<div class="row" style="border-left-color:${x.appeal!==x.ensemble
      ?'var(--high)':'var(--ok)'}">
      <div class="hd"><span class="ti mono">${esc(x.lane_id)}</span>
        <span class="chip">ensemble <b>${esc(x.ensemble)}</b></span>
        <span class="chip">appeal <b>${esc(x.appeal)}</b></span></div>
      <div class="mt">disagreement ${(x.disagreement||0).toFixed(2)}</div>
    </div>`).join('');
  set('judgeAppeals',head+rows);
}

function renderAttackElo(rows){
  if(!rows||!rows.length){set('attackElo',
    '<div class="empty">Attack Elo accrues from repeated pairwise '
    +'comparisons — none in a single-cycle run.</div>');return;}
  set('attackElo',rows.map(x=>{
    const rating=x.rating||1000;
    const c=heat(Math.max(0,Math.min(1,(rating-900)/300)));
    return `<div class="row" style="border-left-color:${c}">
      <div class="hd"><span class="ti mono">${esc(x.zone_id)}</span>
        <span class="chip">${esc(x.attack_id)}</span>
        <span class="chip"><b>${rating.toFixed(0)}</b> Elo</span></div>
      <div class="mt">${x.wins||0}W / ${x.losses||0}L · `
        +`${x.comparisons||0} comparisons</div>
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

function renderSandboxRuns(rows){
  if(!rows||!rows.length){set('sandboxRuns',
    '<div class="empty">no sandbox runs recorded yet</div>');return;}
  set('sandboxRuns',rows.map(x=>{
    const torn=!!x.torn_down_at;
    const col=torn?'var(--ok)':'var(--med)';
    return `<div class="row" style="border-left-color:${col}">
      <div class="hd">${badge(torn?'torn down':'active',col)}
        <span class="ti mono" style="font-size:12px">${esc(x.lane_id)}</span>
        <span class="chip">${esc(x.mode||'mock')}</span>
        <span class="chip">${x.deterministic?'deterministic':'best effort'}</span>
        ${x.patch_applied?'<span class="chip">patched</span>':''}</div>
      <div class="mt">${esc(x.instance_id||'')} · ${rel(x.provisioned_at)}</div>
    </div>`;}).join(''));
}

function renderCycles(c){
  if(!c||!c.length){set('cycles',
    '<div class="empty">no cycles completed yet</div>');return;}
  set('cycles',c.map(x=>
    `<div class="row" data-rk="cy${x.cycle_id}" `
      +`style="border-left-color:var(--accent)">
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

const QUAD={PASS:"var(--ok)",PARTIAL:"var(--med)",
  WEAK:"var(--high)",FAIL:"var(--crit)"};

function renderPurpleHeatmap(h){
  if(!h||!h.length){set('purpleHeatmap',
    '<div class="empty">no detection coverage yet</div>');return;}
  set('purpleHeatmap',h.map(z=>{
    const a=z.attack_coverage||0, d=z.detection_coverage||0;
    return `<div class="zone">
      <div class="top"><span class="id">${esc(z.zone_id)}</span>
        <span class="pct" style="color:${heat(d)}">`
        +`${Math.round(d*100)}%</span></div>
      <div class="nm">${esc(z.zone_name||'')}</div>
      <div class="bar"><i style="width:${Math.max(3,a*100)}%;`
        +`background:${heat(a)}"></i></div>
      <div class="bar"><i style="width:${Math.max(3,d*100)}%;`
        +`background:${heat(d)}"></i></div>
      <div class="ft"><span>attack ${Math.round(a*100)}%</span>`
      +`<span>detect ${Math.round(d*100)}% · ${z.detection_samples||0}n`
      +`</span></div>
    </div>`;}).join(''));
}

function renderPurpleReportCard(c){
  if(!c||!c.dimensions||!c.dimensions.length){set('purpleReportCard',
    '<div class="empty">no report card generated yet</div>');return;}
  const head=`<div class="ap" style="margin-bottom:8px">`
    +`${trunc(c.summary,200)}</div>`;
  const rows=c.dimensions.map(d=>{
    const m=d.measured||0, t=d.target||0;
    const lbl=d.target_is_aspirational?' (aspirational)':'';
    return `<div class="row" style="border-left-color:${heat(m)}">
      <div class="hd"><span class="ti">${esc(d.name)}</span>
        <span class="chip"><b>${(m).toFixed(2)}</b> measured</span>
        <span class="chip">target ${(t).toFixed(2)}${lbl}</span>
        <span class="chip">${d.evidence_count||0} evidence</span></div>
      ${d.notes?`<div class="ap">${trunc(d.notes,140)}</div>`:''}</div>`;
  }).join('');
  set('purpleReportCard',head+rows);
}

function renderPurpleTimeline(t){
  if(!t||!t.length){set('purpleTimeline',
    '<div class="empty">no detection results yet</div>');return;}
  set('purpleTimeline',t.map(r=>
    `<div class="ev"><span class="ts">${ts(r.created_at)}</span>
      <div><div class="et">${esc(r.zone_id)} `
      +`${badge(r.quadrant,QUAD[r.quadrant]||'var(--dim)')}</div>
      <div class="em">${esc(r.prevention)} · ${esc(r.observability)}</div>`
      +`</div></div>`).join(''));
}

// persistent live status pill in the sticky nav — the at-a-glance scoreboard
function renderNav(s){
  const box=document.getElementById('navstat');
  const txt=document.getElementById('navtxt');
  if(!box||!txt)return;
  let str,idle;
  if(s&&s.current){
    idle=false;
    str=`cycle ${s.current.cycle} running · ${s.confirmed||0} confirmed`
      +` · $${(s.cost_usd||0).toFixed(2)}`;
  }else if(s){
    idle=true;
    str=`idle · ${s.cycles||0} cycles · ${s.confirmed||0} confirmed`
      +` · $${(s.cost_usd||0).toFixed(2)}`;
  }else return;
  if(txt.textContent!==str)txt.textContent=str;
  box.classList.toggle('idle',idle);
}

// highlight the nav link for whichever section is in view
function initNav(){
  const links={};
  document.querySelectorAll('nav.secnav a').forEach(a=>{
    links[a.getAttribute('href').slice(1)]=a;
  });
  const obs=new IntersectionObserver(es=>{
    es.forEach(e=>{
      if(!e.isIntersecting)return;
      Object.values(links).forEach(a=>a.classList.remove('on'));
      const a=links[e.target.id];
      if(a)a.classList.add('on');
    });
  },{rootMargin:'-58px 0px -62% 0px'});
  document.querySelectorAll('section[id]').forEach(s=>obs.observe(s));
}

// stale-data notice — shown when /api/all has not answered in a while
let LAST_OK=Date.now();
function checkStale(){
  const el=document.getElementById('stale');
  if(!el)return;
  const age=(Date.now()-LAST_OK)/1000;
  if(age>13){
    el.textContent='connection lost · last update '+Math.floor(age)+'s ago';
    el.classList.add('show');
  }else el.classList.remove('show');
}

async function tick(){
  const d=await j('/api/all');
  if(!d){
    const lt=document.getElementById('liveText');
    if(lt)lt.textContent="no data — knowledge base unreachable";
    return;                       // LAST_OK left stale -> notice appears
  }
  LAST_OK=Date.now();
  const st=document.getElementById('stale');
  if(st)st.classList.remove('show');
  renderNav(d.status);
  renderLive(d.status); renderFlow(d.status); renderMetrics(d.status,d.cycles);
    renderAgents(d.agents);
    renderZones(d.zones); renderFindings(d.findings); renderIdeas(d.ideas);
  renderRepro(d.repro); renderPackages(d.packages); renderPatches(d.patches);
  renderRegression(d.regression); renderArchive(d.archive);
  renderOperators(d.operators); renderJudges(d.judges);
  renderJudgeAppeals(d.judge_appeals); renderAttackElo(d.attack_elo);
  renderTelemetry(d.telemetry); renderCycles(d.cycles);
  renderSandboxRuns(d.sandbox_runs);
  renderModels(d.models);
  renderPurpleHeatmap(d.purple_heatmap);
  renderPurpleReportCard(d.purple_report_card);
  renderPurpleTimeline(d.purple_timeline);
  document.getElementById('stamp').textContent=
    'live · updated '+new Date().toLocaleTimeString();
}
initNav();
tick(); setInterval(tick,5000); setInterval(checkStale,1000);
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

    @app.get("/technique-coverage", response_class=HTMLResponse)
    def technique_coverage() -> str:
        """The MITRE ATLAS / OWASP technique-coverage heatmap — additive
        view alongside the attack-coverage heatmap (corpus-ideation §9)."""
        from infra.database import Database
        from infra.mcp_server import MCPServer
        db = Database(db_path)
        try:
            return render_technique_coverage(MCPServer(db))
        finally:
            db.close()

    @app.get("/generalization", response_class=HTMLResponse)
    def generalization() -> str:
        """The patch-generalization-loop panel — additive read-only view of
        generalization_rounds (patch-generalization-loop §10)."""
        return render_generalization(db_path)

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

    @app.get("/api/niche-heatmap")
    def api_niche_heatmap() -> dict[str, Any]:
        return _niche_heatmap(db_path)

    @app.get("/api/operators")
    def api_operators() -> list[dict[str, Any]]:
        return _operators(db_path)

    @app.get("/api/trajectory_views", response_class=HTMLResponse)
    def api_trajectory_views() -> str:
        """Additive views: trajectory ribbon, near-miss queue, dataset
        readiness."""
        views = _trajectory_views(db_path)
        return (views["trajectory_ribbon"] + views["near_miss_queue"]
                + views["dataset_readiness"])

    @app.get("/api/approvals_panel", response_class=HTMLResponse)
    def api_approvals_panel() -> str:
        """The additive approvals panel: pending requests + posture split."""
        return _approvals_panel(db_path)

    @app.get("/kill-chains", response_class=HTMLResponse)
    def kill_chains() -> str:
        """Cross-zone kill-chain timeline — one ordered, landed/missed row
        per composed AttackChain."""
        return _render_kill_chains_html(_kill_chains(db_path))

    @app.get("/api/mutation-operators")
    def api_mutation_operators() -> dict[str, Any]:
        """Mutation-operator success signal: per-operator uses /
        success-rate / avg-lift, global rollup plus the per-zone breakdown."""
        return {
            "global": _operators(db_path),
            "by_zone": _operators_by_zone(db_path),
        }

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
    # Bind all interfaces so the dashboard is reachable through Docker's
    # published port from the host; container network isolation + the explicit
    # `ports:` mapping are the access control.
    uvicorn.run(build_dashboard_app(db_path), host="0.0.0.0", port=port,
                log_level="warning")
