"""End-to-end exercise of every MCP tool against the real SQLite-backed server."""

from __future__ import annotations

import json

import pytest

from interfaces.types import (
    CycleSummaryInput,
    FindingInput,
    IdeaInput,
    RegressionTestInput,
    ReproPackageInput,
)


def test_coverage_gaps_seeded(real_mcp):
    gaps = real_mcp.get_coverage_gaps(top_n=18)
    assert len(gaps) == 18
    # priority sorted descending
    for a, b in zip(gaps, gaps[1:], strict=False):
        assert a.priority_score >= b.priority_score


def test_update_coverage_bounds(real_mcp):
    before = next(g for g in real_mcp.get_coverage_gaps(99) if g.zone_id == "SBX-FS")
    real_mcp.update_zone_coverage("SBX-FS", 0.05)
    after = next(g for g in real_mcp.get_coverage_gaps(99) if g.zone_id == "SBX-FS")
    assert after.coverage_score >= before.coverage_score
    # Decay
    real_mcp.update_zone_coverage("SBX-FS", -100.0)
    after2 = next(g for g in real_mcp.get_coverage_gaps(99) if g.zone_id == "SBX-FS")
    assert after2.coverage_score == 0.0


def test_log_idea_and_dedup(real_mcp):
    text = "Tool-call exfiltration via pasted documentation"
    iid = real_mcp.log_idea(IdeaInput(
        cycle_id=1, zone_id="PROMPT-INJ", source_mode="creative",
        title="exfil", approach=text, success_criteria="leak occurs",
        estimated_turns=5, novelty_notes="-",
    ))
    # Server embeds the text — callers no longer need to touch the model.
    dup = real_mcp.check_duplicate(f"exfil\n{text}", "PROMPT-INJ", threshold=0.92)
    assert dup.is_duplicate is True
    assert dup.matching_idea_id == iid
    assert dup.max_similarity > 0.95


def test_findings_lifecycle(real_mcp):
    iid = real_mcp.log_idea(IdeaInput(
        cycle_id=1, zone_id="SBX-FS", source_mode="creative",
        title="symlink", approach="..", success_criteria="..",
        estimated_turns=3, novelty_notes="-",
    ))
    fid = real_mcp.log_finding(FindingInput(
        cycle_id=1, idea_id=iid, zone_id="SBX-FS", source_mode="creative",
        idea_summary="Symlink escape via /tmp", verdict="confirmed",
        tier_caught="programmatic", failure_class="sandbox_escape",
        severity="critical", evidence=json.dumps([]),
    ))
    real_mcp.push_to_repro_queue(fid, priority="high")
    queue = real_mcp.get_repro_queue()
    assert len(queue) == 1
    assert queue[0].finding_id == fid
    # Second call: queue empty (atomic dequeue)
    assert real_mcp.get_repro_queue() == []
    found = real_mcp.search_findings("symlink escape", zone="SBX-FS", top_k=3)
    assert any(f.finding_id == fid for f in found)


def test_repro_package_publishes_to_blue_queue(real_mcp):
    iid = real_mcp.log_idea(IdeaInput(
        cycle_id=1, zone_id="PRV-ROUTE", source_mode="creative",
        title="leak", approach="..", success_criteria="..",
        estimated_turns=3, novelty_notes="-",
    ))
    fid = real_mcp.log_finding(FindingInput(
        cycle_id=1, idea_id=iid, zone_id="PRV-ROUTE", source_mode="creative",
        idea_summary="cloud-route leak", verdict="confirmed",
        tier_caught="programmatic", failure_class="pii_leak",
        severity="high", evidence=json.dumps([]),
    ))
    pid = real_mcp.push_repro_package(ReproPackageInput(
        finding_id=fid, vuln_id="MC-2026-0001", title="leak", severity="high",
        repro_rate=0.9, minimal_steps=[{"do": "x"}], affected_zone="PRV-ROUTE",
        affected_paths=None, ideas_used=[iid], transcripts={"original": [], "minimal": []},
        suggested_mitigations=["sanitize input"], repro_document_md="# leak",
        cold_verified=True, ready_for_blue=True,
    ))
    blue = real_mcp.get_blue_team_queue()
    assert any(p.package_id == pid for p in blue)


def test_cycle_summary_roundtrip(real_mcp):
    real_mcp.log_cycle_summary(CycleSummaryInput(
        cycle_id=42, summary="hello", zones_targeted=["SBX-FS"],
        ideas_generated=4, ideas_deduplicated=1, ideas_executed=3,
        vulns_confirmed=1, vulns_suspicious=0,
        total_tokens_used=12345, wall_time_seconds=12.5,
    ))
    summaries = real_mcp.get_recent_summaries(5)
    assert any(s.cycle_id == 42 for s in summaries)


def test_regression_test_roundtrip(real_mcp):
    tid = real_mcp.add_regression_test(RegressionTestInput(
        vuln_id="MC-2026-0001", zone_id="SBX-FS",
        test_script="#!/bin/sh\nexit 0\n",
        expected_result="vulnerability_blocked",
    ))
    suite = real_mcp.get_regression_suite()
    assert any(t.test_id == tid for t in suite)


def test_send_alert_persists(real_mcp, tmp_db):
    real_mcp.send_alert("hello", "high")
    row = tmp_db.fetchone("SELECT message, severity FROM alerts ORDER BY alert_id DESC LIMIT 1")
    assert row["message"] == "hello"
    assert row["severity"] == "high"


def test_real_server_telemetry_roundtrip(server):
    from interfaces.types import TelemetryEventInput
    eid = server.log_telemetry_event(TelemetryEventInput(
        session_id="S1", event_type="agent.tool.requested",
        actor="attacker", action_class="tool", target="Bash"))
    assert eid
    tl = server.get_session_timeline("S1")
    assert len(tl) == 1 and tl[0].event_type == "agent.tool.requested"


def test_real_server_model_run_and_judge_vote(server):
    from interfaces.types import ModelRunInput, JudgeVoteInput
    rid = server.log_model_run(ModelRunInput(
        role="red_ideation", model="m", provider="nvidia",
        input_tokens=5, output_tokens=7, latency_ms=42))
    assert rid
    vid = server.log_judge_vote(JudgeVoteInput(
        lane_id="L1", judge_role="semantic", verdict="confirmed",
        score=0.9, confidence=0.8, reasoning="r", evidence_turns=[3]))
    assert vid


def test_real_server_policy_corpus_roundtrip(server):
    from interfaces.types import PolicyCorpusResultInput
    server.log_policy_corpus_result(PolicyCorpusResultInput(
        run_id="RUN1", case_id="T01", observed_decision="deny",
        expected_decision="deny", passed=True, evidence="hook denial"))
    results = server.get_policy_corpus_results("RUN1")
    assert len(results) == 1 and results[0].passed is True


def test_real_server_conforms_to_protocol_v2(server):
    from interfaces.mcp_tools import MonkeyClawMCP
    assert isinstance(server, MonkeyClawMCP)


def test_a3_tables_exist(db):
    names = {r[0] for r in db.fetchall(
        "SELECT name FROM sqlite_master WHERE type='table'")}
    for t in ("telemetry_events", "model_runs", "judge_votes",
              "policy_corpus_results", "idea_components",
              "idea_archive_cells", "mutation_operator_stats"):
        assert t in names, f"missing table {t}"


def test_a3_schema_version_is_2(db):
    row = db.fetchone(
        "SELECT value FROM schema_meta WHERE key='schema_version'")
    assert row[0] == "2"


def test_migration_upgrades_legacy_v1_db(tmp_path):
    """A DB that predates A3 tables gets upgraded on open."""
    import sqlite3
    from infra.database import Database
    p = tmp_path / "legacy.db"
    # Simulate a v1 DB: schema_meta exists, version=1, no A3 tables.
    raw = sqlite3.connect(p.as_posix())
    raw.execute("CREATE TABLE schema_meta(key TEXT PRIMARY KEY, value TEXT NOT NULL)")
    raw.execute("INSERT INTO schema_meta VALUES('schema_version','1')")
    raw.commit()
    raw.close()
    db = Database(p)  # opening must migrate it
    names = {r[0] for r in db.fetchall(
        "SELECT name FROM sqlite_master WHERE type='table'")}
    assert "telemetry_events" in names
    row = db.fetchone("SELECT value FROM schema_meta WHERE key='schema_version'")
    assert row[0] == "2"
    db.close()
