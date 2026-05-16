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
