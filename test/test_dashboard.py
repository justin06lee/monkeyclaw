"""Dashboard query + app tests (spec C9).

The dashboard is read-only: every function takes a db_path and returns
plain dicts/lists. We build a tiny seeded SQLite DB from the canonical
schema and assert each of the eight spec views produces the right shape.
Empty-DB behavior is also covered — the dashboard must not crash before
the first cycle runs.
"""

from __future__ import annotations

from pathlib import Path

from infra import dashboard
from infra.database import Database


# ---------------------------------------------------------------------------
# Test DB construction — the schema uses sqlite-vec vec0 tables, so we
# bootstrap through the project's Database class (loads the extension).
# ---------------------------------------------------------------------------


def _empty_db(tmp_path: Path) -> str:
    db_path = str(tmp_path / "empty.db")
    Database(db_path).close()
    return db_path


def _seeded_db(tmp_path: Path) -> str:
    db_path = str(tmp_path / "seeded.db")
    conn = Database(db_path)
    # one cycle
    conn.execute(
        "INSERT INTO cycle_log(cycle_id, summary, zones_targeted, "
        "ideas_generated, ideas_deduplicated, ideas_executed, "
        "vulns_confirmed, vulns_suspicious, total_tokens_used) "
        "VALUES (1, 'cycle one', '[\"SBX-FS\"]', 6, 2, 4, 1, 1, 48000)"
    )
    # ideas
    for i, mode in enumerate(["creative", "code_grounded", "creative"]):
        conn.execute(
            "INSERT INTO ideas(idea_id, cycle_id, zone_id, source_mode, "
            "title, approach, success_criteria, deduplicated) "
            "VALUES (?, 1, 'SBX-FS', ?, ?, 'a', 's', ?)",
            (f"IDEA-{i}", mode, f"idea {i}", 1 if i == 2 else 0),
        )
    # findings
    conn.execute(
        "INSERT INTO findings(finding_id, cycle_id, idea_id, zone_id, "
        "source_mode, idea_summary, verdict, tier_caught, failure_class, "
        "severity, evidence, repro_rate, patch_status) VALUES "
        "('FND-1', 1, 'IDEA-0', 'SBX-FS', 'creative', 'symlink escape', "
        "'confirmed', 'programmatic', 'sandbox_escape', 'critical', "
        "'[{\"check_name\": \"filesystem_breach\", \"triggered\": true, "
        "\"severity\": \"critical\", \"evidence\": {\"path\": \"/etc\"}}]', "
        "1.0, 'verified')"
    )
    conn.execute(
        "INSERT INTO findings(finding_id, cycle_id, idea_id, zone_id, "
        "source_mode, idea_summary, verdict, tier_caught, failure_class, "
        "severity, evidence, repro_rate, patch_status) VALUES "
        "('FND-2', 1, 'IDEA-1', 'SBX-FS', 'code_grounded', 'maybe leak', "
        "'suspicious', 'semantic', 'information_disclosure', 'medium', "
        "'[]', 0.4, 'open')"
    )
    # repro package
    conn.execute(
        "INSERT INTO repro_packages(package_id, finding_id, vuln_id, title, "
        "severity, repro_rate, minimal_steps, affected_zone, affected_paths, "
        "ideas_used, transcripts, suggested_mitigations, repro_document_md, "
        "cold_verified, ready_for_blue, blue_team_status) VALUES "
        "('PKG-1', 'FND-1', 'MC-2026-0001', 'symlink escape', 'critical', "
        "1.0, '[{\"step_number\": 1}]', 'SBX-FS', "
        "'[{\"file\": \"src/sandbox/create.ts\"}]', '[\"IDEA-0\"]', '{}', "
        "'[\"canonicalize\"]', '(doc)', 1, 1, 'verified')"
    )
    # patch
    conn.execute(
        "INSERT INTO patches(patch_id, vuln_ids, zone_id, approach, "
        "invasiveness, diff, explanation, side_effects, status) VALUES "
        "('PCH-1', '[\"MC-2026-0001\"]', 'SBX-FS', 'canonicalize', 'low', "
        "'--- a', 'resolves symlinks', 'none', 'approved')"
    )
    # regression tests
    conn.execute(
        "INSERT INTO regression_tests(test_id, vuln_id, zone_id, "
        "test_script, expected_result, last_run_result, consecutive_passes) "
        "VALUES ('RT-1', 'MC-2026-0001', 'SBX-FS', 'x', "
        "'vulnerability_blocked', 'pass', 3)"
    )
    conn.execute(
        "INSERT INTO regression_tests(test_id, vuln_id, zone_id, "
        "test_script, expected_result, last_run_result, consecutive_passes) "
        "VALUES ('RT-2', 'MC-2026-0002', 'SBX-NET', 'x', "
        "'vulnerability_blocked', 'fail', 0)"
    )
    conn.execute(
        "UPDATE surface_zones SET coverage_score = 0.5, vulns_open = 1, "
        "vulns_found = 2, last_tested_at = '2026-05-15T00:00:00Z' "
        "WHERE zone_id = 'SBX-FS'"
    )
    conn.execute(
        "INSERT INTO alerts(message, severity, channel, delivered) "
        "VALUES ('critical finding in SBX-FS', 'critical', 'telegram', 1)"
    )
    conn.close()
    return db_path


# ---------------------------------------------------------------------------
# View 1 — Overview
# ---------------------------------------------------------------------------


def test_overview_reports_headline_stats(tmp_path: Path):
    ov = dashboard._overview(_seeded_db(tmp_path))
    assert ov["cycles"] == 1
    assert ov["findings_confirmed"] == 1
    assert ov["findings_suspicious"] == 1
    assert ov["patches_verified"] == 1
    # one of two regression tests passes
    assert ov["regression_pass_rate"] == 0.5
    assert 0.0 < ov["mean_coverage"] < 1.0


def test_overview_empty_db(tmp_path: Path):
    ov = dashboard._overview(_empty_db(tmp_path))
    assert ov["cycles"] == 0
    assert ov["findings_confirmed"] == 0
    assert ov["regression_pass_rate"] == 0.0


# ---------------------------------------------------------------------------
# View 3 — Finding timeline
# ---------------------------------------------------------------------------


def test_finding_timeline_carries_lifecycle_status(tmp_path: Path):
    rows = dashboard._finding_timeline(_seeded_db(tmp_path))
    assert len(rows) == 2
    by_id = {r["finding_id"]: r for r in rows}
    assert by_id["FND-1"]["patch_status"] == "verified"
    assert by_id["FND-1"]["repro_status"] == "verified"
    assert by_id["FND-1"]["evidence_count"] == 1


# ---------------------------------------------------------------------------
# View 4 — Repro package view
# ---------------------------------------------------------------------------


def test_repro_packages_view(tmp_path: Path):
    rows = dashboard._repro_packages(_seeded_db(tmp_path))
    assert len(rows) == 1
    pkg = rows[0]
    assert pkg["vuln_id"] == "MC-2026-0001"
    assert pkg["cold_verified"] is True
    assert pkg["step_count"] == 1
    assert pkg["affected_path_count"] == 1


# ---------------------------------------------------------------------------
# View 5 — Blue team view
# ---------------------------------------------------------------------------


def test_blue_team_view(tmp_path: Path):
    bt = dashboard._blue_team(_seeded_db(tmp_path))
    assert len(bt["patches"]) == 1
    assert bt["patches"][0]["status"] == "approved"
    assert len(bt["regression_tests"]) == 2


# ---------------------------------------------------------------------------
# View 6 — Evidence timeline
# ---------------------------------------------------------------------------


def test_evidence_timeline_surfaces_triggered_checks(tmp_path: Path):
    rows = dashboard._evidence_timeline(_seeded_db(tmp_path))
    # one triggered check from FND-1 + one alert
    kinds = {r["kind"] for r in rows}
    assert "check" in kinds
    assert "alert" in kinds


# ---------------------------------------------------------------------------
# View 7 — Search intelligence
# ---------------------------------------------------------------------------


def test_search_intelligence_summarizes_ideation(tmp_path: Path):
    si = dashboard._search_intel(_seeded_db(tmp_path))
    assert si["cells_explored"] >= 1  # zones with ideas
    assert si["source_modes"]["creative"] == 2
    assert si["dedup_rate"] > 0.0
    assert si["tier_breakdown"]["programmatic"] == 1


# ---------------------------------------------------------------------------
# View 8 — Cost / model stats
# ---------------------------------------------------------------------------


def test_cost_stats(tmp_path: Path):
    cs = dashboard._cost_stats(_seeded_db(tmp_path))
    assert cs["total_tokens"] == 48000
    assert cs["cost_estimate_usd"] >= 0.0
    assert cs["verdict_breakdown"]["confirmed"] == 1


# ---------------------------------------------------------------------------
# App builder — endpoints exist, empty DB does not crash
# ---------------------------------------------------------------------------


def test_dashboard_app_serves_all_endpoints(tmp_path: Path):
    from fastapi.testclient import TestClient

    app = dashboard.build_dashboard_app(_seeded_db(tmp_path))
    client = TestClient(app)
    assert client.get("/").status_code == 200
    for ep in ["overview", "zones", "finding-timeline", "repro-packages",
               "blue-team", "evidence-timeline", "search-intel",
               "cost-stats"]:
        resp = client.get(f"/api/{ep}")
        assert resp.status_code == 200, ep


def test_dashboard_app_empty_db_ok(tmp_path: Path):
    from fastapi.testclient import TestClient

    app = dashboard.build_dashboard_app(_empty_db(tmp_path))
    client = TestClient(app)
    assert client.get("/").status_code == 200
    assert client.get("/api/overview").status_code == 200
