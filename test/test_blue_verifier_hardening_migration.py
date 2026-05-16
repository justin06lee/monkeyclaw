"""Phase 0 — migration creates the two hardening tables."""

from __future__ import annotations

from infra.database import Database

HARDENING_TABLES = {
    "patch_variant_results",
    "patch_detection_results",
}


def _table_names(db: Database) -> set[str]:
    rows = db.fetchall("SELECT name FROM sqlite_master WHERE type='table'")
    return {r["name"] for r in rows}


def test_migration_creates_hardening_tables(db: Database):
    assert HARDENING_TABLES <= _table_names(db)


def test_patch_variant_results_columns(db: Database):
    cols = {r["name"] for r in db.fetchall(
        "PRAGMA table_info(patch_variant_results)")}
    assert {"result_id", "patch_id", "vuln_id", "operator",
            "variant_hash", "blocked", "judge_verdict"} <= cols


def test_patch_detection_results_columns(db: Database):
    cols = {r["name"] for r in db.fetchall(
        "PRAGMA table_info(patch_detection_results)")}
    assert {"result_id", "patch_id", "vuln_id", "zone_id", "quadrant",
            "observability", "prevention", "passed", "evidence"} <= cols


def test_mcp_logs_and_reads_variant_results(server):
    from interfaces.types import VariantResult

    server.log_patch_variant_results("P1", "MC-2026-0001", [
        VariantResult(operator="paraphrase", variant_hash="h1",
                      blocked=True, judge_verdict="blocked"),
        VariantResult(operator="add_benign_framing", variant_hash="h2",
                      blocked=False, judge_verdict="confirmed"),
    ])
    rows = server.get_patch_variant_results("P1")
    assert len(rows) == 2
    assert {r["operator"] for r in rows} == {
        "paraphrase", "add_benign_framing"}


def test_mcp_logs_and_reads_detection_result(server):
    server.log_patch_detection_result(
        patch_id="P1", vuln_id="MC-2026-0001", zone_id="SBX-FS",
        quadrant="WEAK", observability="silent", prevention="blocked",
        passed=False, evidence='{"surface": "fs"}')
    rows = server.get_patch_detection_results("P1")
    assert len(rows) == 1
    assert rows[0]["quadrant"] == "WEAK" and rows[0]["passed"] == 0


def test_verify_persists_variant_and_detection_results(
    real_mcp, mock_provisioner
):
    """A full verify run writes patch_variant_results and
    patch_detection_results rows for the patch."""
    from blue_team.patch_verifier import PatchVerifier
    from interfaces.types import DetectionVerdict
    from test.test_blue_patch_verifier import (
        make_blocking_replay_factory, make_patch, make_repro_package,
        make_test_pair,
    )

    class _Oracle:
        def score(self, execution, telemetry):  # noqa: ANN001
            return [DetectionVerdict(
                execution_id="L1", session_id="S1", zone_id="SBX-FS",
                quadrant="PASS", prevention="blocked",
                observability="observed", rule_id=None, evidence="{}")]

    pkg = make_repro_package()
    patch = make_patch()
    verifier = PatchVerifier(
        real_mcp, mock_provisioner,
        patched_replay_factory=make_blocking_replay_factory(),
        detection_oracle=_Oracle())
    verifier.verify(patch=patch, package=pkg,
                    test_pair=make_test_pair(pkg))
    assert real_mcp.get_patch_variant_results(patch.patch_id)
    assert real_mcp.get_patch_detection_results(patch.patch_id)
