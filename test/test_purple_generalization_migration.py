"""Phase 0 — patch-generalization-loop migration."""

from __future__ import annotations

from infra.database import Database


def _table_names(db: Database) -> set[str]:
    rows = db.fetchall("SELECT name FROM sqlite_master WHERE type='table'")
    return {r["name"] for r in rows}


def test_migration_creates_generalization_rounds(db: Database):
    assert "generalization_rounds" in _table_names(db)


def test_generalization_rounds_has_the_round_columns(db: Database):
    cols = {r["name"] for r in db.fetchall(
        "PRAGMA table_info(generalization_rounds)")}
    assert {"round_id", "patch_id", "finding_id", "vuln_id", "zone_id",
            "round_index", "operators_tried", "variants_total",
            "variants_bypassed", "variants_inconclusive", "bypass_operators",
            "outcome", "repatch_patch_id", "evidence", "created_at"} <= cols


def test_mcp_logs_generalization_round_and_assigns_id(server):
    from interfaces.types import GeneralizationRoundInput

    rid = server.log_generalization_round(GeneralizationRoundInput(
        patch_id="P1", finding_id="F1", vuln_id="MC-2026-0001",
        zone_id="PROMPT-INJ", round_index=0,
        operators_tried=["paraphrase", "add_benign_framing"],
        variants_total=2, variants_bypassed=1, variants_inconclusive=0,
        bypass_operators=["paraphrase"], outcome="bounced",
        repatch_patch_id="P2",
        evidence=[{"variant_id": "V1", "status": "bypassed"}]))
    assert rid.startswith("GR")


def test_logged_generalization_round_persists_json_fields(server, db):
    from interfaces.types import GeneralizationRoundInput

    server.log_generalization_round(GeneralizationRoundInput(
        patch_id="P1", finding_id="F2", vuln_id="MC-2026-0002",
        zone_id="SBX-NET", round_index=1,
        operators_tried=["paraphrase"], variants_total=1,
        variants_bypassed=0, variants_inconclusive=0,
        bypass_operators=[], outcome="generalized"))
    row = db.fetchone(
        "SELECT * FROM generalization_rounds WHERE finding_id='F2'")
    assert row["outcome"] == "generalized"
    assert row["operators_tried"] == '["paraphrase"]'
