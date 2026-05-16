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
