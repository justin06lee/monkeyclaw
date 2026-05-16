"""Phase 0 — migration 0005 adds idea_archive_cells.niche_descriptors."""

from __future__ import annotations

from infra.database import Database


def _columns(db: Database, table: str) -> set[str]:
    return {r["name"] for r in db.fetchall(f"PRAGMA table_info({table})")}


def test_niche_descriptors_column_exists(tmp_path):
    db = Database(str(tmp_path / "mc.db"))
    try:
        assert "niche_descriptors" in _columns(db, "idea_archive_cells")
    finally:
        db.close()


def test_niche_descriptors_defaults_to_empty_object(tmp_path):
    db = Database(str(tmp_path / "mc.db"))
    try:
        db.execute(
            "INSERT INTO idea_archive_cells"
            "(cell_id, zone_id, interaction_style, response_movement) "
            "VALUES('C1', 'SBX-FS', 'direct', 'refusal')"
        )
        row = db.fetchone(
            "SELECT niche_descriptors FROM idea_archive_cells WHERE cell_id='C1'"
        )
        assert row["niche_descriptors"] == "{}"
    finally:
        db.close()


def test_migration_0005_recorded_in_schema_meta(tmp_path):
    db = Database(str(tmp_path / "mc.db"))
    try:
        rows = db.fetchall(
            "SELECT key FROM schema_meta WHERE key LIKE 'migration:%'"
        )
        assert "migration:0005" in {r["key"] for r in rows}
    finally:
        db.close()
