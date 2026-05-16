"""Migration runner — discovery, application, idempotency, failure."""

from __future__ import annotations

from pathlib import Path

import pytest

from infra.migrations import (
    MIGRATIONS_DIR,
    Migration,
    MigrationError,
    applied_set,
    discover,
    run_pending,
)


def test_discover_returns_sequential_sorted_migrations() -> None:
    migs = discover(MIGRATIONS_DIR)
    assert [m.ordinal for m in migs] == list(range(1, len(migs) + 1))
    assert migs[0].name == "0001_baseline.sql"
    assert all(isinstance(m, Migration) for m in migs)


def test_discover_rejects_malformed_filename(tmp_path: Path) -> None:
    (tmp_path / "not_a_migration.sql").write_text("SELECT 1;")
    with pytest.raises(MigrationError, match="malformed"):
        discover(tmp_path)


def test_discover_rejects_non_sequential_ordinals(tmp_path: Path) -> None:
    (tmp_path / "0001_a.sql").write_text("SELECT 1;")
    (tmp_path / "0003_c.sql").write_text("SELECT 1;")
    with pytest.raises(MigrationError, match="non-sequential"):
        discover(tmp_path)


def _empty_db(tmp_path: Path):
    from infra.database import Database
    return Database(tmp_path / "mig.db")


def test_run_pending_applies_full_set_then_is_idempotent(tmp_path: Path) -> None:
    db = _empty_db(tmp_path)
    try:
        # Database.__init__ already ran run_pending — a second call is a no-op.
        second = run_pending(db.conn)
        assert second == []
        assert applied_set(db.conn) == {
            m.ordinal for m in discover(MIGRATIONS_DIR)
        }
    finally:
        db.close()


def test_run_pending_on_bare_conn_applies_everything(tmp_path: Path) -> None:
    from infra.database import Database
    db = Database(tmp_path / "bare.db")
    try:
        # Forget the ledger, then re-run: every migration re-applies cleanly.
        db.conn.execute("DELETE FROM schema_meta WHERE key LIKE 'migration:%'")
        applied = run_pending(db.conn)
        assert applied == [m.ordinal for m in discover(MIGRATIONS_DIR)]
    finally:
        db.close()


def test_failing_migration_raises_and_is_not_recorded(tmp_path: Path) -> None:
    db = _empty_db(tmp_path)
    try:
        bad_dir = tmp_path / "bad"
        bad_dir.mkdir()
        (bad_dir / "0001_baseline.sql").write_text("SELECT 1;")
        (bad_dir / "0002_boom.sql").write_text(
            "CREATE TABLE ok_tbl(x);\nINSERT INTO nonexistent_tbl VALUES(1);")
        db.conn.execute("DELETE FROM schema_meta WHERE key LIKE 'migration:%'")
        db.conn.execute(
            "INSERT INTO schema_meta(key,value) VALUES('migration:0001','x')")
        with pytest.raises(MigrationError, match="0002_boom"):
            run_pending(db.conn, bad_dir)
        assert 2 not in applied_set(db.conn)
    finally:
        db.close()
