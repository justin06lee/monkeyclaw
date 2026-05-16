"""sweep_stale_claims — stranded rows requeued, fresh claims left alone."""

from __future__ import annotations

from infra.database import Database
from infra.state_machine import TransitionEngine


def _db_with_processing(tmp_path, dequeued_sql_expr: str):
    db = Database(tmp_path / "sweep.db")
    db.execute("INSERT INTO surface_zones(zone_id, name, description) "
               "VALUES('Z','z','z')")
    db.execute(
        "INSERT INTO findings(finding_id, cycle_id, idea_id, zone_id, "
        "source_mode, idea_summary, verdict, tier_caught, failure_class, "
        "severity, evidence) VALUES('F1',1,'I','Z','creative','s',"
        "'confirmed','programmatic','none','high','[]')")
    db.execute(
        f"INSERT INTO repro_queue(finding_id, priority, status, dequeued_at, "
        f"worker_id) VALUES('F1','high','processing',{dequeued_sql_expr},'w1')")
    return db


def test_stale_processing_row_is_requeued(tmp_path) -> None:
    db = _db_with_processing(tmp_path, "datetime('now', '-3600 seconds')")
    try:
        engine = TransitionEngine(db)
        assert engine.sweep_stale_claims(older_than_seconds=600) == 1
        row = db.fetchone(
            "SELECT status FROM repro_queue WHERE finding_id='F1'")
        assert row["status"] == "queued"
        # The requeue is audited with actor='sweep'.
        assert db.fetchone(
            "SELECT 1 FROM queue_transitions WHERE entity_id='F1' "
            "AND to_state='queued' AND actor='sweep'") is not None
    finally:
        db.close()


def test_fresh_processing_row_is_left_alone(tmp_path) -> None:
    db = _db_with_processing(tmp_path, "datetime('now')")
    try:
        engine = TransitionEngine(db)
        assert engine.sweep_stale_claims(older_than_seconds=600) == 0
        row = db.fetchone(
            "SELECT status FROM repro_queue WHERE finding_id='F1'")
        assert row["status"] == "processing"
    finally:
        db.close()
