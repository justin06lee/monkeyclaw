"""claim_next_repro — priority order, concurrency, processing invisibility."""

from __future__ import annotations

import threading

from infra.database import Database
from infra.state_machine import TransitionEngine


def _db_with_queue(tmp_path, rows):
    db = Database(tmp_path / "claim.db")
    db.execute("INSERT INTO surface_zones(zone_id, name, description) "
               "VALUES('Z','z','z')")
    for fid, prio in rows:
        db.execute(
            "INSERT INTO findings(finding_id, cycle_id, idea_id, zone_id, "
            "source_mode, idea_summary, verdict, tier_caught, failure_class, "
            "severity, evidence) VALUES(?,1,'I','Z','creative','s',"
            "'confirmed','programmatic','none','high','[]')", (fid,))
        db.execute("INSERT INTO repro_queue(finding_id, priority, status) "
                   "VALUES(?,?,'queued')", (fid, prio))
    return db


def test_claim_returns_highest_priority_row(tmp_path) -> None:
    db = _db_with_queue(tmp_path, [("LO", "low"), ("HI", "high")])
    try:
        engine = TransitionEngine(db)
        assert engine.claim_next_repro("w1") == "HI"
        row = db.fetchone(
            "SELECT status FROM repro_queue WHERE finding_id='HI'")
        assert row["status"] == "processing"
        # The audit row was written.
        assert db.fetchone(
            "SELECT 1 FROM queue_transitions WHERE entity_id='HI' "
            "AND to_state='processing'") is not None
    finally:
        db.close()


def test_claim_on_empty_queue_returns_none(tmp_path) -> None:
    db = _db_with_queue(tmp_path, [])
    try:
        assert TransitionEngine(db).claim_next_repro("w1") is None
    finally:
        db.close()


def test_processing_row_is_invisible_to_claims(tmp_path) -> None:
    db = _db_with_queue(tmp_path, [("ONLY", "high")])
    try:
        engine = TransitionEngine(db)
        assert engine.claim_next_repro("w1") == "ONLY"
        assert engine.claim_next_repro("w2") is None
    finally:
        db.close()


def test_concurrent_claims_never_return_the_same_row(tmp_path) -> None:
    db = _db_with_queue(
        tmp_path, [(f"F{i}", "high") for i in range(20)])
    try:
        engine = TransitionEngine(db)
        claimed: list[str] = []
        lock = threading.Lock()

        def worker(name: str) -> None:
            while True:
                fid = engine.claim_next_repro(name)
                if fid is None:
                    return
                with lock:
                    claimed.append(fid)

        threads = [threading.Thread(target=worker, args=(f"w{i}",))
                   for i in range(4)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        assert sorted(claimed) == sorted(f"F{i}" for i in range(20))
        assert len(claimed) == len(set(claimed))
    finally:
        db.close()
