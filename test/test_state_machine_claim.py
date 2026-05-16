"""claim_next_repro — priority order, concurrency, processing invisibility."""

from __future__ import annotations

import sqlite3
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


def test_contending_claims_never_return_the_same_row(tmp_path) -> None:
    """Genuine contention: each worker thread drives its OWN `Database`
    (its own SQLite connection on the shared file), so the threads really
    race on `BEGIN IMMEDIATE` rather than serializing behind one
    process-wide RLock. Every queued row must be claimed exactly once.

    This is the cross-connection / cross-process guarantee. Within a
    single `Database`, claims also serialize behind that instance's lock
    (see `claim_next_repro`'s docstring) — but that path can't be
    exercised by threads sharing one connection, so this test stands up
    independent connections to prove the SQLite-level invariant."""
    seed = _db_with_queue(
        tmp_path, [(f"F{i}", "high") for i in range(20)])
    seed.close()
    db_path = tmp_path / "claim.db"

    claimed: list[str] = []
    lock = threading.Lock()

    def worker(name: str) -> None:
        # A fresh Database per worker == a fresh connection genuinely
        # contending for the BEGIN IMMEDIATE write lock on the file.
        db = Database(db_path)
        try:
            engine = TransitionEngine(db)
            while True:
                try:
                    fid = engine.claim_next_repro(name)
                except sqlite3.OperationalError:
                    # 'database is locked' — a peer holds the write lock;
                    # back off and retry, the row is still claimable.
                    continue
                if fid is None:
                    return
                with lock:
                    claimed.append(fid)
        finally:
            db.close()

    threads = [threading.Thread(target=worker, args=(f"w{i}",))
               for i in range(4)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert sorted(claimed) == sorted(f"F{i}" for i in range(20))
    assert len(claimed) == len(set(claimed))
