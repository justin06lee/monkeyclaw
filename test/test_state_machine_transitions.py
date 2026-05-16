"""State machine — FSM declarations + transition engine."""

from __future__ import annotations

import pytest

from infra.state_machine import (
    FINDING_FSM,
    IllegalTransition,
    PATCH_FSM,
    REGRESSION_FSM,
    REPRO_PKG_FSM,
    REPRO_QUEUE_FSM,
    StaleTransition,
    TransitionEngine,
)

ALL_FSMS = {
    "repro_queue": REPRO_QUEUE_FSM,
    "repro_package": REPRO_PKG_FSM,
    "finding": FINDING_FSM,
    "patch": PATCH_FSM,
    "regression_test": REGRESSION_FSM,
}


@pytest.mark.parametrize("name,fsm", ALL_FSMS.items())
def test_fsm_next_states_are_declared_states(name: str, fsm: dict) -> None:
    states = set(fsm)
    for state, nexts in fsm.items():
        for nxt in nexts:
            assert nxt in states, f"{name}: {state}->{nxt} not a declared state"


def test_repro_queue_has_requeue_recovery_edge() -> None:
    assert "queued" in REPRO_QUEUE_FSM["processing"]


def test_repro_pkg_has_stuck_terminal() -> None:
    assert REPRO_PKG_FSM["stuck"] == frozenset()
    assert "stuck" in REPRO_PKG_FSM["patching"]


def test_finding_has_reopen_edge() -> None:
    assert "open" in FINDING_FSM["verified"]


def _seed_db(tmp_path):
    from infra.database import Database
    db = Database(tmp_path / "sm.db")
    db.execute("INSERT INTO surface_zones(zone_id, name, description) "
               "VALUES('Z', 'z', 'z')")
    db.execute(
        "INSERT INTO findings(finding_id, cycle_id, idea_id, zone_id, "
        "source_mode, idea_summary, verdict, tier_caught, failure_class, "
        "severity, evidence) VALUES('F1', 1, 'I1', 'Z', 'creative', 's', "
        "'confirmed', 'programmatic', 'none', 'high', '[]')")
    db.execute("INSERT INTO repro_queue(finding_id, priority, status) "
               "VALUES('F1', 'high', 'queued')")
    db.execute(
        "INSERT INTO repro_packages(package_id, finding_id, vuln_id, title, "
        "severity, repro_rate, minimal_steps, affected_zone, ideas_used, "
        "transcripts, suggested_mitigations, repro_document_md) "
        "VALUES('P1', 'F1', 'MC-1', 't', 'high', 1.0, '[]', 'Z', '[]', "
        "'{}', '[]', 'md')")
    db.execute(
        "INSERT INTO patches(patch_id, vuln_ids, zone_id, approach, diff, "
        "explanation) VALUES('PT1', '[]', 'Z', 'a', 'd', 'e')")
    db.execute(
        "INSERT INTO regression_tests(test_id, vuln_id, zone_id, "
        "test_script, expected_result) "
        "VALUES('RT1', 'MC-1', 'Z', 's', 'blocked')")
    return db


# (entity, entity_id, from_state, to_state) — one legal edge per FSM.
LEGAL_EDGES = [
    ("repro_queue", "F1", "queued", "processing"),
    ("repro_package", "P1", "queued", "triaged"),
    ("finding", "F1", "open", "in_progress"),
    ("patch", "PT1", "proposed", "testing"),
    ("regression_test", "RT1", "untested", "passing"),
]

# (entity, entity_id, illegal_to_state) — one illegal edge per FSM.
ILLEGAL_EDGES = [
    ("repro_queue", "F1", "completed"),     # queued cannot jump to completed
    ("repro_package", "P1", "verified"),    # queued cannot jump to verified
    ("finding", "F1", "verified"),          # open cannot jump to verified
    ("patch", "PT1", "approved"),           # proposed cannot jump to approved
    ("regression_test", "RT1", "quarantined"),  # untested cannot quarantine
]


@pytest.mark.parametrize("entity,eid,_from,to", LEGAL_EDGES)
def test_legal_edge_succeeds_and_writes_one_audit_row(
    tmp_path, entity, eid, _from, to,
) -> None:
    db = _seed_db(tmp_path)
    try:
        engine = TransitionEngine(db)
        assert engine.transition(
            entity=entity, entity_id=eid, to_state=to, actor="test") == to
        rows = db.fetchall(
            "SELECT from_state, to_state FROM queue_transitions "
            "WHERE entity=? AND entity_id=?", (entity, eid))
        assert len(rows) == 1
        assert rows[0]["from_state"] == _from
        assert rows[0]["to_state"] == to
    finally:
        db.close()


@pytest.mark.parametrize("entity,eid,bad_to", ILLEGAL_EDGES)
def test_illegal_edge_raises_and_writes_nothing(
    tmp_path, entity, eid, bad_to,
) -> None:
    db = _seed_db(tmp_path)
    try:
        engine = TransitionEngine(db)
        with pytest.raises(IllegalTransition):
            engine.transition(
                entity=entity, entity_id=eid, to_state=bad_to, actor="test")
        rows = db.fetchall(
            "SELECT 1 FROM queue_transitions WHERE entity=? AND entity_id=?",
            (entity, eid))
        assert rows == []
    finally:
        db.close()


def test_missing_row_raises_keyerror(tmp_path) -> None:
    db = _seed_db(tmp_path)
    try:
        engine = TransitionEngine(db)
        with pytest.raises(KeyError):
            engine.transition(entity="finding", entity_id="NOPE",
                              to_state="in_progress", actor="test")
    finally:
        db.close()


def test_expected_from_mismatch_raises_stale(tmp_path) -> None:
    db = _seed_db(tmp_path)
    try:
        engine = TransitionEngine(db)
        with pytest.raises(StaleTransition):
            engine.transition(entity="repro_queue", entity_id="F1",
                              to_state="processing", actor="test",
                              expected_from="processing")
    finally:
        db.close()


def test_transition_is_atomic_on_audit_insert_failure(tmp_path) -> None:
    """Force the audit INSERT to fail; the status UPDATE must roll back too."""
    db = _seed_db(tmp_path)
    try:
        engine = TransitionEngine(db)
        # Drop the audit table so the INSERT raises mid-transition.
        db.execute("DROP TABLE queue_transitions")
        with pytest.raises(Exception):  # noqa: B017, PT011
            engine.transition(entity="finding", entity_id="F1",
                              to_state="in_progress", actor="test")
        # Status must be unchanged — neither write landed.
        row = db.fetchone(
            "SELECT patch_status FROM findings WHERE finding_id='F1'")
        assert row["patch_status"] == "open"
    finally:
        db.close()
