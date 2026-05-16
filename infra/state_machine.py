"""The transition engine — one path for every queue/finding/patch/regression
status mutation. Five frozen finite-state machines plus the TransitionEngine
that validates each edge and writes the status UPDATE + queue_transitions
audit row atomically inside one BEGIN IMMEDIATE block.

After this module lands, no code outside it issues a raw UPDATE ... SET status
(enforced by test_state_machine_no_raw_updates.py).
"""

from __future__ import annotations

import logging
import uuid

from infra.database import Database

LOG = logging.getLogger("monkeyclaw.state_machine")


class IllegalTransition(Exception):
    """The requested from->to edge is not in the entity's FSM."""


class StaleTransition(Exception):
    """expected_from did not match the row's current state."""


# --- FSM declarations: {state: frozenset(legal_next_states)} ---------------
# A state mapping to an empty frozenset is terminal.

REPRO_QUEUE_FSM: dict[str, frozenset[str]] = {
    "queued":     frozenset({"processing"}),
    "processing": frozenset({"completed", "failed", "queued"}),
    "completed":  frozenset(),
    "failed":     frozenset(),
}

REPRO_PKG_FSM: dict[str, frozenset[str]] = {
    "queued":   frozenset({"triaged"}),
    "triaged":  frozenset({"patching"}),
    "patching": frozenset({"verified", "stuck"}),
    "verified": frozenset(),
    "stuck":    frozenset(),
}

FINDING_FSM: dict[str, frozenset[str]] = {
    "open":        frozenset({"in_progress"}),
    "in_progress": frozenset({"patched"}),
    "patched":     frozenset({"verified"}),
    "verified":    frozenset({"open"}),
}

PATCH_FSM: dict[str, frozenset[str]] = {
    "proposed": frozenset({"testing"}),
    "testing":  frozenset({"approved", "rejected"}),
    "approved": frozenset(),
    "rejected": frozenset(),
}

REGRESSION_FSM: dict[str, frozenset[str]] = {
    "untested":    frozenset({"passing", "failing"}),
    "passing":     frozenset({"failing", "quarantined"}),
    "failing":     frozenset({"passing", "quarantined"}),
    "quarantined": frozenset({"passing", "failing"}),
}


# --- entity registry: entity name -> (table, id_column, status_column, FSM) -
class _EntitySpec:
    __slots__ = ("table", "id_column", "status_column", "fsm")

    def __init__(self, table: str, id_column: str,
                 status_column: str, fsm: dict[str, frozenset[str]]) -> None:
        self.table = table
        self.id_column = id_column
        self.status_column = status_column
        self.fsm = fsm


_REGISTRY: dict[str, _EntitySpec] = {
    "repro_queue": _EntitySpec(
        "repro_queue", "finding_id", "status", REPRO_QUEUE_FSM),
    "repro_package": _EntitySpec(
        "repro_packages", "package_id", "blue_team_status", REPRO_PKG_FSM),
    "finding": _EntitySpec(
        "findings", "finding_id", "patch_status", FINDING_FSM),
    "patch": _EntitySpec(
        "patches", "patch_id", "status", PATCH_FSM),
    "regression_test": _EntitySpec(
        "regression_tests", "test_id", "run_state", REGRESSION_FSM),
}


class TransitionEngine:
    """Routes every status mutation. transition() is atomic: the status
    UPDATE and the queue_transitions INSERT happen inside one BEGIN
    IMMEDIATE block — a reader never sees one without the other."""

    def __init__(self, db: Database) -> None:
        self.db = db

    def _spec(self, entity: str) -> _EntitySpec:
        spec = _REGISTRY.get(entity)
        if spec is None:
            raise IllegalTransition(f"unknown entity {entity!r}")
        return spec

    def transition(
        self,
        *,
        entity: str,
        entity_id: str,
        to_state: str,
        actor: str,
        reason: str = "",
        expected_from: str | None = None,
    ) -> str:
        """Atomically validate current->to_state against the FSM, UPDATE the
        status column and INSERT a queue_transitions audit row. Returns the
        new state. Raises IllegalTransition, StaleTransition, or KeyError
        (missing row)."""
        spec = self._spec(entity)
        with self.db.lock():
            self.db.execute("BEGIN IMMEDIATE")
            try:
                row = self.db.fetchone(
                    f"SELECT {spec.status_column} AS s FROM {spec.table} "
                    f"WHERE {spec.id_column} = ?",
                    (entity_id,),
                )
                if row is None:
                    raise KeyError(
                        f"{entity} {entity_id!r} does not exist")
                current = row["s"]
                if expected_from is not None and current != expected_from:
                    raise StaleTransition(
                        f"{entity} {entity_id}: expected {expected_from!r}, "
                        f"found {current!r}")
                legal = spec.fsm.get(current, frozenset())
                if to_state not in legal:
                    raise IllegalTransition(
                        f"{entity} {entity_id}: {current!r}->{to_state!r} "
                        f"not allowed (legal: {sorted(legal)})")
                self.db.execute(
                    f"UPDATE {spec.table} SET {spec.status_column} = ? "
                    f"WHERE {spec.id_column} = ?",
                    (to_state, entity_id),
                )
                self.db.execute(
                    "INSERT INTO queue_transitions(transition_id, entity, "
                    "entity_id, from_state, to_state, actor, reason) "
                    "VALUES(?,?,?,?,?,?,?)",
                    (f"TR-{uuid.uuid4().hex[:12]}", entity, entity_id,
                     current, to_state, actor, reason),
                )
                self.db.execute("COMMIT")
            except Exception:
                self.db.execute("ROLLBACK")
                raise
        return to_state

    def claim_next_repro(self, worker_id: str) -> str | None:
        """Atomic queued->processing claim of the highest-priority repro_queue
        row. Returns the finding_id, or None if the queue is empty. The claim
        and its audit row are written together inside one BEGIN IMMEDIATE."""
        with self.db.lock():
            self.db.execute("BEGIN IMMEDIATE")
            try:
                row = self.db.fetchone(
                    "SELECT finding_id FROM repro_queue "
                    "WHERE status = 'queued' "
                    "ORDER BY CASE WHEN priority='high' THEN 0 ELSE 1 END, "
                    "enqueued_at LIMIT 1"
                )
                if row is None:
                    self.db.execute("COMMIT")
                    return None
                fid = row["finding_id"]
                self.db.execute(
                    "UPDATE repro_queue SET status='processing', "
                    "dequeued_at=datetime('now'), worker_id=? "
                    "WHERE finding_id=?",
                    (worker_id, fid),
                )
                self.db.execute(
                    "INSERT INTO queue_transitions(transition_id, entity, "
                    "entity_id, from_state, to_state, actor, reason) "
                    "VALUES(?,?,?,?,?,?,?)",
                    (f"TR-{uuid.uuid4().hex[:12]}", "repro_queue", fid,
                     "queued", "processing", worker_id, "claim"),
                )
                self.db.execute("COMMIT")
            except Exception:
                self.db.execute("ROLLBACK")
                raise
        return fid

    def sweep_stale_claims(self, older_than_seconds: int) -> int:
        """Requeue repro_queue rows stuck in 'processing' past the timeout
        (the requeue recovery edge). Each requeue is audited. Returns the
        count requeued."""
        with self.db.lock():
            stale = self.db.fetchall(
                "SELECT finding_id FROM repro_queue "
                "WHERE status='processing' AND dequeued_at IS NOT NULL "
                "AND dequeued_at < datetime('now', ?)",
                (f"-{int(older_than_seconds)} seconds",),
            )
        count = 0
        for row in stale:
            try:
                self.transition(
                    entity="repro_queue", entity_id=row["finding_id"],
                    to_state="queued", actor="sweep",
                    reason="stale claim recovered",
                    expected_from="processing",
                )
                count += 1
            except StaleTransition:
                # A late worker completed it between the SELECT and here.
                continue
        return count
