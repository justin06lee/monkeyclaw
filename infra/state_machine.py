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
from collections.abc import Iterator
from contextlib import contextmanager

from infra.database import Database

LOG = logging.getLogger("monkeyclaw.state_machine")


def new_transition_id() -> str:
    """A fresh `TR-` prefixed id for a queue_transitions audit row.

    Single source of truth — every audit-row insert (transition(),
    claim_next_repro(), push_to_repro_queue()) uses this so the id format
    can never drift between call sites.
    """
    return f"TR-{uuid.uuid4().hex[:12]}"


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
    IMMEDIATE block — a reader never sees one without the other.

    Multi-step atomicity: when several transitions (and possibly some
    plain SQL) must commit or roll back together, use `atomic()` — it
    opens one BEGIN IMMEDIATE and yields a bound engine whose
    `transition()` runs *inside* that same transaction rather than
    starting its own. This keeps the FSM validation + audit row on a
    single code path (`_apply_transition`) regardless of who owns the
    surrounding transaction.
    """

    def __init__(self, db: Database) -> None:
        self.db = db

    def _spec(self, entity: str) -> _EntitySpec:
        spec = _REGISTRY.get(entity)
        if spec is None:
            raise IllegalTransition(f"unknown entity {entity!r}")
        return spec

    def _rollback_quietly(self) -> None:
        """ROLLBACK, swallowing 'no transaction is active' — used on the
        error path where BEGIN IMMEDIATE itself may have failed (e.g. a
        contending writer raised 'database is locked')."""
        try:
            self.db.execute("ROLLBACK")
        except Exception:  # noqa: BLE001
            pass

    def _apply_transition(
        self,
        *,
        entity: str,
        entity_id: str,
        to_state: str,
        actor: str,
        reason: str,
        expected_from: str | None,
    ) -> str:
        """The single validate+UPDATE+audit code path. Assumes a
        transaction is already open and the db lock is already held; it
        issues no BEGIN/COMMIT/ROLLBACK. Both `transition()` (own
        transaction) and `atomic()` (caller's transaction) route through
        here, so FSM enforcement can never be bypassed."""
        spec = self._spec(entity)
        row = self.db.fetchone(
            f"SELECT {spec.status_column} AS s FROM {spec.table} "
            f"WHERE {spec.id_column} = ?",
            (entity_id,),
        )
        if row is None:
            raise KeyError(f"{entity} {entity_id!r} does not exist")
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
            (new_transition_id(), entity, entity_id,
             current, to_state, actor, reason),
        )
        return to_state

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
        (missing row).

        This call owns its transaction: it opens its own BEGIN IMMEDIATE.
        It must NOT be invoked while a transaction is already open on the
        connection — its `except` ROLLBACK would unwind that outer
        transaction. The guard below asserts this; callers that need to
        compose several transitions in one transaction must use
        `atomic()` instead."""
        with self.db.lock():
            # Footgun guard: an outer BEGIN here would mean our ROLLBACK
            # silently discards the caller's in-flight work. Composing
            # transitions is supported only via atomic().
            assert not self.db.conn.in_transaction, (
                "TransitionEngine.transition() called inside an open "
                "transaction; use TransitionEngine.atomic() to compose "
                "multiple transitions atomically")
            self.db.execute("BEGIN IMMEDIATE")
            try:
                result = self._apply_transition(
                    entity=entity, entity_id=entity_id, to_state=to_state,
                    actor=actor, reason=reason, expected_from=expected_from,
                )
                self.db.execute("COMMIT")
            except Exception:
                self._rollback_quietly()
                raise
        return result

    @contextmanager
    def atomic(self) -> Iterator[_BoundEngine]:
        """Open one BEGIN IMMEDIATE and yield a bound engine that runs
        every transition() and execute() inside it. The whole block
        commits on clean exit and rolls back on any exception — the only
        supported way to make several transitions (plus arbitrary SQL)
        one atomic unit. FSM validation still runs per transition via the
        shared `_apply_transition` path."""
        with self.db.lock():
            assert not self.db.conn.in_transaction, (
                "TransitionEngine.atomic() called inside an open "
                "transaction")
            self.db.execute("BEGIN IMMEDIATE")
            try:
                yield _BoundEngine(self)
                self.db.execute("COMMIT")
            except Exception:
                self._rollback_quietly()
                raise

    def claim_next_repro(self, worker_id: str) -> str | None:
        """Atomic queued->processing claim of the highest-priority repro_queue
        row. Returns the finding_id, or None if the queue is empty. The claim
        and its audit row are written together inside one BEGIN IMMEDIATE.

        Concurrency model: `Database` serves all callers through a single
        SQLite connection guarded by one process-wide RLock, so concurrent
        claim_next_repro() calls are serialized — each runs its full
        SELECT-then-UPDATE under the lock before the next begins. Two
        callers therefore can never observe the same 'queued' row. The
        BEGIN IMMEDIATE additionally guards cross-process contention
        against a second `Database`/process on the same file."""
        with self.db.lock():
            assert not self.db.conn.in_transaction, (
                "claim_next_repro() called inside an open transaction")
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
                    (new_transition_id(), "repro_queue", fid,
                     "queued", "processing", worker_id, "claim"),
                )
                self.db.execute("COMMIT")
            except Exception:
                self._rollback_quietly()
                raise
        return fid

    def store_repro_package(
        self,
        *,
        insert_sql: str,
        insert_params: tuple,
        finding_id: str,
        finding_repro_rate: float,
        package_id: str,
    ) -> None:
        """Persist a repro package and run both lifecycle transitions —
        repro_queue ->completed and finding ->in_progress — as one atomic
        unit. The package INSERT, the findings.repro_rate UPDATE and both
        audited transitions commit or roll back together inside a single
        BEGIN IMMEDIATE; a crash mid-way leaves no partial state."""
        with self.atomic() as tx:
            tx.execute(insert_sql, insert_params)
            tx.execute(
                "UPDATE findings SET repro_rate = ? WHERE finding_id = ?",
                (finding_repro_rate, finding_id),
            )
            tx.transition(
                entity="repro_queue", entity_id=finding_id,
                to_state="completed", actor="repro_pipeline",
                reason=f"package {package_id}",
            )
            tx.transition(
                entity="finding", entity_id=finding_id,
                to_state="in_progress", actor="repro_pipeline",
                reason=f"package {package_id}",
            )

    def record_regression_run(
        self,
        *,
        test_id: str,
        update_sql: str,
        update_params: tuple,
        target: str,
        current: str,
        reason: str,
    ) -> None:
        """Persist a regression run's row fields and its run_state
        transition as one atomic unit. The regression_tests UPDATE
        (last_run_at/last_run_result/consecutive_passes) and the FSM
        transition commit or roll back together. A same-state run writes
        only the row UPDATE (no transition)."""
        with self.atomic() as tx:
            tx.execute(update_sql, update_params)
            if target != current:
                tx.transition(
                    entity="regression_test", entity_id=test_id,
                    to_state=target, actor="regression_runner",
                    reason=reason,
                )

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


class _BoundEngine:
    """A TransitionEngine view bound to an already-open transaction
    (opened by `TransitionEngine.atomic()`). Its `transition()` runs the
    shared FSM-validation path WITHOUT starting its own transaction, so
    several transitions and plain SQL commit/roll-back together. Yielded
    by `atomic()`; not constructed directly."""

    __slots__ = ("_engine",)

    def __init__(self, engine: TransitionEngine) -> None:
        self._engine = engine

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
        """Validate + UPDATE + audit inside the caller's open transaction."""
        return self._engine._apply_transition(
            entity=entity, entity_id=entity_id, to_state=to_state,
            actor=actor, reason=reason, expected_from=expected_from,
        )

    def execute(self, sql: str, params: tuple = ()) -> None:
        """Run arbitrary SQL inside the caller's open transaction."""
        self._engine.db.execute(sql, params)
