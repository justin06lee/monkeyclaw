"""State machine — FSM declarations + transition engine."""

from __future__ import annotations

import pytest

from infra.state_machine import (
    FINDING_FSM,
    PATCH_FSM,
    REGRESSION_FSM,
    REPRO_PKG_FSM,
    REPRO_QUEUE_FSM,
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
