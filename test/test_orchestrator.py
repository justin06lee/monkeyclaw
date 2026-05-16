"""End-to-end smoke: run two orchestrator cycles with the mock provisioner
and the stub red/blue pipelines. Verifies the entire infra plumbing works
without depending on Persons 2 and 3."""

from __future__ import annotations

import sqlite3
from pathlib import Path

from infra.orchestrator import main as orch_main


def test_orchestrator_runs_two_cycles(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("MC_STORAGE__DB_PATH", str(tmp_path / "mc.db"))
    monkeypatch.setenv("MC_LOGGING__FILE", str(tmp_path / "mc.log"))
    monkeypatch.setenv("MC_LANES__POOL_SIZE", "2")
    monkeypatch.setenv("MC_LANES__LANE_TIMEOUT_SECONDS", "5")
    rc = orch_main(["--use-mock-provisioner", "--max-cycles", "2"])
    assert rc == 0
    # Mock-provisioner runs use a separate `-mock` database so they never
    # touch the real knowledge base.
    conn = sqlite3.connect((tmp_path / "mc-mock.db").as_posix())
    rows = conn.execute("SELECT cycle_id, ideas_generated FROM cycle_log").fetchall()
    conn.close()
    assert len(rows) >= 2
    # Each cycle generated pool_size=2 ideas
    assert all(r[1] == 2 for r in rows)


# ---------------------------------------------------------------------------
# Task 20 — orchestrator reliability hardening
# ---------------------------------------------------------------------------

from infra.orchestrator import StubRedTeam  # noqa: E402


class FlakyRed(StubRedTeam):
    """Red pipeline whose lane execution raises for exactly one lane.

    Loadable via ``--red test.test_orchestrator:FlakyRed`` (no-arg ctor, so
    ``_load_pipeline`` instantiates it as ``cls()``). Used to prove that a
    single lane failure does not abort the cycle.
    """

    def execute_lane(self, idea, victim, harness, lane_cfg) -> None:
        # Fail the first lane of every cycle; succeed for the rest.
        if idea.idea_id.endswith("-0"):
            raise RuntimeError("planted lane failure")
        super().execute_lane(idea, victim, harness, lane_cfg)


def _cycle_log_rows(db_path: Path) -> list[tuple]:
    conn = sqlite3.connect(db_path.as_posix())
    try:
        return conn.execute(
            "SELECT cycle_id FROM cycle_log ORDER BY cycle_id"
        ).fetchall()
    finally:
        conn.close()


def test_orchestrator_continues_when_one_lane_fails(tmp_path: Path, monkeypatch):
    """A planted exception in one lane must NOT abort the cycle, and a cycle
    summary must still be written."""
    db_path = tmp_path / "mc.db"
    monkeypatch.setenv("MC_STORAGE__DB_PATH", str(db_path))
    monkeypatch.setenv("MC_LOGGING__FILE", str(tmp_path / "mc.log"))
    monkeypatch.setenv("MC_LANES__POOL_SIZE", "2")
    monkeypatch.setenv("MC_LANES__LANE_TIMEOUT_SECONDS", "5")

    # Should not raise even though one lane per cycle fails.
    rc = orch_main([
        "--use-mock-provisioner",
        "--max-cycles", "1",
        "--red", "test.test_orchestrator:FlakyRed",
    ])
    assert rc == 0

    # The cycle summary was still written despite the lane failure.
    # Mock-provisioner runs write to a separate `-mock` database.
    rows = _cycle_log_rows(tmp_path / "mc-mock.db")
    assert len(rows) == 1


def test_orchestrator_respects_max_cycles(tmp_path: Path, monkeypatch):
    """Running with --max-cycles 2 produces exactly two cycle summaries."""
    db_path = tmp_path / "mc.db"
    monkeypatch.setenv("MC_STORAGE__DB_PATH", str(db_path))
    monkeypatch.setenv("MC_LOGGING__FILE", str(tmp_path / "mc.log"))
    monkeypatch.setenv("MC_LANES__POOL_SIZE", "2")
    monkeypatch.setenv("MC_LANES__LANE_TIMEOUT_SECONDS", "5")

    rc = orch_main(["--use-mock-provisioner", "--max-cycles", "2"])
    assert rc == 0

    # Mock-provisioner runs write to a separate `-mock` database.
    rows = _cycle_log_rows(tmp_path / "mc-mock.db")
    assert len(rows) == 2
