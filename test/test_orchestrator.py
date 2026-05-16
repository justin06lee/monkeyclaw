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


def test_orchestrator_sweeps_stale_claims_each_cycle(tmp_path, monkeypatch):
    """A repro_queue row stranded in 'processing' is requeued at cycle start."""
    monkeypatch.setenv("MC_STORAGE__DB_PATH", str(tmp_path / "mc.db"))
    monkeypatch.setenv("MC_LOGGING__FILE", str(tmp_path / "mc.log"))
    monkeypatch.setenv("MC_LANES__POOL_SIZE", "2")
    monkeypatch.setenv("MC_LANES__LANE_TIMEOUT_SECONDS", "5")

    from infra.bootstrap import boot
    from infra.orchestrator import Orchestrator, StubBlue, StubRedTeam

    rt = boot(None, use_mock_provisioner=True)
    try:
        rt.mcp.db.execute(
            "INSERT INTO surface_zones(zone_id, name, description) "
            "VALUES('Z','z','z')")
        rt.mcp.db.execute(
            "INSERT INTO findings(finding_id, cycle_id, idea_id, zone_id, "
            "source_mode, idea_summary, verdict, tier_caught, failure_class, "
            "severity, evidence) VALUES('F1',1,'I','Z','creative','s',"
            "'confirmed','programmatic','none','high','[]')")
        rt.mcp.db.execute(
            "INSERT INTO repro_queue(finding_id, priority, status, "
            "dequeued_at, worker_id) VALUES('F1','high','processing',"
            "datetime('now','-99999 seconds'),'dead')")
        orch = Orchestrator(rt, StubRedTeam(), StubBlue())
        orch._run_cycle(1)
        row = rt.mcp.db.fetchone(
            "SELECT status FROM repro_queue WHERE finding_id='F1'")
        assert row["status"] == "queued"
    finally:
        rt.shutdown()


def test_orchestrator_runs_purple_when_enabled(tmp_path, monkeypatch):
    """A cycle with purple enabled produces a control_validation_runs row."""
    monkeypatch.setenv("MC_STORAGE__DB_PATH", str(tmp_path / "mcp.db"))
    monkeypatch.setenv("MC_LOGGING__FILE", str(tmp_path / "mcp.log"))
    monkeypatch.setenv("MC_LANES__POOL_SIZE", "2")
    monkeypatch.setenv("MC_LANES__LANE_TIMEOUT_SECONDS", "5")

    from infra.bootstrap import boot
    from infra.orchestrator import Orchestrator, StubBlue, StubRedTeam

    rt = boot(None, use_mock_provisioner=True)
    try:
        rt.cfg.purple.enabled = True
        orch = Orchestrator(rt, StubRedTeam(), StubBlue())
        orch._run_cycle(1)
        runs = rt.mcp.get_control_validation_runs()
        assert len(runs) >= 1
    finally:
        rt.shutdown()


def test_orchestrator_skips_purple_when_disabled(tmp_path, monkeypatch):
    monkeypatch.setenv("MC_STORAGE__DB_PATH", str(tmp_path / "mcd.db"))
    monkeypatch.setenv("MC_LOGGING__FILE", str(tmp_path / "mcd.log"))
    monkeypatch.setenv("MC_LANES__POOL_SIZE", "2")
    monkeypatch.setenv("MC_LANES__LANE_TIMEOUT_SECONDS", "5")

    from infra.bootstrap import boot
    from infra.orchestrator import Orchestrator, StubBlue, StubRedTeam

    rt = boot(None, use_mock_provisioner=True)
    try:
        rt.cfg.purple.enabled = False
        orch = Orchestrator(rt, StubRedTeam(), StubBlue())
        orch._run_cycle(1)
        assert rt.mcp.get_control_validation_runs() == []
    finally:
        rt.shutdown()


def test_orchestrator_folds_judgments_into_red_zone_outcomes(tmp_path, monkeypatch):
    """Runtime cycle must feed post-execution judgments back to red routing."""
    monkeypatch.setenv("MC_STORAGE__DB_PATH", str(tmp_path / "mcr.db"))
    monkeypatch.setenv("MC_LOGGING__FILE", str(tmp_path / "mcr.log"))
    monkeypatch.setenv("MC_LANES__POOL_SIZE", "2")
    monkeypatch.setenv("MC_LANES__LANE_TIMEOUT_SECONDS", "5")

    from infra.bootstrap import boot
    from infra.orchestrator import Orchestrator, StubBlue, StubRedTeam
    from interfaces.types import JudgmentResult

    class TournamentRed(StubRedTeam):
        def __init__(self):
            self.zone_outcomes = []
            self._last_cycle_metrics = {}

        def generate_ideas(self, cycle_id, n_lanes):  # noqa: ANN001
            ideas = super().generate_ideas(cycle_id, n_lanes)
            for idea in ideas:
                idea.zone_id = "SBX-FS"
                idea.model_label = "entrant-a"
            return ideas

        def judge(self, lane_result):  # noqa: ANN001
            return JudgmentResult(
                lane_id=lane_result.lane_id,
                idea_id=lane_result.idea_id,
                zone_id=lane_result.zone_targeted,
                verdict="confirmed",
                tier_that_caught="programmatic",
                failure_class="none",
                severity="high",
                confidence=1.0,
                evidence=[],
                reasoning="",
                tokens_used_judgment=0,
                timestamp="",
            )

        def record_zone_outcomes(self, zone_id, judged):  # noqa: ANN001
            self.zone_outcomes.append((zone_id, judged))

    rt = boot(None, use_mock_provisioner=True)
    red = TournamentRed()
    orch = Orchestrator(rt, red, StubBlue())
    orch.scheduler.start()
    try:
        orch._run_cycle(1)
        assert red.zone_outcomes
        zone_id, judged = red.zone_outcomes[0]
        assert zone_id == "SBX-FS"
        assert len(judged) == 2
        assert all(j.verdict == "confirmed" for _, j in judged)
    finally:
        orch.scheduler.shutdown(timeout=5)
        rt.shutdown()
