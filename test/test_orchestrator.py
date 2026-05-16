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
