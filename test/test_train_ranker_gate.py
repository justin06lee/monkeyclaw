"""Phase 3 — train_ranker.py refuses to train on an insufficient dataset."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path


def _run_dry_run(db_path: Path) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, "scripts/train_ranker.py", "--dry-run",
         "--db", str(db_path)],
        capture_output=True, text=True)


def test_dry_run_aborts_on_empty_dataset(tmp_path):
    from infra.database import Database

    db_path = tmp_path / "empty.db"
    Database(db_path).close()       # creates the schema, zero traces
    result = _run_dry_run(db_path)
    assert result.returncode != 0
    assert "volume" in (result.stdout + result.stderr).lower()
    # No artifact must be emitted.
    assert not (tmp_path / "ranker_artifact.json").exists()


def test_dry_run_reports_the_failing_criteria(tmp_path):
    from infra.database import Database

    db_path = tmp_path / "empty2.db"
    Database(db_path).close()
    result = _run_dry_run(db_path)
    out = (result.stdout + result.stderr).lower()
    assert "not ready" in out or "readiness" in out
