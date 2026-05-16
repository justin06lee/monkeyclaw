"""Writer for sandbox_runs / victim_snapshots — real-nemoclaw-provisioner §8.

One sandbox_runs row per provisioned victim is the operational audit trail:
"what victim did this finding run against, and was it isolated". Schema-light
— the provisioner is otherwise an in-memory telemetry producer.
"""

from __future__ import annotations

import dataclasses
import json
import uuid
from datetime import UTC, datetime

from infra.database import Database
from interfaces.provisioning import SandboxCapabilities, VictimSnapshot


def _now() -> str:
    return datetime.now(UTC).isoformat()


class SandboxRunsStore:
    """Thin SQLite writer; no caching, no business logic."""

    def __init__(self, db: Database) -> None:
        self._db = db

    def open_run(
        self,
        *,
        instance_id: str,
        lane_id: str | None,
        mode: str,
        deterministic: bool,
        patch_applied: bool,
        capabilities: SandboxCapabilities,
    ) -> str:
        run_id = f"SBXRUN-{uuid.uuid4().hex[:10]}"
        self._db.execute(
            "INSERT INTO sandbox_runs(run_id, instance_id, lane_id, mode, "
            "deterministic, patch_applied, capabilities, provisioned_at) "
            "VALUES(?,?,?,?,?,?,?,?)",
            (run_id, instance_id, lane_id, mode, int(deterministic),
             int(patch_applied),
             json.dumps(dataclasses.asdict(capabilities)), _now()),
        )
        return run_id

    def close_run(self, run_id: str) -> None:
        self._db.execute(
            "UPDATE sandbox_runs SET torn_down_at = ? WHERE run_id = ?",
            (_now(), run_id),
        )

    def record_snapshot(self, snapshot: VictimSnapshot) -> str:
        snapshot_id = f"SNAP-{uuid.uuid4().hex[:10]}"
        self._db.execute(
            "INSERT INTO victim_snapshots(snapshot_id, name, sandbox_id, "
            "deterministic, patched, base_snapshot, created_at) "
            "VALUES(?,?,?,?,?,?,?)",
            (snapshot_id, snapshot.name, snapshot.sandbox_id,
             int(snapshot.deterministic), int(snapshot.patched),
             snapshot.base_snapshot, snapshot.created_at),
        )
        return snapshot_id


__all__ = ["SandboxRunsStore"]
