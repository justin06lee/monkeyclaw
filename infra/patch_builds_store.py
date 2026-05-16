"""Writer/reader for patch_builds — patch-isolation spec §7.

One patch_builds row per attempted isolation build. The janitor sweep
(patch-isolation §11) queries list_untorn() to reclaim leaked worktrees.
"""

from __future__ import annotations

import json

from infra.database import Database
from interfaces.types import PatchBuild


class PatchBuildsStore:
    """Thin SQLite writer; no caching, no business logic."""

    def __init__(self, db: Database) -> None:
        self._db = db

    def record(self, build: PatchBuild, *, base_ref: str | None) -> None:
        self._db.execute(
            "INSERT OR REPLACE INTO patch_builds("
            "build_id, patch_id, base_ref, worktree_path, diff_applied, "
            "rejected_hunks, build_status, victim_instance_id, "
            "isolation_mode, build_duration_seconds, torn_down) "
            "VALUES(?,?,?,?,?,?,?,?,?,?,0)",
            (build.build_id, build.patch_id, base_ref, build.worktree_path,
             int(build.diff_result.applied),
             json.dumps(build.diff_result.rejected_hunks),
             build.build_status,
             build.victim.instance_id if build.victim else None,
             build.isolation_mode, build.build_duration_seconds),
        )

    def mark_torn_down(self, build_id: str) -> None:
        self._db.execute(
            "UPDATE patch_builds SET torn_down = 1 WHERE build_id = ?",
            (build_id,),
        )

    def list_untorn(self) -> list[dict]:
        return self._db.fetchall(
            "SELECT * FROM patch_builds WHERE torn_down = 0")


__all__ = ["PatchBuildsStore"]
