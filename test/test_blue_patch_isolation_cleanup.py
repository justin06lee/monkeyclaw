"""Phase 4 — teardown is structural even on a mid-context crash."""

from __future__ import annotations

from pathlib import Path

import pytest

from blue_team.patch_isolation import PatchIsolation, PatchIsolationConfig
from infra.patch_builds_store import PatchBuildsStore
from test._git_repo_fixture import GOOD_DIFF, build_repo, make_patch


def test_exception_inside_prepare_still_tears_down(tmp_path, db):
    repo, base = build_repo(tmp_path / "nemoclaw")
    iso = PatchIsolation(
        provisioner=None, store=PatchBuildsStore(db),
        cfg=PatchIsolationConfig(
            nemoclaw_repo_path=repo, base_ref=base,
            worktree_root=str(tmp_path / "wt")))
    captured_worktree = {}
    with pytest.raises(RuntimeError, match="gate exploded"):
        with iso.prepare(make_patch("P1", GOOD_DIFF)) as b:
            captured_worktree["path"] = b.worktree_path
            assert Path(b.worktree_path).exists()
            raise RuntimeError("gate exploded mid-verify")
    # The finally block removed the worktree despite the crash.
    assert not Path(captured_worktree["path"]).exists()
    rows = db.fetchall("SELECT * FROM patch_builds WHERE torn_down = 1")
    assert len(rows) == 1
