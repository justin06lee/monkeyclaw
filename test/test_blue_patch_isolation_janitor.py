"""Phase 4 — the startup janitor sweep (patch-isolation spec §11)."""

from __future__ import annotations

from blue_team.patch_isolation import sweep_orphaned_worktrees
from infra.patch_builds_store import PatchBuildsStore
from interfaces.types import DiffApplyResult, PatchBuild


def test_sweep_reclaims_orphaned_worktree_with_no_row(tmp_path):
    root = tmp_path / "wt"
    root.mkdir()
    orphan = root / "mc-patch-orphan1"
    orphan.mkdir()
    (orphan / "stale.txt").write_text("leaked by a crash")
    removed = sweep_orphaned_worktrees(str(root), store=None)
    assert removed == 1
    assert not orphan.exists()


def test_sweep_ignores_non_mc_patch_dirs(tmp_path):
    root = tmp_path / "wt"
    root.mkdir()
    keep = root / "some-other-dir"
    keep.mkdir()
    removed = sweep_orphaned_worktrees(str(root), store=None)
    assert removed == 0
    assert keep.exists()


def test_sweep_reclaims_untorn_build_worktree(tmp_path, db):
    root = tmp_path / "wt"
    root.mkdir()
    wt = root / "mc-patch-untorn"
    wt.mkdir()
    store = PatchBuildsStore(db)
    store.record(
        PatchBuild(build_id="B1", patch_id="P1", worktree_path=str(wt),
                   victim=None, diff_result=DiffApplyResult(),
                   isolation_mode="live", build_status="built"),
        base_ref="r")
    removed = sweep_orphaned_worktrees(str(root), store=store)
    assert removed == 1
    assert not wt.exists()
