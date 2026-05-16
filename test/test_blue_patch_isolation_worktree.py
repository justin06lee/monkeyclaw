"""Phase 1 — patch-isolation worktree lifecycle (patch-isolation spec §6)."""

from __future__ import annotations


def test_patch_builds_store_writes_and_tears_down(db):
    from infra.patch_builds_store import PatchBuildsStore
    from interfaces.types import DiffApplyResult, PatchBuild

    store = PatchBuildsStore(db)
    build = PatchBuild(
        build_id="B1", patch_id="P1", worktree_path="/tmp/mc-patch-x",
        victim=None,
        diff_result=DiffApplyResult(applied=True, checked=True),
        isolation_mode="live", build_status="built")
    store.record(build, base_ref="abc123")
    row = db.fetchone("SELECT * FROM patch_builds WHERE build_id='B1'")
    assert row["isolation_mode"] == "live"
    assert row["diff_applied"] == 1
    assert row["torn_down"] == 0
    store.mark_torn_down("B1")
    row = db.fetchone("SELECT * FROM patch_builds WHERE build_id='B1'")
    assert row["torn_down"] == 1


def test_patch_builds_store_lists_untorn_builds(db):
    from infra.patch_builds_store import PatchBuildsStore
    from interfaces.types import DiffApplyResult, PatchBuild

    store = PatchBuildsStore(db)
    for bid, torn in (("B1", False), ("B2", True)):
        store.record(
            PatchBuild(build_id=bid, patch_id="P", worktree_path=f"/t/{bid}",
                       victim=None, diff_result=DiffApplyResult(),
                       isolation_mode="live", build_status="built"),
            base_ref="r")
        if torn:
            store.mark_torn_down(bid)
    untorn = store.list_untorn()
    assert {r["build_id"] for r in untorn} == {"B1"}


def test_diff_applies_accepts_a_clean_diff(tmp_path, db):
    from blue_team.patch_isolation import PatchIsolation, PatchIsolationConfig
    from infra.patch_builds_store import PatchBuildsStore
    from test._git_repo_fixture import GOOD_DIFF, build_repo, make_patch

    repo, base = build_repo(tmp_path / "nemoclaw")
    iso = PatchIsolation(
        provisioner=None, store=PatchBuildsStore(db),
        cfg=PatchIsolationConfig(
            nemoclaw_repo_path=repo, base_ref=base,
            worktree_root=str(tmp_path / "wt")))
    patch = make_patch("P1", GOOD_DIFF)
    result = iso.diff_applies(patch)
    assert result.checked is True
    assert result.applied is True
    assert result.rejected_hunks == []


def test_diff_applies_rejects_a_conflicting_diff(tmp_path, db):
    from blue_team.patch_isolation import PatchIsolation, PatchIsolationConfig
    from infra.patch_builds_store import PatchBuildsStore
    from test._git_repo_fixture import CONFLICTING_DIFF, build_repo, make_patch

    repo, base = build_repo(tmp_path / "nemoclaw")
    iso = PatchIsolation(
        provisioner=None, store=PatchBuildsStore(db),
        cfg=PatchIsolationConfig(
            nemoclaw_repo_path=repo, base_ref=base,
            worktree_root=str(tmp_path / "wt")))
    patch = make_patch("P2", CONFLICTING_DIFF)
    result = iso.diff_applies(patch)
    assert result.checked is True
    assert result.applied is False
    assert result.stderr  # git apply --check emitted a reason


def test_prepare_creates_then_tears_down_worktree(tmp_path, db):
    from pathlib import Path

    from blue_team.patch_isolation import PatchIsolation, PatchIsolationConfig
    from infra.patch_builds_store import PatchBuildsStore
    from test._git_repo_fixture import GOOD_DIFF, build_repo, make_patch

    repo, base = build_repo(tmp_path / "nemoclaw")
    iso = PatchIsolation(
        provisioner=None, store=PatchBuildsStore(db),
        cfg=PatchIsolationConfig(
            nemoclaw_repo_path=repo, base_ref=base,
            worktree_root=str(tmp_path / "wt")))
    patch = make_patch("P1", GOOD_DIFF)
    with iso.prepare(patch) as build:
        wt = build.worktree_path
        assert wt is not None
        assert Path(wt).exists()
        # provisioner is None -> no victim built, status records that.
        assert build.build_status in ("built", "build_failed")
    assert not Path(wt).exists()           # worktree gone after context exit
    row = db.fetchone(
        "SELECT * FROM patch_builds WHERE build_id = ?", (build.build_id,))
    assert row["torn_down"] == 1


def test_prepare_apply_failed_yields_apply_failed_status(tmp_path, db):
    from blue_team.patch_isolation import PatchIsolation, PatchIsolationConfig
    from infra.patch_builds_store import PatchBuildsStore
    from test._git_repo_fixture import CONFLICTING_DIFF, build_repo, make_patch

    repo, base = build_repo(tmp_path / "nemoclaw")
    iso = PatchIsolation(
        provisioner=None, store=PatchBuildsStore(db),
        cfg=PatchIsolationConfig(
            nemoclaw_repo_path=repo, base_ref=base,
            worktree_root=str(tmp_path / "wt")))
    patch = make_patch("P2", CONFLICTING_DIFF)
    with iso.prepare(patch) as build:
        assert build.build_status == "apply_failed"
        assert build.diff_result.applied is False


def test_make_victim_replay_fn_binds_to_an_instance():
    from blue_team.replay_minimizer import make_victim_replay_fn
    from interfaces.provisioning import VictimInstance

    inst = VictimInstance(
        instance_id="VICT-1", chat_endpoint="mock://chat/VICT-1",
        shell_endpoint=None, status="running", sandbox_id="VICT-1")
    replay = make_victim_replay_fn(inst)
    assert callable(replay)
