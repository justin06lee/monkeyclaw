"""Phase 0 — patch-isolation shared type contracts."""

from __future__ import annotations

from dataclasses import fields

from interfaces.types import DiffApplyResult, PatchBuild


def test_diff_apply_result_shape():
    fnames = {f.name for f in fields(DiffApplyResult)}
    assert {"applied", "checked", "rejected_hunks", "stderr"} <= fnames


def test_diff_apply_result_defaults_to_unapplied():
    r = DiffApplyResult()
    assert r.applied is False
    assert r.checked is False
    assert r.rejected_hunks == []


def test_patch_build_carries_isolation_mode_and_status():
    fnames = {f.name for f in fields(PatchBuild)}
    assert {"build_id", "patch_id", "worktree_path", "victim",
            "diff_result", "isolation_mode", "build_status"} <= fnames


def test_patch_build_mock_construction():
    b = PatchBuild(
        build_id="B1", patch_id="P1", worktree_path=None, victim=None,
        diff_result=DiffApplyResult(), isolation_mode="mock",
        build_status="mock")
    assert b.isolation_mode == "mock"
    assert b.build_status == "mock"
