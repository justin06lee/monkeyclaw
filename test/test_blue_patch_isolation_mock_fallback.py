"""Phase 3 — pipeline wiring + mock fallback (patch-isolation spec §9)."""

from __future__ import annotations

from blue_team.patch_isolation import build_patched_replay_factory
from infra.provisioning_nemoclaw import MockProvisioner


def test_mock_fallback_returns_mock_replay_and_labels_mode(tmp_path):
    """With no nemoclaw_repo_path, the factory returns the mock replay and
    a verdict is never overclaimed."""
    from blue_team.patch_isolation import PatchIsolation, PatchIsolationConfig
    from test._git_repo_fixture import make_patch

    iso = PatchIsolation(
        provisioner=None, store=None,
        cfg=PatchIsolationConfig(nemoclaw_repo_path=None))
    factory = build_patched_replay_factory(iso)
    replay = factory(make_patch("P1", "x"))
    assert callable(replay)
    assert factory._active_build is None  # no live build attempted
    assert factory._last_mode == "mock"


def test_live_config_fallback_records_actual_mock_mode(tmp_path):
    """A configured repo is not enough to claim live isolation when the
    patched victim cannot be built."""
    from blue_team.patch_isolation import PatchIsolation, PatchIsolationConfig
    from test._git_repo_fixture import GOOD_DIFF, build_repo, make_patch

    repo, base = build_repo(tmp_path / "nemoclaw")
    iso = PatchIsolation(
        provisioner=None, store=None,
        cfg=PatchIsolationConfig(
            nemoclaw_repo_path=repo, base_ref=base,
            worktree_root=str(tmp_path / "wt")))
    factory = build_patched_replay_factory(iso)

    replay = factory(make_patch("P1", GOOD_DIFF))

    assert callable(replay)
    assert factory._last_mode == "mock"
    assert factory._active_cm is None


def test_pipeline_builds_isolation_only_when_enabled(server, tmp_path):
    from blue_team.pipeline import Pipeline

    pipe = Pipeline(mcp=server, provisioner=MockProvisioner())
    # Default config has patch_isolation.enabled=False -> isolation is None.
    assert pipe.patch_isolation is None
    # The verifier still works (mock surface, current behaviour).
    assert pipe.patch_verifier is not None


def test_dashboard_patch_view_includes_isolation_mode(db):
    from infra.dashboard import patch_isolation_badge

    assert patch_isolation_badge("live") == "live"
    assert patch_isolation_badge("mock") == "mock"
    assert patch_isolation_badge(None) == "mock"   # default when unset
