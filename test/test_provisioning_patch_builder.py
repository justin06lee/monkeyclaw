"""Phase 4 — the patch builder (real-nemoclaw-provisioner spec §7.4)."""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

from infra.patch_builder import PatchBuilder
from interfaces.provisioning import ProvisioningError, SandboxCapabilities


def _git_repo(root: Path) -> None:
    root.mkdir(parents=True, exist_ok=True)
    (root / "control.py").write_text("ALLOW = ['/work']\n")
    for cmd in (["git", "init", "-q"],
                ["git", "config", "user.email", "t@t"],
                ["git", "config", "user.name", "t"],
                ["git", "add", "."],
                ["git", "commit", "-q", "-m", "base"]):
        subprocess.run(cmd, cwd=root, check=True)


_GOOD_DIFF = (
    "--- a/control.py\n"
    "+++ b/control.py\n"
    "@@ -1 +1 @@\n"
    "-ALLOW = ['/work']\n"
    "+ALLOW = []\n"
)
_BAD_DIFF = (
    "--- a/control.py\n"
    "+++ b/control.py\n"
    "@@ -1 +1 @@\n"
    "-ALLOW = ['/does-not-match']\n"
    "+ALLOW = []\n"
)

_CAPS_FULL = SandboxCapabilities(
    cli_present=True, snapshots=True, ephemeral=True,
    container_fsdiff=True, recover=True)
_CAPS_NO_SNAP = SandboxCapabilities(
    cli_present=True, snapshots=False, ephemeral=False,
    container_fsdiff=True, recover=True)


def test_build_patched_snapshot_applies_diff_in_isolation(tmp_path: Path):
    repo = tmp_path / "nemoclaw"
    _git_repo(repo)
    builder = PatchBuilder(
        repo_path=str(repo), work_area_dir=str(tmp_path / "work"),
        capabilities=_CAPS_FULL, build_timeout_s=60)
    snap = builder.build_patched_snapshot(_GOOD_DIFF, baseline="clean-baseline")
    assert snap.patched is True
    assert snap.base_snapshot == "clean-baseline"
    # The baseline checkout is untouched.
    assert (repo / "control.py").read_text() == "ALLOW = ['/work']\n"


def test_unappliable_diff_raises_provisioning_error(tmp_path: Path):
    repo = tmp_path / "nemoclaw"
    _git_repo(repo)
    builder = PatchBuilder(
        repo_path=str(repo), work_area_dir=str(tmp_path / "work"),
        capabilities=_CAPS_FULL, build_timeout_s=60)
    with pytest.raises(ProvisioningError, match="apply"):
        builder.build_patched_snapshot(_BAD_DIFF, baseline="clean-baseline")


def test_patch_without_snapshot_support_raises(tmp_path: Path):
    repo = tmp_path / "nemoclaw"
    _git_repo(repo)
    builder = PatchBuilder(
        repo_path=str(repo), work_area_dir=str(tmp_path / "work"),
        capabilities=_CAPS_NO_SNAP, build_timeout_s=60)
    with pytest.raises(ProvisioningError, match="snapshot"):
        builder.build_patched_snapshot(_GOOD_DIFF, baseline="clean-baseline")
