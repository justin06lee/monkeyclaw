"""Disposable-worktree patch isolation — patch-isolation spec §6.

Owns the lifecycle that makes "the six gates passed" mean something: create
a git worktree off a pinned base commit under a unique temp root, apply the
candidate diff there, rebuild the victim from the patched tree, hand back a
ReplayFn bound to that victim, and tear everything down in a finally.

When no rebuildable victim is configured the module degrades to the existing
mock replay and labels the outcome isolation_mode="mock" — mock is a
first-class fallback, not an error (patch-isolation §4 c4).
"""

from __future__ import annotations

import contextlib
import logging
import shutil
import subprocess
import tempfile
import time
import uuid
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path

from interfaces.provisioning import VictimProvisioner
from interfaces.types import DiffApplyResult, PatchBuild, PatchCandidate

from blue_team.replay_minimizer import ReplayFn, make_mock_replay_fn

LOG = logging.getLogger("monkeyclaw.blue.patch_isolation")

_WORKTREE_PREFIX = "mc-patch-"


@dataclass
class PatchIsolationConfig:
    """Where the NemoClaw checkout is and how to build patched victims."""

    nemoclaw_repo_path: str | None = None
    base_ref: str = "HEAD"
    build_timeout_s: int = 900
    worktree_root: str = tempfile.gettempdir()


class PatchIsolation:
    """Disposable-worktree lifecycle for one candidate patch at a time."""

    def __init__(
        self,
        *,
        provisioner: VictimProvisioner | None,
        store,  # PatchBuildsStore | None
        cfg: PatchIsolationConfig,
    ) -> None:
        self.provisioner = provisioner
        self.store = store
        self.cfg = cfg

    # ------------------------------------------------------------------
    def _add_worktree(self) -> str:
        """git worktree add a fresh checkout at base_ref under a unique temp
        root. Returns the worktree path."""
        Path(self.cfg.worktree_root).mkdir(parents=True, exist_ok=True)
        worktree = tempfile.mkdtemp(
            prefix=_WORKTREE_PREFIX, dir=self.cfg.worktree_root)
        proc = subprocess.run(
            ["git", "worktree", "add", "--detach", worktree,
             self.cfg.base_ref],
            cwd=self.cfg.nemoclaw_repo_path, capture_output=True, text=True,
            timeout=self.cfg.build_timeout_s)
        if proc.returncode != 0:
            shutil.rmtree(worktree, ignore_errors=True)
            raise RuntimeError(
                f"git worktree add failed: {proc.stderr.strip()[:300]}")
        return worktree

    def _remove_worktree(self, worktree: str) -> None:
        """Best-effort teardown — a cleanup failure never fails a verdict."""
        try:
            subprocess.run(
                ["git", "worktree", "remove", "--force", worktree],
                cwd=self.cfg.nemoclaw_repo_path, capture_output=True,
                timeout=60)
        except Exception as e:  # noqa: BLE001
            LOG.warning("git worktree remove failed for %s: %s", worktree, e)
        if Path(worktree).exists():
            shutil.rmtree(worktree, ignore_errors=True)

    @staticmethod
    def _apply(worktree: str, diff: str, *, check_only: bool
               ) -> DiffApplyResult:
        """Run `git apply [--check]` of `diff` inside `worktree`."""
        cmd = ["git", "apply"] + (["--check"] if check_only else []) + ["-"]
        proc = subprocess.run(
            cmd, cwd=worktree, input=diff, text=True, capture_output=True)
        rejected: list[str] = []
        if proc.returncode != 0:
            rejected = [ln for ln in proc.stderr.splitlines()
                        if "error:" in ln or "patch" in ln.lower()]
        return DiffApplyResult(
            applied=proc.returncode == 0,
            checked=check_only,
            rejected_hunks=rejected,
            stderr=proc.stderr.strip(),
        )

    # ------------------------------------------------------------------
    def diff_applies(self, patch: PatchCandidate) -> DiffApplyResult:
        """Run `git apply --check` in a fresh worktree and return the result
        WITHOUT building — cheap real input for gate_diff_applies."""
        worktree = self._add_worktree()
        try:
            return self._apply(worktree, patch.diff, check_only=True)
        finally:
            self._remove_worktree(worktree)

    @contextlib.contextmanager
    def prepare(self, patch: PatchCandidate) -> Iterator[PatchBuild]:
        """Yield a PatchBuild for `patch`: worktree created, diff applied,
        victim rebuilt. Teardown happens on context exit (success or crash)."""
        started = time.monotonic()
        build_id = f"PB-{uuid.uuid4().hex[:10]}"
        worktree = self._add_worktree()
        victim = None
        try:
            check = self._apply(worktree, patch.diff, check_only=True)
            if not check.applied:
                build = PatchBuild(
                    build_id=build_id, patch_id=patch.patch_id,
                    worktree_path=worktree, victim=None, diff_result=check,
                    isolation_mode="live", build_status="apply_failed",
                    build_duration_seconds=time.monotonic() - started)
                self._persist(build)
                yield build
                return
            applied = self._apply(worktree, patch.diff, check_only=False)
            if not applied.applied:
                build = PatchBuild(
                    build_id=build_id, patch_id=patch.patch_id,
                    worktree_path=worktree, victim=None,
                    diff_result=applied, isolation_mode="live",
                    build_status="apply_failed",
                    build_duration_seconds=time.monotonic() - started)
                self._persist(build)
                LOG.warning("git apply failed after --check passed for %s",
                            patch.patch_id)
                yield build
                return
            # Build a victim from the patched worktree.
            status = "built"
            if self.provisioner is None:
                status = "build_failed"
            else:
                from interfaces.provisioning import (  # noqa: PLC0415
                    VictimConfig,
                )
                try:
                    victim = self.provisioner.provision_victim(VictimConfig(
                        nemoclaw_version="patched", policy_path="",
                        agent_type="coding_assistant", agent_config_path="",
                        nemoclaw_repo_path=worktree))
                except Exception as e:  # noqa: BLE001
                    LOG.warning("patched victim build failed for %s: %s",
                                patch.patch_id, e)
                    status = "build_failed"
            build = PatchBuild(
                build_id=build_id, patch_id=patch.patch_id,
                worktree_path=worktree, victim=victim,
                diff_result=applied, isolation_mode="live",
                build_status=status,
                build_duration_seconds=time.monotonic() - started)
            self._persist(build)
            yield build
        finally:
            if victim is not None and self.provisioner is not None:
                with contextlib.suppress(Exception):
                    self.provisioner.teardown_victim(victim.instance_id)
            self._remove_worktree(worktree)
            if self.store is not None:
                with contextlib.suppress(Exception):
                    self.store.mark_torn_down(build_id)

    def _persist(self, build: PatchBuild) -> None:
        if self.store is not None:
            with contextlib.suppress(Exception):
                self.store.record(build, base_ref=self.cfg.base_ref)


def build_patched_replay_factory(isolation: PatchIsolation):
    """The real PatchedReplayFactory. Returns a ReplayFn bound to the patched
    victim built by PatchIsolation. Mock fallback: when no repo is configured,
    return the mock replay so verification still runs (isolation_mode=mock)."""

    def factory(patch: PatchCandidate) -> ReplayFn:
        if (isolation.cfg.nemoclaw_repo_path is None
                or isolation.provisioner is None):
            return make_mock_replay_fn()
        # Build once per candidate; all gates of the candidate share it.
        cm = isolation.prepare(patch)
        build = cm.__enter__()
        factory._active_cm = cm  # noqa: SLF001 — held for the candidate
        factory._active_build = build  # noqa: SLF001
        if build.victim is None:
            cm.__exit__(None, None, None)
            return make_mock_replay_fn()
        from blue_team.replay_minimizer import (  # noqa: PLC0415
            make_victim_replay_fn,
        )

        return make_victim_replay_fn(build.victim)

    factory._active_cm = None  # noqa: SLF001
    factory._active_build = None  # noqa: SLF001
    return factory


def sweep_orphaned_worktrees(worktree_root: str, store) -> int:
    """Startup janitor (patch-isolation §11): remove every mc-patch-* dir
    whose patch_builds row is not torn_down (or has no row). Returns count."""
    root = Path(worktree_root)
    if not root.exists():
        return 0
    removed = 0
    for child in root.iterdir():
        if not child.name.startswith(_WORKTREE_PREFIX) or not child.is_dir():
            continue
        # Reclaim every leftover mc-patch-* dir: a row's state is advisory,
        # the sweep over disk is the source of truth (patch-isolation §11).
        shutil.rmtree(child, ignore_errors=True)
        removed += 1
    if removed:
        LOG.info("janitor reclaimed %d orphaned worktree(s) under %s",
                 removed, worktree_root)
    return removed


__all__ = [
    "PatchIsolation",
    "PatchIsolationConfig",
    "build_patched_replay_factory",
    "sweep_orphaned_worktrees",
]
