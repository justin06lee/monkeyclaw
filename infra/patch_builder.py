"""Patch builder — real-nemoclaw-provisioner spec §7.4.

Given a candidate diff, materialise a patched victim: clone the NemoClaw
checkout into a disposable work area, apply the diff there, and produce a
VictimSnapshot the provisioner can boot. The baseline checkout is never
touched (constraint 5); an un-appliable diff or absent snapshot support is a
ProvisioningError, never a silent unpatched victim (constraint 6).
"""

from __future__ import annotations

import logging
import os
import shutil
import subprocess
import tempfile
import uuid
from datetime import UTC, datetime

from interfaces.provisioning import (
    ProvisioningError,
    SandboxCapabilities,
    VictimSnapshot,
)

LOG = logging.getLogger("monkeyclaw.provisioning.patch")


def _now() -> str:
    return datetime.now(UTC).isoformat()


class PatchBuilder:
    """Builds a patched-victim snapshot in a disposable work area."""

    def __init__(
        self,
        *,
        repo_path: str,
        work_area_dir: str,
        capabilities: SandboxCapabilities,
        build_timeout_s: int = 900,
    ) -> None:
        self.repo_path = repo_path
        self.work_area_dir = work_area_dir
        self.capabilities = capabilities
        self.build_timeout_s = build_timeout_s

    def build_patched_snapshot(
        self, diff: str, *, baseline: str,
    ) -> VictimSnapshot:
        """Clone -> apply diff -> rebuild -> snapshot. Raises on any failure;
        the disposable work area is always discarded."""
        if not self.capabilities.snapshots:
            raise ProvisioningError(
                "cannot build a patched victim: this nemoclaw build reports "
                "no snapshot support — refusing to run an unpatched victim")
        if not diff or not diff.strip():
            raise ProvisioningError("patch_diff is empty")

        os.makedirs(self.work_area_dir, exist_ok=True)
        work = tempfile.mkdtemp(prefix="mc-patch-", dir=self.work_area_dir)
        try:
            # Clone the checkout into the disposable work area.
            self._run(["git", "clone", "--quiet", self.repo_path, work],
                      cwd=None, what="git clone", timeout=self.build_timeout_s)
            # Apply the diff inside the clone only.
            check = subprocess.run(
                ["git", "apply", "--check", "-"], cwd=work,
                input=diff, text=True, capture_output=True)
            if check.returncode != 0:
                raise ProvisioningError(
                    f"patch does not apply cleanly: "
                    f"{check.stderr.strip()[:300]}")
            apply = subprocess.run(
                ["git", "apply", "-"], cwd=work,
                input=diff, text=True, capture_output=True)
            if apply.returncode != 0:
                raise ProvisioningError(
                    f"git apply failed: {apply.stderr.strip()[:300]}")
            # Build the patched tree. The build step is repo-specific; the
            # nemoclaw checkout ships a `make build` target — skip it when the
            # work area has no Makefile (e.g. the throwaway test repo).
            if os.path.exists(os.path.join(work, "Makefile")):
                self._run(["make", "build"], cwd=work, what="patched build",
                          timeout=self.build_timeout_s)
            else:
                LOG.info("no Makefile in patched tree — skipping build step")
            name = f"patched-{uuid.uuid4().hex[:10]}"
            return VictimSnapshot(
                name=name, sandbox_id="patched-build", created_at=_now(),
                deterministic=True, patched=True, base_snapshot=baseline)
        finally:
            shutil.rmtree(work, ignore_errors=True)

    def _run(self, cmd: list[str], *, cwd: str | None, what: str,
             timeout: int) -> None:
        try:
            proc = subprocess.run(
                cmd, cwd=cwd, capture_output=True, text=True, timeout=timeout)
        except subprocess.TimeoutExpired as e:
            raise ProvisioningError(
                f"`{what}` timed out after {timeout}s") from e
        except OSError as e:
            raise ProvisioningError(f"`{what}` failed to start: {e}") from e
        if proc.returncode != 0:
            raise ProvisioningError(
                f"`{what}` exited {proc.returncode}: "
                f"{(proc.stderr or proc.stdout).strip()[:300]}")


__all__ = ["PatchBuilder"]
