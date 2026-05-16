"""Optional post-approval PR generation (approval spec §6.3).

Given an `allow`-resolved patch, drafts a pull request on a dedicated branch
via the `gh` CLI. Never on the authorization critical path — any failure
returns None and is logged; the approval still stands.
"""

from __future__ import annotations

import logging
import subprocess
import tempfile
import uuid
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path

from interfaces.types import ApprovalEvent, PatchCandidate, PullRequestDraft

LOG = logging.getLogger("monkeyclaw.infra.pr_generator")


def _run(cmd: list[str]) -> str:
    """Default command runner — shells out and returns stdout."""
    result = subprocess.run(  # noqa: S603
        cmd, capture_output=True, text=True, check=True)
    return result.stdout.strip()


class PRGenerator:
    def __init__(
        self,
        *,
        base_branch: str = "master",
        runner: Callable[[list[str]], str] | None = None,
    ) -> None:
        self.base_branch = base_branch
        self._run = runner or _run

    # ------------------------------------------------------------------
    def draft(
        self,
        patch: PatchCandidate,
        package,  # noqa: ANN001 — ReproPackage
        approval_event: ApprovalEvent,
    ) -> PullRequestDraft | None:
        """Create a branch, apply the diff, and open a draft PR.

        Returns the PullRequestDraft, or None on any failure (non-fatal)."""
        vuln = patch.vuln_ids[0] if patch.vuln_ids else patch.patch_id
        branch = f"monkeyclaw/{vuln}-{uuid.uuid4().hex[:6]}"
        try:
            self._run(["git", "checkout", "-b", branch, self.base_branch])
            self._apply_diff(patch.diff)
            self._run(["git", "add", "-A"])
            self._run(["git", "commit", "-m", self._commit_message(patch)])
            self._run(["git", "push", "-u", "origin", branch])
            pr_url = self._run([
                "gh", "pr", "create", "--draft",
                "--base", self.base_branch, "--head", branch,
                "--title", self._pr_title(patch, package),
                "--body", self._pr_body(patch, package, approval_event),
            ])
            commit_sha = self._run(["git", "rev-parse", "HEAD"])
        except Exception as e:  # noqa: BLE001
            LOG.warning("PR generation failed (non-fatal): %s", e)
            return None
        return PullRequestDraft(
            branch=branch, pr_url=pr_url, commit_sha=commit_sha,
            created_at=datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
        )

    # ------------------------------------------------------------------
    def _apply_diff(self, diff: str) -> None:
        with tempfile.NamedTemporaryFile(
                "w", suffix=".patch", delete=False) as fh:
            fh.write(diff)
            patch_path = fh.name
        try:
            self._run(["git", "apply", patch_path])
        finally:
            Path(patch_path).unlink(missing_ok=True)

    @staticmethod
    def _commit_message(patch: PatchCandidate) -> str:
        return (f"fix({patch.zone_id}): patch {','.join(patch.vuln_ids)}\n\n"
                f"{patch.explanation}")

    @staticmethod
    def _pr_title(patch: PatchCandidate, package) -> str:  # noqa: ANN001
        return f"[MonkeyClaw] {getattr(package, 'title', patch.zone_id)}"

    @staticmethod
    def _pr_body(
        patch: PatchCandidate, package, event: ApprovalEvent,  # noqa: ANN001
    ) -> str:
        return (
            f"## MonkeyClaw auto-drafted patch\n\n"
            f"- **Vulnerabilities:** {', '.join(patch.vuln_ids)}\n"
            f"- **Zone:** {patch.zone_id}\n"
            f"- **Severity:** {event.severity}\n"
            f"- **Approach:** {patch.approach}\n"
            f"- **Generalization:** {event.generalization_status or 'n/a'}\n\n"
            f"### Approval\n"
            f"Approved by **{event.approver}** — {event.reason}\n\n"
            f"### Finding\n{getattr(package, 'repro_document_md', '')[:4000]}\n"
        )


__all__ = ["PRGenerator"]
