"""Phase 4 — pr_generator drafts a PR for an approved patch."""

from __future__ import annotations

from infra.pr_generator import PRGenerator
from interfaces.types import ApprovalEvent, PatchCandidate, ReproPackage


def _patch() -> PatchCandidate:
    return PatchCandidate(
        patch_id="P1", vuln_ids=["MC-2026-0001"], zone_id="SBX-FS",
        approach="bounds-check", invasiveness="low",
        diff="--- a/x\n+++ b/x\n@@ -1 +1 @@\n-bad\n+good\n",
        explanation="fix the bounds bug", side_effects="none",
        status="approved")


def _package() -> ReproPackage:
    return ReproPackage(
        package_id="PKG-1", finding_id="F-1", vuln_id="MC-2026-0001",
        title="Path traversal", severity="high", repro_rate=1.0,
        minimal_steps=[], affected_zone="SBX-FS", affected_paths=None,
        ideas_used=[], transcripts={}, suggested_mitigations=[],
        repro_document_md="# repro", cold_verified=True,
        ready_for_blue=True, blue_team_status="patched",
        created_at="2026-05-15T00:00:00Z")


def _event() -> ApprovalEvent:
    return ApprovalEvent(
        event_id="E1", request_id="R1", patch_id="P1",
        vuln_ids=["MC-2026-0001"], zone_id="SBX-FS", severity="high",
        decision="allow", posture="require_approval", approver="alice",
        reason="reviewed", ask_expiry=None, grant_expiry=None,
        generalization_status="generalized", pr_url=None,
        created_at="2026-05-15T00:00:00Z")


class _FakeRunner:
    """Records gh/git calls; returns canned success output."""

    def __init__(self) -> None:
        self.calls: list[list[str]] = []

    def __call__(self, cmd: list[str]) -> str:
        self.calls.append(cmd)
        if cmd[:2] == ["gh", "pr"]:
            return "https://github.com/org/repo/pull/42"
        if cmd[:2] == ["git", "rev-parse"]:
            return "abc1234"
        return ""


class _FailingRunner:
    def __call__(self, cmd: list[str]) -> str:
        raise RuntimeError("gh: command not found")


def test_draft_produces_a_pull_request_draft():
    runner = _FakeRunner()
    gen = PRGenerator(base_branch="master", runner=runner)
    draft = gen.draft(_patch(), _package(), _event())
    assert draft is not None
    assert draft.pr_url == "https://github.com/org/repo/pull/42"
    assert draft.branch.startswith("monkeyclaw/")
    # The diff was applied and a branch was created.
    assert any(c[:2] == ["git", "apply"] for c in runner.calls) or \
        any("apply" in " ".join(c) for c in runner.calls)


def test_gh_failure_is_non_fatal():
    gen = PRGenerator(base_branch="master", runner=_FailingRunner())
    draft = gen.draft(_patch(), _package(), _event())
    # PR generation failed -> returns None, never raises.
    assert draft is None
