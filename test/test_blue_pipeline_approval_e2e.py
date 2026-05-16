"""Phase 3 — process_blue_queue routes through the approval service.

Reuses the test_blue_pipeline_e2e harness: it lands a cold-verified repro
package via process_repro_queue, then drives process_blue_queue with a
blocking replay factory so the six verifier gates pass. The package severity
is overridden before draining the blue queue to exercise the gate posture.
"""

from __future__ import annotations

import json
from pathlib import Path

from infra.approval_service import ApprovalService
from interfaces.config_schema import ApprovalsConfig
from interfaces.llm import MockLLM
from red_team import mock_victim

from blue_team._common import default_policy
from blue_team.patch_verifier import PatchVerifier, PatchVerifierConfig
from blue_team.pipeline import Pipeline
from blue_team.replay_minimizer import default_judge
from test.test_blue_pipeline_e2e import (
    _GOOD_DIFF,
    _blocking_replay_factory,
    _clean_mock,
    _patch_block,
    _planted_provisioner,
    _seed_finding,
)


class _StubDispatcher:
    def send(self, message: str, severity: str) -> None:
        pass


def setup_function(_):
    mock_victim.reset_all()


def _pipeline_with_pending_patch(tmp_path: Path, severity: str):
    """Build a mock-mode Pipeline whose blue queue holds one cold-verified
    package whose severity has been forced to `severity`."""
    allowed = tmp_path / "allowed"
    escape = tmp_path / "evil"
    provisioner = _planted_provisioner(allowed, escape)
    mcp = _clean_mock()
    _seed_finding(mcp, escape)

    llm = MockLLM()
    llm.queue(json.dumps([
        {"trace": "fs trace"},
        {"file": "src/sandbox/create.ts", "function": "createSandbox",
         "line_range": "L120-L168", "explanation": "no canon",
         "confidence": 0.85},
    ]))
    llm.queue(f"save backup to {escape}/cold.txt")
    llm.queue("<<STEPS_COMPLETE>>")

    policy = default_policy()
    policy.allowed_paths = [str(allowed)]
    pipe = Pipeline(mcp=mcp, provisioner=provisioner, llm=llm, policy=policy)
    pipe.process_repro_queue()
    assert len(mcp._repro_packages) == 1

    # Force the landed package severity so the gate posture is exercised.
    for pkg in mcp._repro_packages.values():
        pkg.severity = severity

    # Verifier with a blocking replay factory so the six gates pass.
    pipe.patch_verifier = PatchVerifier(
        mcp=mcp, provisioner=provisioner,
        cfg=PatchVerifierConfig(max_attempts_per_patch=3),
        policy=policy,
        patched_replay_factory=_blocking_replay_factory,
        judge_fn=default_judge,
    )
    llm.queue(
        _patch_block(1, "Canonicalize", "low", _GOOD_DIFF)
        + _patch_block(2, "Reject symlinks", "medium",
                       _GOOD_DIFF.replace("create.ts", "policy.ts"))
        + _patch_block(3, "Rewrite engine", "high",
                       _GOOD_DIFF.replace("create.ts", "engine.ts"))
    )
    return pipe


def test_low_severity_patch_auto_allows_and_finalizes(tmp_path: Path):
    pipe = _pipeline_with_pending_patch(tmp_path, "low")
    approved = pipe.process_blue_queue()
    assert approved == 1
    # An auto-allow ApprovalEvent was recorded.
    events = [e for plist in
              [pipe.mcp.get_approval_events(p) for p in
               {ev.patch_id for ev in pipe.mcp._approval_events}]
              for e in plist]
    assert events and any(e.decision == "allow" and e.posture == "auto_allow"
                          for e in events)


def test_high_severity_patch_goes_pending_then_finalizes_on_resolve(
        tmp_path: Path):
    pipe = _pipeline_with_pending_patch(tmp_path, "high")
    # First pass: the patch is held, not finalized.
    approved = pipe.process_blue_queue()
    assert approved == 0
    pending = ApprovalService(
        mcp=pipe.mcp, dispatcher=_StubDispatcher(),
        cfg=ApprovalsConfig()).list_pending()
    assert len(pending) == 1
    # Resolve it, then run another pass — now it finalizes.
    ApprovalService(mcp=pipe.mcp, dispatcher=_StubDispatcher(),
                    cfg=ApprovalsConfig()).resolve(
        pending[0].request_id, decision="allow",
        approver="alice", reason="reviewed")
    approved2 = pipe.process_blue_queue()
    assert approved2 == 1
