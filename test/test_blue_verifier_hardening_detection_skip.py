"""Phase 2 — gate_detection clean-skip when the oracle is absent (spec §4.4)."""

from __future__ import annotations

from blue_team.patch_verifier import PatchVerifier
from test.test_blue_patch_verifier import (
    make_blocking_replay_factory, make_patch, make_repro_package,
    make_test_pair,
)


def test_gate_detection_skips_with_recorded_reason(real_mcp, mock_provisioner):
    """With detection_oracle=None, gate_detection is a recorded skip — not
    a pass — and the patch can still be approved on the other gates."""
    pkg = make_repro_package()
    verifier = PatchVerifier(  # no detection_oracle injected
        real_mcp, mock_provisioner,
        patched_replay_factory=make_blocking_replay_factory())
    outcome = verifier.verify(
        patch=make_patch(), package=pkg, test_pair=make_test_pair(pkg))
    g7 = next(g for g in outcome.gates if g.name == "gate_detection")
    assert g7.detail.get("skipped") is True
    assert g7.detail.get("reason") == "detection oracle not configured"
    # the patch still approves on the seven other gates plus the skip.
    assert outcome.approved is True


def test_gate_detection_skip_does_not_fabricate_verdicts(
    real_mcp, mock_provisioner
):
    pkg = make_repro_package()
    verifier = PatchVerifier(
        real_mcp, mock_provisioner,
        patched_replay_factory=make_blocking_replay_factory())
    outcome = verifier.verify(
        patch=make_patch(), package=pkg, test_pair=make_test_pair(pkg))
    assert outcome.detection_verdicts == []
