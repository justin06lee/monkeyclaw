"""Phase 2 — gate_detection / gate 7 (spec §6.2, §8 step 5)."""

from __future__ import annotations

from blue_team.patch_verifier import PatchVerifier
from interfaces.types import DetectionVerdict
from test.test_blue_patch_verifier import (
    make_blocking_replay_factory, make_patch, make_repro_package,
    make_test_pair,
)


class _FakeOracle:
    """Stand-in for purple_team.detection_oracle.DetectionOracle."""

    def __init__(self, observability: str):
        self._obs = observability

    def score(self, execution, telemetry):  # noqa: ANN001
        prevention = "blocked"
        quadrant = "PASS" if self._obs == "observed" else "WEAK"
        return [DetectionVerdict(
            execution_id="L1", session_id="S1", zone_id="SBX-FS",
            quadrant=quadrant, prevention=prevention,
            observability=self._obs, rule_id=None, evidence="{}")]


def test_observed_oracle_passes_gate_detection(real_mcp, mock_provisioner):
    pkg = make_repro_package()
    verifier = PatchVerifier(
        real_mcp, mock_provisioner,
        patched_replay_factory=make_blocking_replay_factory(),
        detection_oracle=_FakeOracle("observed"))
    outcome = verifier.verify(
        patch=make_patch(), package=pkg, test_pair=make_test_pair(pkg))
    g7 = next(g for g in outcome.gates if g.name == "gate_detection")
    assert g7.passed is True
    assert outcome.approved is True
    assert outcome.detection_verdicts


def test_silent_oracle_rejects_and_names_surface(real_mcp, mock_provisioner):
    pkg = make_repro_package()
    verifier = PatchVerifier(
        real_mcp, mock_provisioner,
        patched_replay_factory=make_blocking_replay_factory(),
        detection_oracle=_FakeOracle("silent"))
    outcome = verifier.verify(
        patch=make_patch(), package=pkg, test_pair=make_test_pair(pkg))
    assert outcome.approved is False
    assert outcome.failed_gate == "gate_detection"
    assert "blinds detection" in outcome.notes
    assert "SBX-FS" in outcome.notes


def test_oracle_returning_empty_is_a_skip_not_a_pass(
    real_mcp, mock_provisioner
):
    class _EmptyOracle:
        def score(self, execution, telemetry):  # noqa: ANN001
            return []

    pkg = make_repro_package()
    verifier = PatchVerifier(
        real_mcp, mock_provisioner,
        patched_replay_factory=make_blocking_replay_factory(),
        detection_oracle=_EmptyOracle())
    outcome = verifier.verify(
        patch=make_patch(), package=pkg, test_pair=make_test_pair(pkg))
    g7 = next(g for g in outcome.gates if g.name == "gate_detection")
    assert g7.detail.get("skipped") is True
    # never upgraded to a pass on missing evidence (spec §10).
    assert "no detection evidence" in g7.detail.get("reason", "")
