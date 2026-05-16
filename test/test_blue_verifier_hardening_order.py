"""Phase 1 — gate ordering: gate1 fails before gate1b runs (spec §4.1)."""

from __future__ import annotations

from blue_team.patch_verifier import PatchVerifier
from test.test_blue_patch_verifier import (
    make_leaking_replay_factory, make_patch, make_repro_package,
    make_test_pair,
)


def test_failed_recorded_repro_short_circuits_before_gate1b(
    real_mcp, mock_provisioner
):
    """A patch that does NOT block the recorded repro fails at
    gate1_regression — gate1b never runs (cheapest failure first)."""
    pkg = make_repro_package()
    verifier = PatchVerifier(
        real_mcp, mock_provisioner,
        # leaking factory: even the recorded repro is judged confirmed.
        patched_replay_factory=make_leaking_replay_factory())
    outcome = verifier.verify(
        patch=make_patch(), package=pkg, test_pair=make_test_pair(pkg))
    assert outcome.approved is False
    assert outcome.failed_gate == "gate1_regression"
    gate_names = [g.name for g in outcome.gates]
    assert "gate1b_mutation_robustness" not in gate_names


def test_all_pass_path_reports_eight_gates(real_mcp, mock_provisioner):
    """The fully-passing path now reports eight gates including gate1b
    and gate_detection."""
    from test.test_blue_patch_verifier import make_blocking_replay_factory

    pkg = make_repro_package()
    verifier = PatchVerifier(
        real_mcp, mock_provisioner,
        patched_replay_factory=make_blocking_replay_factory())
    outcome = verifier.verify(
        patch=make_patch(), package=pkg, test_pair=make_test_pair(pkg))
    assert outcome.approved is True
    names = [g.name for g in outcome.gates]
    assert names == [
        "gate_diff_applies", "gate1_regression",
        "gate1b_mutation_robustness", "gate2_functionality",
        "gate3_full_suite", "gate_control_plane", "gate_telemetry",
        "gate_detection",
    ]
