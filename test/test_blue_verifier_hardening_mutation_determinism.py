"""Phase 1 — gate1b is byte-for-byte reproducible (spec §4.2, §12)."""

from __future__ import annotations

from blue_team.patch_verifier import PatchVerifier
from test.test_blue_patch_verifier import (
    make_blocking_replay_factory, make_patch, make_repro_package,
    make_test_pair,
)


def _run(real_mcp, mock_provisioner):
    pkg = make_repro_package()
    verifier = PatchVerifier(
        real_mcp, mock_provisioner,
        patched_replay_factory=make_blocking_replay_factory())
    outcome = verifier.verify(
        patch=make_patch(), package=pkg, test_pair=make_test_pair(pkg))
    g1b = next(g for g in outcome.gates
               if g.name == "gate1b_mutation_robustness")
    return g1b.detail["variant_results"]


def test_gate1b_variant_results_are_byte_identical(real_mcp, mock_provisioner):
    first = _run(real_mcp, mock_provisioner)
    second = _run(real_mcp, mock_provisioner)
    assert first == second
    # hashes are stable across runs — mutations carry no LLM, no randomness.
    assert [v["variant_hash"] for v in first] == [
        v["variant_hash"] for v in second]
