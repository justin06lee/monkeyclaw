"""The patch generalization loop — purple-owned mutate -> re-verify -> bounce.

After blue verifies a patch, this loop mutates the original attack with the
deterministic red-team operators, replays each variant against the patched
victim, and — if a variant bypasses — bounces the bypass back to the patch
generator and re-verifies. It generates no attacks and writes no diffs: it
orchestrates existing red mutation, the existing PatchGenerator, and the
unmodified six-gate PatchVerifier. Provably bounded (§9).
"""

from __future__ import annotations

import logging
from dataclasses import dataclass

from interfaces.types import (
    BypassResult,
    GeneralizationResult,
    GeneralizationRound,
    GeneralizationRoundInput,
)
from purple_team.bounce_builder import build as build_bounce
from purple_team.bypass_detector import BypassDetector
from purple_team.mutation_replayer import MutationReplayer
from purple_team.operator_budget import budget_for

LOG = logging.getLogger("monkeyclaw.purple.generalization_loop")


@dataclass
class GeneralizationConfig:
    """Read from configs/monkeyclaw.yaml's purple.generalization block."""

    enabled: bool = True
    max_rounds: int = 3


class GeneralizationLoop:
    """Orchestrates the bounded round loop for one verified patch."""

    def __init__(
        self,
        *,
        mcp: object,
        replay_fn,
        judge_fn,
        patch_generator=None,
        patch_verifier=None,
        cfg: GeneralizationConfig | None = None,
    ) -> None:
        self.mcp = mcp
        self.cfg = cfg or GeneralizationConfig()
        self.replayer = MutationReplayer(replay_fn=replay_fn)
        self.detector = BypassDetector(judge_fn=judge_fn)
        self.patch_generator = patch_generator
        self.patch_verifier = patch_verifier
        self._replay_fn = replay_fn
        self._judge_fn = judge_fn

    def _persist_round(
        self, patch: object, package: object, round_index: int,
        operators: list[str], results: list[BypassResult], outcome: str,
        repatch_patch_id: str | None,
    ) -> GeneralizationRound:
        """Build, best-effort-persist, and return one GeneralizationRound."""
        bypassed = [r for r in results if r.status == "bypassed"]
        inconclusive = [r for r in results if r.status == "inconclusive"]
        row_in = GeneralizationRoundInput(
            patch_id=getattr(patch, "patch_id", ""),
            finding_id=getattr(package, "finding_id", ""),
            vuln_id=getattr(package, "vuln_id", ""),
            zone_id=getattr(package, "affected_zone", ""),
            round_index=round_index,
            operators_tried=operators,
            variants_total=len(results),
            variants_bypassed=len(bypassed),
            variants_inconclusive=len(inconclusive),
            bypass_operators=[r.operator for r in bypassed],
            outcome=outcome,
            repatch_patch_id=repatch_patch_id,
            evidence=[{"variant_id": r.variant_id, "operator": r.operator,
                       "status": r.status, "severity": r.severity}
                      for r in results],
        )
        round_id = ""
        try:
            round_id = self.mcp.log_generalization_round(row_in)
        except Exception as e:  # noqa: BLE001
            LOG.warning("log_generalization_round failed: %s — round kept "
                        "in memory", e)
        return GeneralizationRound(
            round_id=round_id or f"GR-mem-{round_index}",
            patch_id=row_in.patch_id, finding_id=row_in.finding_id,
            vuln_id=row_in.vuln_id, zone_id=row_in.zone_id,
            round_index=round_index, operators_tried=operators,
            variants_total=row_in.variants_total,
            variants_bypassed=row_in.variants_bypassed,
            variants_inconclusive=row_in.variants_inconclusive,
            bypass_operators=row_in.bypass_operators, outcome=outcome,
            repatch_patch_id=repatch_patch_id, evidence=row_in.evidence,
            created_at="")

    def run(
        self, patch: object, package: object, test_pair: object, task: object
    ) -> GeneralizationResult:
        """The full bounded loop. Round 0 verifies the literal patch's
        family; rounds 1..max_rounds re-patch against each round's bypass.
        Exits GENERALIZED (no bypass within budget) or UNCONVERGED."""
        finding_id = getattr(package, "finding_id", "")
        zone_id = getattr(package, "affected_zone", "")
        rounds: list[GeneralizationRound] = []
        current_patch = patch
        current_task = task
        prior_bypass_ops: list[str] = []

        for round_index in range(self.cfg.max_rounds + 1):
            operators = budget_for(round_index, zone_id, prior_bypass_ops)
            variants = self.replayer.replay_variants(
                current_patch, package, operators)
            results = [self.detector.score(v, package) for v in variants]
            bypassed = [r for r in results if r.status == "bypassed"]
            inconclusive = [r for r in results
                            if r.status == "inconclusive"]

            # Every variant inconclusive -> never claim generalization.
            if results and len(inconclusive) == len(results):
                rnd = self._persist_round(
                    current_patch, package, round_index, operators, results,
                    "unconverged", None)
                rounds.append(rnd)
                return GeneralizationResult(
                    finding_id=finding_id,
                    final_patch_id=getattr(current_patch, "patch_id", ""),
                    status="unconverged", reason="replay_unavailable",
                    rounds=rounds, open_bypasses=[])

            # No bypass -> the patch generalized.
            if not bypassed:
                rnd = self._persist_round(
                    current_patch, package, round_index, operators, results,
                    "generalized", None)
                rounds.append(rnd)
                return GeneralizationResult(
                    finding_id=finding_id,
                    final_patch_id=getattr(current_patch, "patch_id", ""),
                    status="generalized", reason=None, rounds=rounds,
                    open_bypasses=[])

            # A bypass exists. Out of round budget -> UNCONVERGED.
            if round_index == self.cfg.max_rounds:
                rnd = self._persist_round(
                    current_patch, package, round_index, operators, results,
                    "unconverged", None)
                rounds.append(rnd)
                return GeneralizationResult(
                    finding_id=finding_id,
                    final_patch_id=getattr(current_patch, "patch_id", ""),
                    status="unconverged", reason="round_budget_exhausted",
                    rounds=rounds, open_bypasses=bypassed)

            # Bounce: build the constraint, re-patch, re-verify.
            prior_bypass_ops = sorted(
                {*prior_bypass_ops, *(r.operator for r in bypassed)})
            transcripts = {
                v.operator: v.mutated_transcript for v in variants
                if v.operator in {r.operator for r in bypassed}}
            current_task, _constraint = build_bounce(
                current_task, results, transcripts)
            repatched = self._repatch(current_task, package, test_pair)
            if repatched is None:
                rnd = self._persist_round(
                    current_patch, package, round_index, operators, results,
                    "unconverged", None)
                rounds.append(rnd)
                return GeneralizationResult(
                    finding_id=finding_id,
                    final_patch_id=getattr(current_patch, "patch_id", ""),
                    status="unconverged", reason="repatch_failed_gates",
                    rounds=rounds, open_bypasses=bypassed)
            rnd = self._persist_round(
                current_patch, package, round_index, operators, results,
                "bounced", getattr(repatched, "patch_id", None))
            rounds.append(rnd)
            current_patch = repatched

        # Unreachable — the loop always returns inside the range.
        raise RuntimeError(  # pragma: no cover
            "generalization loop did not terminate")

    def _repatch(
        self, task: object, package: object, test_pair: object
    ) -> object | None:
        """Generate re-patch candidates and return the first to pass the full
        six-gate verifier, or None if none pass / none are produced."""
        if self.patch_generator is None or self.patch_verifier is None:
            return None
        candidates = self.patch_generator.generate_for_task(task)
        for cand in candidates:
            outcome = self.patch_verifier.verify(
                patch=cand, package=package, test_pair=test_pair)
            if getattr(outcome, "approved", False):
                return cand
        return None


__all__ = ["GeneralizationConfig", "GeneralizationLoop"]
