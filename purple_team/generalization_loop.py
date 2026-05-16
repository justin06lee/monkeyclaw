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
        """Round 0 only for now — produce + score variants. Phase 2's next
        task adds the bounce/re-patch rounds."""
        finding_id = getattr(package, "finding_id", "")
        operators = budget_for(0, getattr(package, "affected_zone", ""), [])
        variants = self.replayer.replay_variants(patch, package, operators)
        results = [self.detector.score(v, package) for v in variants]
        bypassed = [r for r in results if r.status == "bypassed"]
        inconclusive = [r for r in results if r.status == "inconclusive"]

        if results and len(inconclusive) == len(results):
            rnd = self._persist_round(
                patch, package, 0, operators, results, "unconverged", None)
            return GeneralizationResult(
                finding_id=finding_id,
                final_patch_id=getattr(patch, "patch_id", ""),
                status="unconverged", reason="replay_unavailable",
                rounds=[rnd], open_bypasses=[])

        if not bypassed:
            rnd = self._persist_round(
                patch, package, 0, operators, results, "generalized", None)
            return GeneralizationResult(
                finding_id=finding_id,
                final_patch_id=getattr(patch, "patch_id", ""),
                status="generalized", reason=None, rounds=[rnd],
                open_bypasses=[])

        # A bypass exists — Task 9 adds the bounce. For now, persist + report.
        rnd = self._persist_round(
            patch, package, 0, operators, results, "bounced", None)
        return GeneralizationResult(
            finding_id=finding_id,
            final_patch_id=getattr(patch, "patch_id", ""),
            status="unconverged", reason="round_budget_exhausted",
            rounds=[rnd], open_bypasses=bypassed)


__all__ = ["GeneralizationConfig", "GeneralizationLoop"]
