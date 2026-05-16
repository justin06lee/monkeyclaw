"""pipeline — purple-team spec §7.9, §9.

Assembles the purple pipeline and exposes a single entrypoint the
orchestrator calls once per cycle: run(cycle_context) -> PurpleCycleResult.

Data flow per cycle (spec §9):
  1. The adapter materialises telemetry from each execution.
  2. detection_oracle scores each execution into a quadrant.
  3. coverage_model updates detection coverage for the touched zones.
  4. control_validator runs the inline subset (or the full sweep on cadence).
  5. detection_synthesizer turns confirmed findings into DetectionRules.
  6. report_card regenerates.
  7. feedback_router boosts red priority on blind spots and pushes
     regressions / PARTIALs to the blue queue.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field

from interfaces.mcp_tools import MonkeyClawMCP
from interfaces.types import (
    DetectionVerdict,
    FindingRecord,
    JudgmentResult,
    LaneResult,
    PurpleCycleResult,
)
from purple_team.control_validator import CaseRunner, ControlValidator
from purple_team.correlator import Correlator
from purple_team.coverage_model import CoverageModel
from purple_team.derived_adapter import DerivedEvidenceAdapter
from purple_team.detection_oracle import DetectionOracle
from purple_team.detection_synthesizer import DetectionSynthesizer
from purple_team.feedback_router import FeedbackRouter
from purple_team.report_card import ReportCardGenerator
from purple_team.self_governance import AgentProfile, SelfGovernance
from red_team.policy_corpus import PolicyCorpusCase

LOG = logging.getLogger("monkeyclaw.purple.pipeline")


def _default_agent_profiles() -> list[AgentProfile]:
    """The governance posture of MonkeyClaw's own agents in mock mode:
    every agent runs bounded, sandboxed, secret-free, with a full audit
    trail — the posture the real runtime must preserve."""
    names = ["attacker", "cold-verifier", "patch-generator", "judge"]
    return [AgentProfile(
        name=n, egress_bounded=True, sandboxed=True,
        reads_secret_paths=False, audit_trail_complete=True)
        for n in names]


@dataclass
class CycleContext:
    """What the orchestrator hands the purple pipeline once per cycle."""

    cycle_id: int
    zone_id: str
    # (execution, red judgment) pairs from the red cycle.
    executions: list[tuple[LaneResult, JudgmentResult]] = field(
        default_factory=list)
    confirmed_findings: list[FindingRecord] = field(default_factory=list)


class PurplePipeline:
    """The assembled purple pipeline — one run() per cycle."""

    def __init__(
        self,
        mcp: MonkeyClawMCP,
        *,
        corpus: list[PolicyCorpusCase] | None = None,
        case_runner: CaseRunner,
        full_sweep_every: int = 10,
        self_governance_enabled: bool = True,
    ) -> None:
        self.mcp = mcp
        self.adapter = DerivedEvidenceAdapter()
        self.oracle = DetectionOracle()
        self.coverage = CoverageModel(mcp)
        self.validator = ControlValidator(
            mcp, corpus=corpus, case_runner=case_runner)
        self.synthesizer = DetectionSynthesizer(mcp)
        self.correlator = Correlator(mcp)
        self.report = ReportCardGenerator(mcp)
        self.router = FeedbackRouter(mcp)
        self.self_governance = SelfGovernance(mcp)
        self.full_sweep_every = max(1, full_sweep_every)
        self.self_governance_enabled = self_governance_enabled

    def run(self, ctx: CycleContext) -> PurpleCycleResult:
        # 1-3: materialise telemetry, score, update coverage.
        all_verdicts: list[DetectionVerdict] = []
        for execution, judgment in ctx.executions:
            for event in self.adapter.telemetry_for(execution):
                self.mcp.log_telemetry_event(event)
            decisions = self.adapter.decisions_for(execution)
            verdicts = self.oracle.score(execution, judgment, decisions)
            for v in verdicts:
                self.mcp.log_detection_result(v)
            all_verdicts.extend(verdicts)
        by_zone: dict[str, list[DetectionVerdict]] = {}
        for v in all_verdicts:
            by_zone.setdefault(v.zone_id, []).append(v)
        for zone_id, zone_verdicts in by_zone.items():
            self.coverage.update(zone_id, zone_verdicts)

        # 4: validate — full sweep on cadence, inline otherwise.
        is_sweep = ctx.cycle_id % self.full_sweep_every == 0
        validation_run = (
            self.validator.validate_full() if is_sweep
            else self.validator.validate_inline(ctx.zone_id)
        )

        # 5: synthesise detection rules for confirmed findings.
        new_rules = []
        for finding in ctx.confirmed_findings:
            rule = self.synthesizer.synthesize(finding)
            if rule is not None:
                new_rules.append(rule)

        # 6: regenerate the report card (with self-governance on full sweeps).
        self_gov = None
        if is_sweep and self.self_governance_enabled:
            self_gov = self.self_governance.audit_self(
                _default_agent_profiles())
        report_card = self.report.generate(self_governance=self_gov)

        # 7: route feedback signals.
        routed = self.router.route(all_verdicts, validation_run)

        return PurpleCycleResult(
            verdicts=all_verdicts,
            validation_run=validation_run,
            report_card=report_card,
            new_rules=new_rules,
            routed_signals=routed,
        )

    def detection_coverage_gap(self) -> dict[str, float]:
        """The blind-spot signal for red_team.priority — read after run()."""
        return self.router.detection_coverage_gap()


__all__ = ["CycleContext", "PurplePipeline"]
