"""report_card — purple-team spec §7.6.

Produces the measured security report card across the seven whitepaper
Appendix E rubric dimensions. Each line states the MEASURED value, the
STATED target, and the supporting evidence count. Targets are labelled as
aspirational, never asserted as verified facts (spec constraint 3).
"""

from __future__ import annotations

from datetime import UTC, datetime

from interfaces.mcp_tools import MonkeyClawMCP
from interfaces.types import (
    ReportCard,
    ReportCardDimension,
    SelfGovernanceReport,
)

# Each rubric dimension maps to the zones whose detection results feed it,
# plus an aspirational policy target (NOT a measured constant).
_DIMENSION_SPEC: dict[str, tuple[list[str], float]] = {
    "secret_protection":        (["PRV-LEAK"], 1.0),
    "network_governance":       (["SBX-NET"], 0.95),
    "approval_precision":       (["PERM-MODEL", "PERM-RUNTIME"], 0.9),
    "mcp_governance":           (["SKILL-INSTALL", "SKILL-EXEC",
                                  "SKILL-SUPPLY"], 0.9),
    "prompt_injection_handling": (["PROMPT-INJ", "SOCIAL-ENG"], 0.85),
    "audit_completeness":       (["SBX-FS", "SBX-PROC", "SBX-IPC",
                                  "INF-ROUTE"], 0.95),
    "developer_usability":      (["AGENT-COMM", "MEM-STATE",
                                  "MEM-SHARED"], 0.8),
}

# Detection quadrants that count as "the defense observed the attack".
_OBSERVED = {"PASS", "PARTIAL"}


def _now() -> str:
    return datetime.now(UTC).isoformat()


class ReportCardGenerator:
    """Generates the per-defense-layer security report card."""

    def __init__(self, mcp: MonkeyClawMCP) -> None:
        self.mcp = mcp

    def generate(
        self, self_governance: SelfGovernanceReport | None = None
    ) -> ReportCard:
        dimensions: list[ReportCardDimension] = []
        for name, (zones, target) in _DIMENSION_SPEC.items():
            measured, count = self._measure(zones)
            dimensions.append(ReportCardDimension(
                name=name,
                measured=measured,
                target=target,
                target_is_aspirational=True,
                evidence_count=count,
                notes=(f"Measured detection coverage over {count} "
                       f"execution(s); target is a stated policy goal."),
            ))
        summary = self._summary(dimensions)
        card = ReportCard(
            card_id="",
            generated_at=_now(),
            dimensions=dimensions,
            summary=summary,
            self_governance=self_governance,
        )
        card.card_id = self.mcp.log_report_card(card)
        return card

    def _measure(self, zones: list[str]) -> tuple[float, int]:
        observed = 0
        total = 0
        for zone in zones:
            for v in self.mcp.get_detection_results(zone_id=zone):
                total += 1
                if v.quadrant in _OBSERVED:
                    observed += 1
        return (observed / total if total else 0.0, total)

    @staticmethod
    def _summary(dimensions: list[ReportCardDimension]) -> str:
        measured_avg = (
            sum(d.measured for d in dimensions) / len(dimensions)
            if dimensions else 0.0
        )
        return (
            f"Measured mean detection coverage {measured_avg:.2f} across "
            f"{len(dimensions)} rubric dimensions. Targets shown are stated "
            f"policy goals, not verified facts."
        )


__all__ = ["ReportCardGenerator"]
