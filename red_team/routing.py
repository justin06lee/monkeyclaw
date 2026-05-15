"""Post-judgment routing.

Per .agents/person_2_redteam.md Deliverable 6:

- **confirmed** → log_finding + push_to_repro_queue(high) + update_zone_coverage(+0.05) + send_alert
- **suspicious** → log_finding + push_to_repro_queue(low) + update_zone_coverage(+0.05)
- **clean** → log_finding + update_zone_coverage(+0.05)

All three verdicts update zone coverage — the zone was tested regardless
of outcome.

Alerts are gated on severity (>= configurable floor) so noisy low-severity
confirmations don't spam Telegram.
"""

from __future__ import annotations

import json
import logging
from dataclasses import asdict

from interfaces.mcp_tools import MonkeyClawMCP
from interfaces.types import FindingInput, IdeaObject, JudgmentResult

LOG = logging.getLogger("monkeyclaw.red.routing")


COVERAGE_INCREMENT = 0.05

SEVERITY_ORDER = {"low": 0, "medium": 1, "high": 2, "critical": 3}


def _evidence_json(judgment: JudgmentResult) -> str:
    return json.dumps([asdict(c) for c in judgment.evidence])


def _alert_message(idea: IdeaObject, judgment: JudgmentResult) -> str:
    return (
        f"[{judgment.verdict.upper()} / {judgment.severity}] "
        f"{idea.zone_id} — {idea.title}\n"
        f"tier={judgment.tier_that_caught} class={judgment.failure_class}\n"
        f"lane={judgment.lane_id} idea={judgment.idea_id}\n"
        f"reason: {judgment.reasoning[:300]}"
    )


def _reusability(judgment: JudgmentResult) -> float:
    """Heuristic reusability score for the FindingRecord.

    - Confirmed + critical/high → 0.8 (very reusable)
    - Confirmed + medium/low → 0.5
    - Suspicious → 0.4
    - Clean → 0.1
    """
    if judgment.verdict == "confirmed":
        return 0.8 if SEVERITY_ORDER.get(judgment.severity, 0) >= 2 else 0.5
    if judgment.verdict == "suspicious":
        return 0.4
    return 0.1


def route_judgment(
    judgment: JudgmentResult,
    idea: IdeaObject,
    mcp: MonkeyClawMCP,
    *,
    alert_severity_floor: str = "high",
) -> str:
    """Apply the routing rules. Returns the finding_id."""
    finding_input = FindingInput(
        cycle_id=idea.cycle_id,
        idea_id=judgment.idea_id,
        zone_id=judgment.zone_id,
        source_mode=idea.source_mode,
        idea_summary=f"{idea.title}: {idea.approach}"[:1000],
        verdict=judgment.verdict,
        tier_caught=judgment.tier_that_caught,
        failure_class=judgment.failure_class,
        severity=judgment.severity,
        evidence=_evidence_json(judgment),
        reusability=_reusability(judgment),
    )
    finding_id = mcp.log_finding(finding_input)

    # Always update coverage — the zone was tested.
    mcp.update_zone_coverage(judgment.zone_id, COVERAGE_INCREMENT)

    if judgment.verdict == "confirmed":
        mcp.push_to_repro_queue(finding_id, priority="high")
        if SEVERITY_ORDER.get(judgment.severity, 0) >= SEVERITY_ORDER.get(
                alert_severity_floor, 0
        ):
            mcp.send_alert(_alert_message(idea, judgment), severity=judgment.severity)
        LOG.info("routed confirmed finding %s → repro_queue(high)", finding_id)
    elif judgment.verdict == "suspicious":
        mcp.push_to_repro_queue(finding_id, priority="low")
        LOG.info("routed suspicious finding %s → repro_queue(low)", finding_id)
    else:
        LOG.info("routed clean finding %s — coverage only", finding_id)

    return finding_id


__all__ = ["COVERAGE_INCREMENT", "route_judgment"]
