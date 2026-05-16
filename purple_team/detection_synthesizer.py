"""detection_synthesizer — purple-team spec §7.4.

Turns a confirmed red finding into a reusable detection rule in the
whitepaper Appendix D shape: detection logic, expected telemetry
signature, response action, bound zone. Detection rules become
first-class assets the oracle and report card reference, and the basis
of "did detection fire" checks for future attacks of the same family.
"""

from __future__ import annotations

import logging

from interfaces.mcp_tools import MonkeyClawMCP
from interfaces.types import DetectionRule, DetectionRuleInput, FindingRecord

LOG = logging.getLogger("monkeyclaw.purple.synthesizer")

# failure_class -> (telemetry signature, response action).
_SIGNATURE_BY_CLASS: dict[str, tuple[str, str]] = {
    "sandbox_escape": (
        "agent.network.request OR agent.file.write decision=deny",
        "block_and_alert"),
    "pii_leak": (
        "agent.tool.decision data_class=pii decision=deny",
        "block_and_redact"),
    "prompt_injection": (
        "agent.tool.requested reason_code=injected_instruction",
        "quarantine_input"),
    "permission_escalation": (
        "agent.approval.requested decision=deny",
        "deny_and_alert"),
    "policy_modification": (
        "agent.file.write target=policy decision=deny",
        "block_and_alert"),
    "information_disclosure": (
        "agent.tool.decision data_class=sensitive decision=deny",
        "block_and_redact"),
}

_VERDICTS_WORTH_A_RULE = {"confirmed", "suspicious"}


class DetectionSynthesizer:
    """Confirmed finding -> reusable DetectionRule."""

    def __init__(self, mcp: MonkeyClawMCP) -> None:
        self.mcp = mcp

    def synthesize(self, finding: FindingRecord) -> DetectionRule | None:
        """Build + persist a detection rule for a confirmed finding.
        Returns None for non-confirmed findings — nothing to detect."""
        if finding.verdict not in _VERDICTS_WORTH_A_RULE:
            return None
        signature, response = _SIGNATURE_BY_CLASS.get(
            finding.failure_class,
            ("agent.tool.decision decision=deny", "alert"))
        logic = (
            f"Detect attacks of family '{finding.failure_class}' in zone "
            f"{finding.zone_id}: match telemetry against the expected "
            f"signature. Derived from finding {finding.finding_id} "
            f"({finding.idea_summary})."
        )
        rule_input = DetectionRuleInput(
            zone_id=finding.zone_id,
            source_finding_id=finding.finding_id,
            logic=logic,
            expected_telemetry_signature=signature,
            response_action=response,
            status="candidate",
        )
        rule_id = self.mcp.log_detection_rule(rule_input)
        LOG.info("synthesized detection rule %s for finding %s",
                 rule_id, finding.finding_id)
        return DetectionRule(
            rule_id=rule_id,
            zone_id=rule_input.zone_id,
            source_finding_id=rule_input.source_finding_id,
            logic=rule_input.logic,
            expected_telemetry_signature=rule_input.expected_telemetry_signature,
            response_action=rule_input.response_action,
            status=rule_input.status,
            created_at="",
        )


__all__ = ["DetectionSynthesizer"]
