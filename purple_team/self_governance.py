"""self_governance — purple-team spec §7.8.

Points the detection-as-pass machinery at MonkeyClaw itself. MonkeyClaw is
an adversarial agent system; by the whitepaper's own logic it must obey the
controls it tests for. This module validates that MonkeyClaw's own agents
(attacker, cold-verifier, patch generator, cyber-specialised model lanes)
run under: bounded egress, sandboxed execution, no secret-path reads, and a
complete audit trail. Produces a self-governance section in the report card.

Risk-isolated to this dedicated module (spec §7.8): it can be disabled by
config (purple.self_governance_enabled) without touching the victim path.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass

from interfaces.mcp_tools import MonkeyClawMCP
from interfaces.types import SelfGovernanceCheck, SelfGovernanceReport

LOG = logging.getLogger("monkeyclaw.purple.self_governance")


@dataclass
class AgentProfile:
    """The governance posture of one MonkeyClaw agent. The orchestrator
    builds these from runtime config; tests supply them directly."""

    name: str
    egress_bounded: bool
    sandboxed: bool
    reads_secret_paths: bool
    audit_trail_complete: bool


# (check name, failure detail).
_CONTROLS: list[tuple[str, str]] = [
    ("bounded_egress", "egress is not bounded"),
    ("sandboxed_execution", "execution is not sandboxed"),
    ("no_secret_path_reads", "reads secret paths"),
    ("complete_audit_trail", "audit trail is incomplete"),
]


class SelfGovernance:
    """Audits MonkeyClaw's own agents against its own controls."""

    def __init__(self, mcp: MonkeyClawMCP) -> None:
        self.mcp = mcp

    def audit_self(
        self, agents: list[AgentProfile]
    ) -> SelfGovernanceReport:
        checks: list[SelfGovernanceCheck] = []
        violations: list[str] = []
        for agent in agents:
            outcomes = {
                "bounded_egress": agent.egress_bounded,
                "sandboxed_execution": agent.sandboxed,
                "no_secret_path_reads": not agent.reads_secret_paths,
                "complete_audit_trail": agent.audit_trail_complete,
            }
            for check_name, fail_detail in _CONTROLS:
                passed = outcomes[check_name]
                detail = ("compliant" if passed
                          else f"agent {agent.name} {fail_detail}")
                checks.append(SelfGovernanceCheck(
                    name=check_name, subject=agent.name,
                    passed=passed, detail=detail))
                if not passed:
                    violations.append(detail)
        report = SelfGovernanceReport(
            checks=checks, violations=violations,
            passed=not violations)
        if violations:
            LOG.warning("self-governance: %d violation(s): %s",
                        len(violations), "; ".join(violations))
        return report


__all__ = ["AgentProfile", "SelfGovernance"]
