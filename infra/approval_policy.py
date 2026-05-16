"""Severity -> gate-posture policy (approval spec §6.2).

Pure: no DB, no I/O. The one piece of policy operators tune most, so it lives
in its own module. Applies the spec §4.6 default-deny rule.
"""

from __future__ import annotations

from dataclasses import dataclass

from interfaces.config_schema import ApprovalsConfig

_VALID_POSTURES = ("auto_allow", "require_approval")


@dataclass
class GatePolicy:
    """A resolved, immutable view of the approvals config."""

    cfg: ApprovalsConfig

    def posture_for(
        self, severity: str | None, generalization: str | None = None,
    ) -> str:
        """Map a patch severity (+ generalization status) to a gate posture.

        Default-deny: an unknown/missing severity, or an `unconverged`
        generalization result, always resolves to `require_approval`.
        """
        if generalization == "unconverged":
            return "require_approval"
        if severity is None:
            return "require_approval"
        posture = getattr(self.cfg.posture, str(severity).lower(), None)
        if posture not in _VALID_POSTURES:
            return "require_approval"
        return posture

    def ask_expiry_hours(self) -> int:
        return self.cfg.ask_expiry_hours

    def grant_expiry_hours(self) -> int:
        return self.cfg.grant_expiry_hours


def gate_policy(cfg: ApprovalsConfig) -> GatePolicy:
    """Construct the gate policy from the approvals config block."""
    return GatePolicy(cfg=cfg)


__all__ = ["GatePolicy", "gate_policy"]
