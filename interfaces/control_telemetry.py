"""The control-telemetry adapter contract — purple-team spec §5.

Purple's oracle, coverage model, correlator, and report card are written
against this Protocol. The DerivedEvidenceAdapter ships first; a
NativeEventAdapter slots in later with no change to purple's code.
"""

from __future__ import annotations

from typing import Protocol, runtime_checkable

from interfaces.types import ControlDecision, LaneResult, TelemetryEventInput


@runtime_checkable
class ControlTelemetryAdapter(Protocol):
    """Materialises control decisions + telemetry for one attack execution."""

    def telemetry_for(self, execution: LaneResult) -> list[TelemetryEventInput]:
        """TelemetryEvent records (write-side) for this execution's session."""
        ...

    def decisions_for(self, execution: LaneResult) -> list[ControlDecision]:
        """Control decisions touched by this execution, with observed flags."""
        ...


__all__ = ["ControlTelemetryAdapter"]
