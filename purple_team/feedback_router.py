"""feedback_router — purple-team spec §7.7.

Converts purple findings into steering signals:
  - Blind-spot signal -> red: zones with low detection coverage or recent
    FAIL/WEAK quadrants get a priority boost (consumed by
    red_team.priority.score_ideas via detection_coverage_gap).
  - Regression signal -> blue: any control that regressed from PASS, or any
    PARTIAL quadrant (detection fired, prevention failed), becomes a blue
    fix task.

Best-effort (spec §12): a routing failure logs an alert and never aborts
the cycle.
"""

from __future__ import annotations

import logging

from interfaces.mcp_tools import MonkeyClawMCP
from interfaces.types import ControlValidationRun, DetectionVerdict

LOG = logging.getLogger("monkeyclaw.purple.feedback")

# Quadrants that indicate the defense is blind in a zone.
_BLIND_QUADRANTS = {"FAIL", "WEAK"}
# Quadrants that need a blue fix (prevention failed despite detection).
_BLUE_QUADRANTS = {"PARTIAL", "FAIL"}


class FeedbackRouter:
    """Routes purple findings to red priority and the blue queue."""

    def __init__(self, mcp: MonkeyClawMCP) -> None:
        self.mcp = mcp
        self._blue_tasks: list[str] = []
        self._detection_gap: dict[str, float] = {}

    def route(
        self,
        verdicts: list[DetectionVerdict],
        validation_run: ControlValidationRun | None,
    ) -> list[str]:
        """Compute + emit steering signals. Returns a human-readable
        signal log. Never raises."""
        signals: list[str] = []
        try:
            signals.extend(self._route_blind_spots(verdicts))
            signals.extend(self._route_partials(verdicts))
            if validation_run is not None:
                signals.extend(self._route_regressions(validation_run))
        except Exception as e:  # noqa: BLE001
            LOG.exception("feedback routing failed (best-effort): %s", e)
            try:
                self.mcp.send_alert(
                    f"purple feedback routing failed: {e!r}", severity="low")
            except Exception:  # noqa: BLE001
                pass
        return signals

    def _route_blind_spots(
        self, verdicts: list[DetectionVerdict]
    ) -> list[str]:
        signals: list[str] = []
        for v in verdicts:
            if v.quadrant in _BLIND_QUADRANTS:
                # WEAK is a partial blind spot; FAIL is total.
                gap = 1.0 if v.quadrant == "FAIL" else 0.5
                self._detection_gap[v.zone_id] = max(
                    self._detection_gap.get(v.zone_id, 0.0), gap)
                signals.append(
                    f"red priority boost: zone {v.zone_id} is blind "
                    f"({v.quadrant})")
        return signals

    def _route_partials(
        self, verdicts: list[DetectionVerdict]
    ) -> list[str]:
        signals: list[str] = []
        for v in verdicts:
            if v.quadrant in _BLUE_QUADRANTS:
                task = (f"blue fix task: zone {v.zone_id} prevention failed "
                        f"({v.quadrant}) for execution {v.execution_id}")
                self._blue_tasks.append(task)
                signals.append(task)
        return signals

    def _route_regressions(
        self, run: ControlValidationRun
    ) -> list[str]:
        signals: list[str] = []
        for reg in run.regressions:
            task = (f"blue fix task: control case {reg['case_id']} regressed "
                    f"{reg.get('prior')} -> {reg.get('now')}")
            self._blue_tasks.append(task)
            signals.append(task)
        return signals

    def detection_coverage_gap(self) -> dict[str, float]:
        """The per-zone blind-spot signal for red_team.priority.score_ideas."""
        return dict(self._detection_gap)

    def blue_tasks(self) -> list[str]:
        """Fix tasks routed to the blue queue this cycle."""
        return list(self._blue_tasks)


__all__ = ["FeedbackRouter"]
