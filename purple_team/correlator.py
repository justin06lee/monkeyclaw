"""correlator — purple-team spec §7.5.

Builds the unified evidence/decision timeline (the whitepaper "session
timeline") by joining, per session: the red finding, telemetry events,
the derived control decisions, the blue patch, and the detection rules.
This is the artifact an investigator reads and the data source for the
evidence-timeline dashboard view.
"""

from __future__ import annotations

import logging
from collections.abc import Callable

from interfaces.mcp_tools import MonkeyClawMCP
from interfaces.types import (
    ControlDecision,
    FindingRecord,
    SessionTimeline,
    TelemetryEvent,
)

LOG = logging.getLogger("monkeyclaw.purple.correlator")


class Correlator:
    """Joins per-session artifacts into a SessionTimeline."""

    def __init__(
        self,
        mcp: MonkeyClawMCP,
        *,
        zone_for_session: Callable[[str], str | None] | None = None,
    ) -> None:
        self.mcp = mcp
        self._zone_for_session = zone_for_session

    def timeline(self, session_id: str) -> SessionTimeline:
        events = self.mcp.get_session_timeline(session_id)
        decisions = self._decisions_from_events(events)
        finding = self._finding_for_session(session_id, events)
        zone = (
            self._zone_for_session(session_id)
            if self._zone_for_session else
            (finding.zone_id if finding else None)
        )
        rules = self.mcp.get_detection_rules(zone) if zone else []
        patches = self._patches_for_finding(finding)
        return SessionTimeline(
            session_id=session_id,
            finding=finding,
            telemetry_events=events,
            control_decisions=decisions,
            patches=patches,
            detection_rules=rules,
        )

    @staticmethod
    def _decisions_from_events(
        events: list[TelemetryEvent]
    ) -> list[ControlDecision]:
        decisions: list[ControlDecision] = []
        for e in events:
            if e.decision is None:
                continue
            decisions.append(ControlDecision(
                action_class=e.action_class,
                target=e.target,
                decision=e.decision,
                observed=True,  # a telemetry row IS the observation
                reason_code=e.reason_code,
                source="derived",
            ))
        return decisions

    def _finding_for_session(
        self, session_id: str, events: list[TelemetryEvent]
    ) -> FindingRecord | None:
        # session_id == lane_id; findings carry idea_id, lanes carry idea_id.
        # Match newest finding whose idea/lane shares this session.
        try:
            rows = self.mcp.search_findings(
                query=session_id, zone=None, top_k=1)
        except Exception as e:  # noqa: BLE001
            LOG.debug("finding lookup failed for %s: %s", session_id, e)
            return None
        return rows[0] if rows else None

    def _patches_for_finding(
        self, finding: FindingRecord | None
    ) -> list[dict]:
        if finding is None:
            return []
        try:
            rows = self.mcp.db.fetchall(  # type: ignore[attr-defined]
                "SELECT patch_id, status, approach FROM patches "
                "WHERE vuln_ids LIKE ?", (f"%{finding.finding_id}%",))
            return [dict(r) for r in rows]
        except Exception as e:  # noqa: BLE001
            LOG.debug("patch lookup failed: %s", e)
            return []


__all__ = ["Correlator"]
