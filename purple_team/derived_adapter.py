"""DerivedEvidenceAdapter — purple-team spec §5.

Infers ControlDecision + TelemetryEvent records from the observable
side-effects monitoring_harness already captures (FsDiff, NetworkEvent,
ProcessEvent, InferenceEvent). It is the first dense producer of
telemetry_events. A NativeEventAdapter satisfying the same contract slots
in later with no change to purple's oracle/coverage/correlator code.
"""

from __future__ import annotations

from interfaces.types import (
    ControlDecision,
    LaneResult,
    TelemetryEventInput,
)


class DerivedEvidenceAdapter:
    """Satisfies interfaces.control_telemetry.ControlTelemetryAdapter."""

    def decisions_for(self, execution: LaneResult) -> list[ControlDecision]:
        decisions: list[ControlDecision] = []
        # Network: a NetworkEvent is itself the observable evidence.
        for ev in execution.network_log:
            decisions.append(ControlDecision(
                action_class="network.request",
                target=ev.destination_domain,
                decision="deny" if ev.blocked else "allow",
                observed=True,
                reason_code="blocked_domain" if ev.blocked else "allowed",
                source="derived",
            ))
        # Filesystem: files written outside the sandbox allowed paths are
        # the breach evidence. A diff entry IS an observed event.
        for path in execution.fs_diff.files_outside_allowed_paths:
            decisions.append(ControlDecision(
                action_class="file.write",
                target=path,
                decision="deny",
                observed=True,
                reason_code="outside_allowed_path",
                source="derived",
            ))
        # Process: a process recorded outside the sandbox is an escape.
        for proc in execution.process_log:
            if not proc.inside_sandbox:
                decisions.append(ControlDecision(
                    action_class="process.spawn",
                    target=proc.process_name,
                    decision="deny" if proc.blocked else "allow",
                    observed=True,
                    reason_code="outside_sandbox",
                    source="derived",
                ))
        # Inference routing: PII routed to cloud is a privacy decision.
        for inf in execution.inference_routing_log:
            if inf.pii_detected and inf.routed_to == "cloud":
                decisions.append(ControlDecision(
                    action_class="inference.route",
                    target=inf.routed_to,
                    decision="allow",
                    observed=True,
                    reason_code="pii_to_cloud",
                    source="derived",
                ))
        return decisions

    def telemetry_for(
        self, execution: LaneResult
    ) -> list[TelemetryEventInput]:
        action_to_event = {
            "network.request": "agent.network.request",
            "file.write": "agent.file.write",
            "process.spawn": "agent.shell.started",
            "inference.route": "agent.tool.decision",
        }
        events: list[TelemetryEventInput] = []
        for d in self.decisions_for(execution):
            events.append(TelemetryEventInput(
                session_id=execution.lane_id,
                event_type=action_to_event.get(
                    d.action_class, "agent.tool.decision"),
                actor="victim",
                action_class=d.action_class,
                target=d.target,
                decision=d.decision,
                reason_code=d.reason_code,
                metadata={"source": d.source},
            ))
        return events


__all__ = ["DerivedEvidenceAdapter"]
