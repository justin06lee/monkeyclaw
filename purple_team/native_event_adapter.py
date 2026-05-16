"""NativeEventAdapter — native-event-adapter spec §5.1.

Ingests OpenClaw hook-event JSONL produced by the `purple-team-telemetry`
plugin and converts each line to purple `TelemetryEvent` / `ControlDecision`
records. Satisfies the SAME `interfaces.control_telemetry.ControlTelemetryAdapter`
contract as `DerivedEvidenceAdapter`, so purple's oracle, coverage model,
correlator, and report card never change when the adapter is swapped
(spec §3).

The event source is a JSONL file the OpenClaw plugin appends to; each line is:

    {"hook": "before_tool_call", "ts": 1747000000123,
     "payload": {...}, "decision": {"decision": "allow"}}

`decision` is present only for the 4 decision hooks. `ingest()` tails the
file from a tracked offset (resumable); malformed lines and unknown hooks
are skipped and counted, never aborting the run (spec §9).
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field

from interfaces.types import ControlDecision, LaneResult, TelemetryEventInput

LOG = logging.getLogger("monkeyclaw.purple.native_adapter")

# Hooks that carry a control decision (spec §6 — the 4 decision hooks).
_DECISION_HOOKS: frozenset[str] = frozenset(
    {"before_agent_run", "before_tool_call", "subagent_spawning",
     "outbound_dispatch"}
)

# Direct hook -> purple event_type (spec §6 mapping table). `after_tool_call`
# is intentionally absent — it is polymorphic on toolName (see _tool_event).
# `before_tool_call` is absent — it yields only a ControlDecision.
_HOOK_MAP: dict[str, str] = {
    "session_start": "agent.session.start",
    "session_resume": "agent.session.start",
    "session_end": "agent.session.end",
    "before_agent_run": "agent.turn.start",
    "llm_input": "agent.llm.request",
    "model_call_started": "agent.llm.request",
    "model_call_ended": "agent.llm.response",
    "llm_output": "agent.llm.response",
    "subagent_spawning": "agent.subagent.spawn",
    "subagent_spawned": "agent.subagent.spawned",
    "subagent_ended": "agent.subagent.ended",
    "agent_end": "agent.turn.end",
    "outbound_dispatch": "agent.message.out",
    "message_delivery": "agent.message.out",
    "network.request.blocked": "agent.network.blocked",
    "network.request.approved": "agent.network.approved",
    "network.request.denied": "agent.network.denied",
}


def _tool_event(tool_name: str | None) -> str:
    """`after_tool_call` is polymorphic on toolName (spec §6)."""
    name = (tool_name or "").lower()
    if name == "file_read":
        return "agent.file.read"
    if name == "file_write":
        return "agent.file.write"
    if name == "file_delete":
        return "agent.file.delete"
    if name in {"bash", "exec", "shell"}:
        return "agent.shell.ended"
    if name.startswith("browser_"):
        return "agent.browser." + (name[len("browser_"):] or "action")
    if name.startswith("mcp_"):
        return "agent.mcp.invoked"
    return "agent.tool.ended"


@dataclass
class IngestResult:
    """The outcome of one ingest() pass over the hook-event JSONL."""

    events: list[TelemetryEventInput] = field(default_factory=list)
    decisions: list[ControlDecision] = field(default_factory=list)
    offset: int = 0          # byte offset to resume from next time
    lines_read: int = 0
    skipped: int = 0         # malformed JSON / missing-hook lines
    unknown_hooks: int = 0   # well-formed lines with an unrecognised hook


def _session_of(payload: dict) -> str:
    """The correlation key threading records together (spec §5.1)."""
    for key in ("sessionKey", "runId", "session_id", "run_id"):
        val = payload.get(key)
        if val:
            return str(val)
    return "unknown"


def _decision_value(raw: dict | None) -> str:
    """OpenClaw decision verbs -> purple PolicyDecisionType (allow|deny|ask)."""
    verb = (raw or {}).get("decision", "allow")
    if verb in {"block", "cancel"}:
        return "deny"
    if verb in {"requireApproval", "override"}:
        return "ask"
    return "allow"


class NativeEventAdapter:
    """Satisfies interfaces.control_telemetry.ControlTelemetryAdapter."""

    def __init__(self) -> None:
        # Records accumulated across ingest() calls, keyed by session id.
        self._events: dict[str, list[TelemetryEventInput]] = {}
        self._decisions: dict[str, list[ControlDecision]] = {}

    # -- ControlTelemetryAdapter contract -----------------------------------

    def telemetry_for(
        self, execution: LaneResult
    ) -> list[TelemetryEventInput]:
        """TelemetryEvent records for this execution's session."""
        return list(self._events.get(execution.lane_id, []))

    def decisions_for(self, execution: LaneResult) -> list[ControlDecision]:
        """Control decisions touched by this execution."""
        return list(self._decisions.get(execution.lane_id, []))

    # -- tailing ingest -----------------------------------------------------

    def ingest(self, source_path, since_offset: int = 0) -> IngestResult:
        """Tail the hook-event JSONL from `since_offset` and convert lines.

        Resumable: pass the returned `offset` back as `since_offset` next
        time. A missing/empty source yields an empty result and logs once
        (spec §9) — purple then degrades to observability=unknown.
        """
        import os

        path = os.path.expanduser(str(source_path))
        result = IngestResult(offset=since_offset)
        if not os.path.exists(path):
            LOG.info("native adapter: source file %s absent — no events", path)
            return result
        with open(path, encoding="utf-8") as fh:
            fh.seek(since_offset)
            for raw_line in fh:
                result.lines_read += 1
                self._ingest_line(raw_line, result)
            result.offset = fh.tell()
        return result

    def _ingest_line(self, raw_line: str, result: IngestResult) -> None:
        line = raw_line.strip()
        if not line:
            result.lines_read -= 1  # blank lines are not lines
            return
        try:
            record = json.loads(line)
        except (json.JSONDecodeError, ValueError):
            result.skipped += 1
            LOG.warning("native adapter: skipped malformed JSONL line")
            return
        hook = record.get("hook")
        if not hook:
            result.skipped += 1
            LOG.warning("native adapter: skipped line with no hook")
            return
        payload = record.get("payload") or {}
        decision_raw = record.get("decision")
        # before_tool_call and after_tool_call are known but absent from
        # _HOOK_MAP: the former yields only a decision (+conditional events),
        # the latter is polymorphic on toolName.
        is_known = (
            hook in _HOOK_MAP
            or hook in ("after_tool_call", "before_tool_call")
        )
        if not is_known:
            result.unknown_hooks += 1
            LOG.warning("native adapter: unknown hook %r — skipped", hook)
            return
        session = _session_of(payload)

        # Control decision — only the 4 decision hooks carry one.
        if hook in _DECISION_HOOKS:
            decision = self._build_decision(hook, payload, decision_raw)
            self._decisions.setdefault(session, []).append(decision)

        # TelemetryEvent.
        events = self._build_events(hook, payload, decision_raw, session)
        if events:
            self._events.setdefault(session, []).extend(events)
        result.events.extend(events)
        if hook in _DECISION_HOOKS:
            result.decisions.append(self._decisions[session][-1])

    # -- mapping helpers ----------------------------------------------------

    def _build_decision(
        self, hook: str, payload: dict, decision_raw: dict | None
    ) -> ControlDecision:
        action_class = {
            "before_agent_run": "agent.run",
            "before_tool_call": payload.get("toolName") or "tool.call",
            "subagent_spawning": "subagent.spawn",
            "outbound_dispatch": "message.dispatch",
        }.get(hook, hook)
        decision = _decision_value(decision_raw)
        return ControlDecision(
            action_class=action_class,
            target=payload.get("target") or payload.get("toolName"),
            decision=decision,
            observed=True,  # the hook fired — the runtime emitted the event
            reason_code=(decision_raw or {}).get("reason"),
            source="native",
        )

    def _build_events(
        self, hook: str, payload: dict, decision_raw: dict | None,
        session: str,
    ) -> list[TelemetryEventInput]:
        events: list[TelemetryEventInput] = []
        decision = _decision_value(decision_raw) if decision_raw else None

        if hook == "after_tool_call":
            event_type = _tool_event(payload.get("toolName"))
            events.append(self._event(
                session, event_type, payload, action_class="tool.call",
                target=payload.get("toolName")))
            return events

        if hook == "before_tool_call":
            # before_tool_call yields no telemetry event of its own, but a
            # block of a shell/MCP tool also emits a *.blocked event, and a
            # requireApproval emits an approval-requested event (spec §6).
            tool = (payload.get("toolName") or "").lower()
            if decision == "deny" and tool in {"bash", "exec", "shell"}:
                events.append(self._event(
                    session, "agent.shell.blocked", payload,
                    action_class="shell.exec", target=payload.get("toolName"),
                    decision="deny"))
            elif decision == "deny" and tool.startswith("mcp_"):
                events.append(self._event(
                    session, "agent.mcp.blocked", payload,
                    action_class="mcp.invoke", target=payload.get("toolName"),
                    decision="deny"))
            if decision == "ask":
                events.append(self._event(
                    session, "agent.approval.requested", payload,
                    action_class="approval", target=payload.get("toolName"),
                    decision="ask"))
            return events

        event_type = _HOOK_MAP.get(hook)
        if event_type is None:
            return events
        events.append(self._event(
            session, event_type, payload,
            action_class=hook, target=payload.get("target"),
            decision=decision))
        return events

    @staticmethod
    def _event(
        session: str, event_type: str, payload: dict, *,
        action_class: str, target: str | None = None,
        decision: str | None = None,
    ) -> TelemetryEventInput:
        return TelemetryEventInput(
            session_id=session,
            event_type=event_type,
            actor=str(payload.get("actor") or "victim"),
            action_class=action_class,
            target=target,
            decision=decision,
            reason_code=None,
            metadata={
                "source": "native",
                "toolCallId": payload.get("toolCallId"),
                "traceId": payload.get("traceId"),
                "spanId": payload.get("spanId"),
            },
        )


__all__ = ["IngestResult", "NativeEventAdapter"]
