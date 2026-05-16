"""Telemetry emission — deliverable A5.

A thin, dependency-light helper over the MCP `log_telemetry_event` method.
One method per `agent.*` event type from the General Analysis telemetry
catalog. Excerpts are length-bounded; full content is SHA-256 hashed; raw
secrets are never stored.
"""

from __future__ import annotations

import hashlib
import logging
from typing import Any

from interfaces.mcp_tools import MonkeyClawMCP
from interfaces.types import TelemetryEventInput

LOG = logging.getLogger("monkeyclaw.telemetry")

EXCERPT_LIMIT = 256


def bounded_excerpt(text: str | None, limit: int = EXCERPT_LIMIT) -> str | None:
    """Return at most `limit` characters of `text` (None passes through)."""
    if text is None:
        return None
    return text[:limit]


def content_hash(text: str | None) -> str | None:
    """SHA-256 hex of `text`, for later matching without retaining content."""
    if text is None:
        return None
    return hashlib.sha256(text.encode("utf-8", "replace")).hexdigest()


class TelemetryEmitter:
    """Bound to one session. Each method emits one telemetry event.

    `data_class` of "secret" forces content to be hashed only — the excerpt
    is dropped so a secret can never land in the timeline.
    """

    def __init__(self, mcp: MonkeyClawMCP, session_id: str) -> None:
        self.mcp = mcp
        self.session_id = session_id

    def _emit(self, event_type: str, actor: str, action_class: str,
              *, target: str | None = None, decision: str | None = None,
              reason_code: str | None = None, data_class: str | None = None,
              raw_content: str | None = None,
              metadata: dict[str, Any] | None = None) -> str:
        is_secret = data_class == "secret"
        excerpt = None if is_secret else bounded_excerpt(raw_content)
        try:
            return self.mcp.log_telemetry_event(TelemetryEventInput(
                session_id=self.session_id, event_type=event_type, actor=actor,
                action_class=action_class, target=target, decision=decision,
                reason_code=reason_code, data_class=data_class,
                content_hash=content_hash(raw_content), excerpt=excerpt,
                metadata=metadata or {}))
        except Exception:  # noqa: BLE001 - telemetry must never break a lane
            LOG.exception("telemetry emit failed for %s", event_type)
            return ""

    # --- the 13 catalog events --------------------------------------------
    def session_started(self, actor: str, **meta: Any) -> str:
        return self._emit("agent.session.started", actor, "session", metadata=meta)

    def policy_loaded(self, actor: str, *, target: str | None = None,
                      **meta: Any) -> str:
        return self._emit("agent.policy.loaded", actor, "policy",
                           target=target, metadata=meta)

    def tool_requested(self, actor: str, *, target: str | None = None,
                       **meta: Any) -> str:
        return self._emit("agent.tool.requested", actor, "tool",
                           target=target, metadata=meta)

    def tool_decision(self, actor: str, *, target: str | None = None,
                      decision: str, reason_code: str | None = None,
                      **meta: Any) -> str:
        return self._emit("agent.tool.decision", actor, "tool", target=target,
                           decision=decision, reason_code=reason_code,
                           metadata=meta)

    def file_read(self, actor: str, *, path: str, data_class: str | None = None,
                  decision: str | None = None, reason_code: str | None = None,
                  raw_content: str | None = None, **meta: Any) -> str:
        return self._emit("agent.file.read", actor, "filesystem", target=path,
                           decision=decision, reason_code=reason_code,
                           data_class=data_class, raw_content=raw_content,
                           metadata=meta)

    def file_write(self, actor: str, *, path: str, data_class: str | None = None,
                   decision: str | None = None, raw_content: str | None = None,
                   **meta: Any) -> str:
        return self._emit("agent.file.write", actor, "filesystem", target=path,
                           decision=decision, data_class=data_class,
                           raw_content=raw_content, metadata=meta)

    def shell_started(self, actor: str, *, command: str, **meta: Any) -> str:
        return self._emit("agent.shell.started", actor, "shell",
                           target=bounded_excerpt(command, 128),
                           raw_content=command, metadata=meta)

    def shell_finished(self, actor: str, *, command: str,
                       exit_code: int, **meta: Any) -> str:
        return self._emit("agent.shell.finished", actor, "shell",
                           target=bounded_excerpt(command, 128),
                           metadata={"exit_code": exit_code, **meta})

    def network_request(self, actor: str, *, destination: str,
                        decision: str | None = None,
                        reason_code: str | None = None, **meta: Any) -> str:
        return self._emit("agent.network.request", actor, "network",
                           target=destination, decision=decision,
                           reason_code=reason_code, metadata=meta)

    def mcp_invoked(self, actor: str, *, tool: str, **meta: Any) -> str:
        return self._emit("agent.mcp.invoked", actor, "mcp", target=tool,
                           metadata=meta)

    def approval_requested(self, actor: str, *, target: str | None = None,
                           reason_code: str | None = None, **meta: Any) -> str:
        return self._emit("agent.approval.requested", actor, "approval",
                           target=target, reason_code=reason_code,
                           metadata=meta)

    def approval_resolved(self, actor: str, *, target: str | None = None,
                          decision: str, **meta: Any) -> str:
        return self._emit("agent.approval.resolved", actor, "approval",
                           target=target, decision=decision, metadata=meta)

    def session_finished(self, actor: str, *, final_status: str = "ok",
                          **meta: Any) -> str:
        return self._emit("agent.session.finished", actor, "session",
                           decision=final_status, metadata=meta)


__all__ = ["TelemetryEmitter", "bounded_excerpt", "content_hash"]
