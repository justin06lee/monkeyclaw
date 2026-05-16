"""Self-containment guardrails — deliverable A8.

MonkeyClaw is adversarial: a planted red-team lane will deliberately try to
escape. `PolicyEnforcer` is the central decision point — the harness and the
lane scheduler consult it before risky actions. Every decision is a
`PolicyDecision`; callers emit it as telemetry.
"""

from __future__ import annotations

import logging
import os
import threading
from datetime import UTC, datetime

from interfaces.config_schema import GuardrailsConfig
from interfaces.types import PolicyDecision

LOG = logging.getLogger("monkeyclaw.guardrails")


def _iso_now() -> str:
    return datetime.now(UTC).isoformat()


def _expand(p: str) -> str:
    return os.path.abspath(os.path.expanduser(p))


class PolicyEnforcer:
    """Thread-safe. One instance per cycle/run."""

    def __init__(self, cfg: GuardrailsConfig) -> None:
        self.cfg = cfg
        self._lock = threading.Lock()
        self._stopped = cfg.emergency_stop
        self._stop_reason = "config" if cfg.emergency_stop else ""
        self._artifact_dir = _expand(cfg.artifact_dir)
        self._denied = [_expand(p) for p in cfg.denied_host_paths]
        self._counter = 0

    def _decide(self, action_class: str, target: str | None,
                decision: str, reason_code: str,
                policy_rule: str | None = None) -> PolicyDecision:
        with self._lock:
            self._counter += 1
            did = f"PD-{self._counter:06d}"
        if decision == "deny":
            LOG.warning("guardrail DENY %s target=%s reason=%s",
                        action_class, target, reason_code)
        return PolicyDecision(
            decision_id=did, session_id="", action_class=action_class,
            target=target, decision=decision, reason_code=reason_code,
            policy_rule=policy_rule, approver=None, latency_ms=0,
            created_at=_iso_now())

    def _stop_guard(self, action_class: str, target: str | None):
        if self._stopped:
            return self._decide(action_class, target, "deny",
                                "emergency_stop", self._stop_reason)
        return None

    def check_path_read(self, path: str) -> PolicyDecision:
        stop = self._stop_guard("filesystem", path)
        if stop:
            return stop
        resolved = _expand(path)
        for denied in self._denied:
            if resolved == denied or resolved.startswith(denied + os.sep):
                return self._decide("filesystem", path, "deny",
                                    "denied_host_path", denied)
        return self._decide("filesystem", path, "allow", "path_permitted")

    def check_path_write(self, path: str) -> PolicyDecision:
        stop = self._stop_guard("filesystem", path)
        if stop:
            return stop
        resolved = _expand(path)
        if resolved == self._artifact_dir or resolved.startswith(
                self._artifact_dir + os.sep):
            return self._decide("filesystem", path, "allow", "in_artifact_dir")
        for denied in self._denied:
            if resolved == denied or resolved.startswith(denied + os.sep):
                return self._decide("filesystem", path, "deny",
                                    "denied_host_path", denied)
        return self._decide("filesystem", path, "deny", "outside_artifact_dir",
                            self._artifact_dir)

    def check_network(self, destination: str, phase: str = "default") -> PolicyDecision:
        stop = self._stop_guard("network", destination)
        if stop:
            return stop
        allowed = set(self.cfg.network_allowlist.get(phase, []))
        allowed |= set(self.cfg.network_allowlist.get("default", []))
        host = destination.split("://")[-1].split("/")[0].split(":")[0]
        if host in allowed:
            return self._decide("network", destination, "allow",
                                "egress_permitted", phase)
        return self._decide("network", destination, "deny",
                            "egress_not_in_allowlist", phase)

    def check_mcp_tool(self, server_or_tool: str) -> PolicyDecision:
        stop = self._stop_guard("mcp", server_or_tool)
        if stop:
            return stop
        if server_or_tool in self.cfg.mcp_tool_allowlist:
            return self._decide("mcp", server_or_tool, "allow",
                                "mcp_tool_allowed")
        return self._decide("mcp", server_or_tool, "deny",
                            "mcp_tool_not_in_allowlist")

    def check_model_route(self, provider: str) -> PolicyDecision:
        stop = self._stop_guard("model", provider)
        if stop:
            return stop
        if provider in self.cfg.model_route_allowlist:
            return self._decide("model", provider, "allow", "route_allowed")
        return self._decide("model", provider, "deny",
                            "route_not_in_allowlist")

    def check_lane_budget(self, lanes_used: int) -> PolicyDecision:
        stop = self._stop_guard("budget", "lanes")
        if stop:
            return stop
        if lanes_used >= self.cfg.max_lanes_per_cycle:
            return self._decide("budget", "lanes", "deny", "lane_budget_exhausted",
                                str(self.cfg.max_lanes_per_cycle))
        return self._decide("budget", "lanes", "allow", "within_lane_budget")

    def check_token_budget(self, tokens_used: int) -> PolicyDecision:
        stop = self._stop_guard("budget", "tokens")
        if stop:
            return stop
        if tokens_used >= self.cfg.max_tokens_per_cycle:
            return self._decide("budget", "tokens", "deny",
                                "token_budget_exhausted",
                                str(self.cfg.max_tokens_per_cycle))
        return self._decide("budget", "tokens", "allow", "within_token_budget")

    def trigger_emergency_stop(self, reason: str) -> None:
        with self._lock:
            self._stopped = True
            self._stop_reason = reason
        LOG.error("EMERGENCY STOP triggered: %s", reason)

    def emergency_stopped(self) -> bool:
        return self._stopped


__all__ = ["PolicyEnforcer"]
