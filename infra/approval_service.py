"""The severity-gated approval service (approval spec §6.1).

Authorizes a verified patch: auto-allows low/medium, holds high/critical for a
human decision. All state is the append-only `approval_events` table — the
service is stateless beyond the DB. It authorizes; it does not verify or patch.
"""

from __future__ import annotations

import logging
import uuid
from datetime import UTC, datetime, timedelta

from infra.approval_policy import gate_policy
from interfaces.config_schema import ApprovalsConfig
from interfaces.types import (
    ApprovalEvent,
    ApprovalEventInput,
    ApprovalOutcome,
    ApprovalRequest,
    PatchCandidate,
)

LOG = logging.getLogger("monkeyclaw.infra.approval")


def _now() -> datetime:
    return datetime.now(UTC)


def _iso(dt: datetime) -> str:
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def _parse(iso: str) -> datetime:
    return datetime.strptime(iso, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC)


class ApprovalService:
    def __init__(
        self,
        *,
        mcp,  # noqa: ANN001 — MonkeyClawMCP
        dispatcher,  # noqa: ANN001 — infra.notifications.AlertDispatcher
        cfg: ApprovalsConfig | None = None,
    ) -> None:
        self.mcp = mcp
        self.dispatcher = dispatcher
        self.cfg = cfg or ApprovalsConfig()
        self.policy = gate_policy(self.cfg)

    # ------------------------------------------------------------------
    def request(
        self,
        patch: PatchCandidate,
        *,
        severity: str | None,
        generalization: str | None = None,
    ) -> ApprovalOutcome:
        """Gate a verified patch. Returns ALLOW (auto) or PENDING."""
        posture = self.policy.posture_for(severity, generalization)
        request_id = f"REQ-{uuid.uuid4().hex[:14]}"
        sev = severity or "unknown"

        if posture == "auto_allow":
            event_in = ApprovalEventInput(
                request_id=request_id, patch_id=patch.patch_id,
                vuln_ids=list(patch.vuln_ids), zone_id=patch.zone_id,
                severity=sev, decision="allow", posture="auto_allow",
                approver="system",
                reason=f"auto-allow: severity={sev}",
                generalization_status=generalization,
            )
            event_id = self.mcp.log_approval_event(event_in)
            event = self._read_event(patch.patch_id, event_id)
            return ApprovalOutcome(
                decision="ALLOW", request_id=request_id, event=event)

        # require_approval: persist the `ask` row first — a request that was
        # never recorded must never look pending (spec §12).
        ask_expiry = _iso(
            _now() + timedelta(hours=self.policy.ask_expiry_hours()))
        ask_in = ApprovalEventInput(
            request_id=request_id, patch_id=patch.patch_id,
            vuln_ids=list(patch.vuln_ids), zone_id=patch.zone_id,
            severity=sev, decision="ask", posture="require_approval",
            approver="system", reason="awaiting human review",
            ask_expiry=ask_expiry, generalization_status=generalization,
        )
        self.mcp.log_approval_event(ask_in)  # raises -> caller sees no PENDING

        # Route the notification — delivery failure is non-fatal (§4.5).
        message = (
            f"[APPROVAL REQUEST / {sev}] request={request_id} "
            f"patch={patch.patch_id} vulns={','.join(patch.vuln_ids)} "
            f"zone={patch.zone_id} generalization={generalization or 'n/a'}\n"
            f"Resolve: monkeyclaw approvals resolve {request_id} "
            f"--allow|--deny --reason \"<text>\""
        )
        try:
            self.dispatcher.send(message, sev)
        except Exception as e:  # noqa: BLE001
            LOG.warning("approval notification delivery failed: %s", e)

        return ApprovalOutcome(
            decision="PENDING", request_id=request_id, event=None)

    # ------------------------------------------------------------------
    def resolve(
        self,
        request_id: str,
        *,
        decision: str,  # "allow" | "deny"
        approver: str,
        reason: str,
        expiry: str | None = None,
    ) -> ApprovalEvent:
        """Record a human decision on a pending request."""
        if decision not in ("allow", "deny"):
            raise ValueError(
                f"resolve decision must be allow|deny, got {decision!r}")
        ask = self._find_ask(request_id)
        if ask is None:
            raise ValueError(f"no such approval request: {request_id}")
        if self._is_resolved(request_id):
            raise ValueError(
                f"approval request {request_id} is already resolved")

        grant_expiry = expiry
        if grant_expiry is None and decision == "allow" \
                and self.policy.grant_expiry_hours() > 0:
            grant_expiry = _iso(
                _now() + timedelta(hours=self.policy.grant_expiry_hours()))

        event_id = self.mcp.log_approval_event(ApprovalEventInput(
            request_id=request_id, patch_id=ask.patch_id,
            vuln_ids=list(ask.vuln_ids), zone_id=ask.zone_id,
            severity=ask.severity, decision=decision,
            posture="require_approval", approver=approver, reason=reason,
            grant_expiry=grant_expiry,
            generalization_status=ask.generalization_status,
        ))
        # Informational resolution alert (§8).
        try:
            self.dispatcher.send(
                f"[APPROVAL {decision.upper()}] request={request_id} "
                f"patch={ask.patch_id} approver={approver} reason={reason!r}",
                ask.severity)
        except Exception as e:  # noqa: BLE001
            LOG.warning("resolution notification failed: %s", e)
        return self._read_event(ask.patch_id, event_id)

    def expire_stale(
        self, *, now: datetime | None = None,
    ) -> list[ApprovalEvent]:
        """Lapse overdue `ask` requests and overdue `allow` grants."""
        now = now or _now()
        lapsed: list[ApprovalEvent] = []

        # 1. Overdue pending asks.
        for req in self.list_pending():
            if req.ask_expiry and _parse(req.ask_expiry) < now:
                event_id = self.mcp.log_approval_event(ApprovalEventInput(
                    request_id=req.request_id, patch_id=req.patch_id,
                    vuln_ids=list(req.vuln_ids), zone_id=req.zone_id,
                    severity=req.severity, decision="expired",
                    posture="require_approval", approver="system",
                    reason="ask expired without a human decision",
                    generalization_status=req.generalization_status))
                try:
                    self.dispatcher.send(
                        f"[APPROVAL EXPIRED] request={req.request_id} "
                        f"patch={req.patch_id} — unactioned, escalating.",
                        "high")
                except Exception as e:  # noqa: BLE001
                    LOG.warning("expiry notification failed: %s", e)
                ev = self._read_event(req.patch_id, event_id)
                if ev:
                    lapsed.append(ev)

        # 2. Overdue granted allows.
        for ev in self._overdue_grants(now):
            event_id = self.mcp.log_approval_event(ApprovalEventInput(
                request_id=ev.request_id, patch_id=ev.patch_id,
                vuln_ids=list(ev.vuln_ids), zone_id=ev.zone_id,
                severity=ev.severity, decision="expired",
                posture=ev.posture, approver="system",
                reason="granted approval lapsed before application",
                generalization_status=ev.generalization_status))
            lapsed_ev = self._read_event(ev.patch_id, event_id)
            if lapsed_ev:
                lapsed.append(lapsed_ev)
        return lapsed

    # ------------------------------------------------------------------
    def list_pending(self) -> list[ApprovalRequest]:
        return list(self.mcp.get_pending_approvals())

    # ------------------------------------------------------------------
    def _find_ask(self, request_id: str) -> ApprovalEvent | None:
        """The `ask` event for a request_id, found across the full audit
        log (resolved or not). None when the request never existed."""
        for ev in self.mcp.get_approval_events_by_request(request_id):
            if ev.decision == "ask":
                return ev
        return None

    def _is_resolved(self, request_id: str) -> bool:
        return any(
            ev.decision in ("allow", "deny", "expired")
            for ev in self.mcp.get_approval_events_by_request(request_id))

    def _overdue_grants(self, now: datetime) -> list[ApprovalEvent]:
        out: list[ApprovalEvent] = []
        for ev in self.mcp.get_resolved_allows():
            if ev.grant_expiry and _parse(ev.grant_expiry) < now:
                out.append(ev)
        return out

    def _read_event(
        self, patch_id: str, event_id: str,
    ) -> ApprovalEvent | None:
        for e in self.mcp.get_approval_events(patch_id):
            if e.event_id == event_id:
                return e
        return None


__all__ = ["ApprovalService"]
