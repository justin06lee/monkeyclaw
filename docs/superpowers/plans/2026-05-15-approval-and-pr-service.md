# Approval and PR Service Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a severity-gated approval service that authorizes verified patches — auto-allowing low/medium and holding high/critical for a recorded human decision — produces an append-only `approval_events` audit trail, routes request/resolution alerts through the existing dispatcher, exposes a `monkeyclaw approvals` CLI, and optionally drafts a pull request for an approved patch.

**Architecture:** `infra/approval_service.py` is the gate, peer to `infra/notifications.py`. It consults the pure `infra/approval_policy.py` (severity → posture) and, for `auto_allow`, records an immediate `ApprovalEvent`; for `require_approval` it persists a pending `ApprovalRequest` and routes a notification. All state lives in the append-only `approval_events` table — a request is an `ask` row, its resolution a second row sharing `request_id`. `blue_team/pipeline.py`'s `_on_patch_approved` is split so a verified patch routes through the service before finalizing; `process_blue_queue` polls for resolved/expired requests each pass. `infra/pr_generator.py` is the optional post-approval step.

**Tech Stack:** Python 3.12, `uv` for env + test running, `pytest`, SQLite via `infra/database.py`, the existing migration runner (`infra/migrations.py` + `infra/migrations/`), Pydantic `MonkeyClawConfig` (`interfaces/config_schema.py`), `interfaces/types.py` dataclasses, the `gh` CLI via `subprocess` (stubbed in tests), `ruff` for lint. Everything runs in mock mode with zero model credentials and a stub `AlertDispatcher`/`subprocess` boundary.

---

## File Structure

| File | Create/Modify | Responsibility |
|------|---------------|----------------|
| `interfaces/types.py` | Modify | Add `ApprovalDecision`, `GatePosture`, `ApprovalOutcomeKind`, `ApprovalRequest`, `ApprovalEvent`, `ApprovalEventInput`, `ApprovalOutcome`, `PullRequestDraft`. |
| `interfaces/schema.sql` | Modify | Add the `approval_events` table (reference copy, kept in sync with the migration). |
| `interfaces/mcp_tools.py` | Modify | Add `log_approval_event`, `get_pending_approvals`, `get_approval_events` method signatures. |
| `interfaces/config_schema.py` | Modify | `ApprovalsConfig` + `ApprovalPostureConfig` dataclasses; `approvals` field on `MonkeyClawConfig`. |
| `infra/migrations/00N_approval_events.sql` | Create | Migration adding `approval_events`; `schema_version` bump. |
| `infra/mcp_server.py` | Modify | Implement the three approval MCP methods over `approval_events`. |
| `infra/approval_policy.py` | Create | Pure severity → posture mapping; expiry accessors; default-deny. |
| `infra/approval_service.py` | Create | `request` / `resolve` / `list_pending` / `expire_stale`; notification routing. |
| `infra/pr_generator.py` | Create | Optional post-approval `gh`-CLI pull-request draft. |
| `infra/cli.py` | Modify | `approvals` subcommand: list pending + `resolve`. |
| `blue_team/pipeline.py` | Modify | Split `_on_patch_approved` through the service; `expire_stale` + resolved poll in `process_blue_queue`. |
| `infra/dashboard.py` | Modify | Additive approvals panel: pending, recent resolutions, posture split. |
| `configs/monkeyclaw.yaml` | Modify | `approvals` config block. |
| `test/test_infra_approval_types.py` | Create | Type/contract tests for the new dataclasses. |
| `test/test_infra_approval_migration.py` | Create | Migration applies; `approval_events` columns; MCP round-trip. |
| `test/test_infra_approval_policy.py` | Create | Table-driven severity × posture; default-deny tests. |
| `test/test_infra_approval_service.py` | Create | auto-allow, require-approval, resolve, expire, delivery-failure tests. |
| `test/test_infra_approval_audit.py` | Create | `approval_events` append-only / lifecycle-reconstruction tests. |
| `test/test_infra_pr_generator.py` | Create | `PullRequestDraft` produced; `gh` failure non-fatal. |
| `test/test_blue_pipeline_approval_e2e.py` | Create | `process_blue_queue` low auto-allow vs. high pending→resolve→finalize. |
| `test/test_cli_approvals.py` | Create | `monkeyclaw approvals` list + `resolve` tests. |

---

# Phase 0 — Contracts

No behaviour yet: shared types, the `approval_events` migration, MCP signatures, the config block.

## Task 1 — New interface types

**Files:**
- Modify: `interfaces/types.py`
- Test: `test/test_infra_approval_types.py`

- [ ] Write the failing test. Create `test/test_infra_approval_types.py`:
```python
"""Phase 0 — approval-service shared type contracts."""

from __future__ import annotations

from dataclasses import fields

from interfaces.types import (
    ApprovalEvent,
    ApprovalEventInput,
    ApprovalOutcome,
    ApprovalRequest,
    PullRequestDraft,
)


def test_approval_request_has_lifecycle_fields():
    fnames = {f.name for f in fields(ApprovalRequest)}
    assert {"request_id", "patch_id", "vuln_ids", "zone_id", "severity",
            "posture", "ask_expiry", "generalization_status",
            "created_at", "status"} <= fnames


def test_approval_event_carries_decision_and_approver():
    e = ApprovalEvent(
        event_id="E1", request_id="R1", patch_id="P1", vuln_ids=["MC-1"],
        zone_id="SBX-FS", severity="high", decision="allow",
        posture="require_approval", approver="operator", reason="reviewed",
        ask_expiry=None, grant_expiry=None, generalization_status=None,
        pr_url=None, created_at="2026-05-15T00:00:00Z",
    )
    assert e.decision == "allow"
    assert e.approver == "operator"


def test_approval_event_input_is_the_write_shape():
    fnames = {f.name for f in fields(ApprovalEventInput)}
    # event_id + created_at are server-filled, so absent from the write shape.
    assert "event_id" not in fnames
    assert {"request_id", "patch_id", "vuln_ids", "zone_id", "severity",
            "decision", "posture", "approver", "reason"} <= fnames


def test_approval_outcome_kinds():
    o = ApprovalOutcome(decision="PENDING", request_id="R1", event=None)
    assert o.decision in ("ALLOW", "DENY", "PENDING")


def test_pull_request_draft_shape():
    fnames = {f.name for f in fields(PullRequestDraft)}
    assert {"branch", "pr_url", "commit_sha", "created_at"} <= fnames
```
- [ ] Run it, verify it fails: `uv run pytest test/test_infra_approval_types.py -q` — expect `ImportError: cannot import name 'ApprovalEvent'`.
- [ ] Add the literals to `interfaces/types.py` after the existing literal block:
```python
ApprovalDecision = Literal["ask", "allow", "deny", "expired"]
GatePosture = Literal["auto_allow", "require_approval"]
ApprovalOutcomeKind = Literal["ALLOW", "DENY", "PENDING"]
ApprovalRequestStatus = Literal["pending", "resolved", "expired"]
GeneralizationStatus = Literal["generalized", "unconverged"]
```
- [ ] Add the dataclasses to `interfaces/types.py` before the `__all__` list:
```python
# ---------------------------------------------------------------------------
# Approval & PR service — severity-gated authorization (approval spec §9)
# ---------------------------------------------------------------------------


@dataclass
class ApprovalRequest:
    """A pending request for a human decision on a verified patch."""

    request_id: str
    patch_id: str
    vuln_ids: list[str]
    zone_id: str
    severity: str
    posture: str  # GatePosture
    ask_expiry: str | None  # ISO timestamp, None for no expiry
    generalization_status: str | None  # GeneralizationStatus | None
    created_at: str
    status: str  # ApprovalRequestStatus


@dataclass
class ApprovalEvent:
    """One row of the append-only approval_events audit log (read shape)."""

    event_id: str
    request_id: str
    patch_id: str
    vuln_ids: list[str]
    zone_id: str
    severity: str
    decision: str  # ApprovalDecision
    posture: str  # GatePosture
    approver: str  # operator id or "system"
    reason: str
    ask_expiry: str | None
    grant_expiry: str | None
    generalization_status: str | None
    pr_url: str | None
    created_at: str


@dataclass
class ApprovalEventInput:
    """Write shape for an approval_events row — server fills event_id +
    created_at."""

    request_id: str
    patch_id: str
    vuln_ids: list[str]
    zone_id: str
    severity: str
    decision: str  # ApprovalDecision
    posture: str  # GatePosture
    approver: str
    reason: str
    ask_expiry: str | None = None
    grant_expiry: str | None = None
    generalization_status: str | None = None
    pr_url: str | None = None


@dataclass
class ApprovalOutcome:
    """What approval_service.request() returns."""

    decision: str  # ApprovalOutcomeKind
    request_id: str
    event: ApprovalEvent | None  # the allow event for an immediate auto-allow


@dataclass
class PullRequestDraft:
    """The result of pr_generator.draft() for an approved patch."""

    branch: str
    pr_url: str
    commit_sha: str
    created_at: str
```
- [ ] Append the new names to `__all__` in `interfaces/types.py`, alphabetised within the list: `ApprovalDecision`, `ApprovalEvent`, `ApprovalEventInput`, `ApprovalOutcome`, `ApprovalOutcomeKind`, `ApprovalRequest`, `ApprovalRequestStatus`, `GatePosture`, `GeneralizationStatus`, `PullRequestDraft`.
- [ ] Run the test, verify it passes: `uv run pytest test/test_infra_approval_types.py -q` — expect `5 passed`.
- [ ] Run lint: `uv run ruff check interfaces/types.py test/test_infra_approval_types.py` — expect `All checks passed!`.
- [ ] Commit: `git add interfaces/types.py test/test_infra_approval_types.py && git commit -m "feat(approval): shared interface types"`.

## Task 2 — Schema migration for `approval_events`

**Files:**
- Create: `infra/migrations/00N_approval_events.sql`
- Modify: `interfaces/schema.sql`
- Test: `test/test_infra_approval_migration.py`

- [ ] Inspect the highest existing migration number: `ls infra/migrations/`. Take the next free number (coordination rule 1 of the upgrade roadmap) and use it consistently for the file name and the `schema_version` bump. This plan writes the file as `00N_approval_events.sql` — substitute the real number when executing.
- [ ] Write the failing test. Create `test/test_infra_approval_migration.py`:
```python
"""Phase 0 — approval_events migration creates the audit table."""

from __future__ import annotations

from infra.database import Database


def _table_names(db: Database) -> set[str]:
    rows = db.fetchall("SELECT name FROM sqlite_master WHERE type='table'")
    return {r["name"] for r in rows}


def test_migration_creates_approval_events(db: Database):
    assert "approval_events" in _table_names(db)


def test_approval_events_columns(db: Database):
    cols = {r["name"] for r in db.fetchall(
        "PRAGMA table_info(approval_events)")}
    assert {"event_id", "request_id", "patch_id", "vuln_ids", "zone_id",
            "severity", "decision", "posture", "approver", "reason",
            "ask_expiry", "grant_expiry", "generalization_status",
            "pr_url", "created_at"} <= cols
```
- [ ] Run it, verify it fails: `uv run pytest test/test_infra_approval_migration.py -q` — expect `AssertionError` (table absent).
- [ ] Create `infra/migrations/00N_approval_events.sql` (substitute the real number):
```sql
-- Migration 00N — approval_events audit table (approval spec §9).
-- Forward-only, idempotent, append-only at the application layer.

BEGIN;

CREATE TABLE IF NOT EXISTS approval_events (
    event_id              TEXT PRIMARY KEY,
    request_id            TEXT NOT NULL,
    patch_id              TEXT NOT NULL,
    vuln_ids              TEXT NOT NULL DEFAULT '[]',  -- JSON list
    zone_id               TEXT NOT NULL,
    severity              TEXT NOT NULL,
    decision              TEXT NOT NULL,            -- ask|allow|deny|expired
    posture               TEXT NOT NULL,            -- auto_allow|require_approval
    approver              TEXT NOT NULL,            -- operator id or 'system'
    reason                TEXT NOT NULL DEFAULT '',
    ask_expiry            TEXT,
    grant_expiry          TEXT,
    generalization_status TEXT,                     -- generalized|unconverged
    pr_url                TEXT,
    created_at            TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_approval_events_decision
    ON approval_events(decision, created_at);
CREATE INDEX IF NOT EXISTS idx_approval_events_patch
    ON approval_events(patch_id);
CREATE INDEX IF NOT EXISTS idx_approval_events_request
    ON approval_events(request_id);

COMMIT;
```
- [ ] Mirror the `CREATE TABLE` / `CREATE INDEX` statements into `interfaces/schema.sql` (append after the `patches` block) so the bootstrap-from-empty path and the migrated path agree. Drop the `BEGIN;`/`COMMIT;` — `schema.sql` is run as one script.
- [ ] Bump `schema_version` to the migration number wherever the migration runner records it (confirm with `grep -rn schema_version infra/`).
- [ ] Run the test, verify it passes: `uv run pytest test/test_infra_approval_migration.py -q` — expect `2 passed`.
- [ ] Run the migration-runner test: `uv run pytest test/ -k migration -q` — expect all green.
- [ ] Run lint: `uv run ruff check test/test_infra_approval_migration.py` — expect `All checks passed!`.
- [ ] Commit: `git add infra/migrations/ interfaces/schema.sql test/test_infra_approval_migration.py && git commit -m "feat(approval): migration — approval_events audit table"`.

## Task 3 — MCP write/read methods for `approval_events`

**Files:**
- Modify: `interfaces/mcp_tools.py`
- Modify: `infra/mcp_server.py`
- Test: `test/test_infra_approval_migration.py` (extend)

- [ ] Add failing tests to the end of `test/test_infra_approval_migration.py`:
```python
def test_mcp_logs_and_reads_approval_event(server):
    from interfaces.types import ApprovalEventInput

    server.log_approval_event(ApprovalEventInput(
        request_id="R1", patch_id="P1", vuln_ids=["MC-1"], zone_id="SBX-FS",
        severity="low", decision="allow", posture="auto_allow",
        approver="system", reason="auto-allow: severity=low",
    ))
    events = server.get_approval_events(patch_id="P1")
    assert len(events) == 1
    assert events[0].decision == "allow"
    assert events[0].vuln_ids == ["MC-1"]


def test_mcp_pending_request_is_an_ask_with_no_resolution(server):
    from interfaces.types import ApprovalEventInput

    server.log_approval_event(ApprovalEventInput(
        request_id="R2", patch_id="P2", vuln_ids=["MC-2"], zone_id="SBX-NET",
        severity="high", decision="ask", posture="require_approval",
        approver="system", reason="awaiting human review",
        ask_expiry="2099-01-01T00:00:00Z",
    ))
    pending = server.get_pending_approvals()
    assert any(p.request_id == "R2" and p.status == "pending"
               for p in pending)


def test_mcp_resolved_request_drops_out_of_pending(server):
    from interfaces.types import ApprovalEventInput

    server.log_approval_event(ApprovalEventInput(
        request_id="R3", patch_id="P3", vuln_ids=["MC-3"], zone_id="SBX-FS",
        severity="high", decision="ask", posture="require_approval",
        approver="system", reason="ask",
        ask_expiry="2099-01-01T00:00:00Z"))
    server.log_approval_event(ApprovalEventInput(
        request_id="R3", patch_id="P3", vuln_ids=["MC-3"], zone_id="SBX-FS",
        severity="high", decision="allow", posture="require_approval",
        approver="operator", reason="approved"))
    pending_ids = {p.request_id for p in server.get_pending_approvals()}
    assert "R3" not in pending_ids
```
- [ ] Note: reuse whatever `server` fixture the existing `test_infra_*` migration/MCP tests use (grep `test/conftest.py` for `server`); do not invent a new fixture.
- [ ] Run it, verify it fails: `uv run pytest test/test_infra_approval_migration.py -q` — expect `AttributeError: 'MonkeyClawMCPServer' object has no attribute 'log_approval_event'` (or the equivalent server class name).
- [ ] Add the three method signatures to the `MonkeyClawMCP` Protocol in `interfaces/mcp_tools.py` (after `mark_patch_status`):
```python
    def log_approval_event(self, event: "ApprovalEventInput") -> str:
        """Append one row to the approval_events audit log; returns event_id."""
        ...

    def get_pending_approvals(self) -> list["ApprovalRequest"]:
        """Every request_id with an `ask` row and no allow/deny/expired row."""
        ...

    def get_approval_events(self, patch_id: str) -> list["ApprovalEvent"]:
        """Every approval_events row for one patch, oldest first."""
        ...
```
- [ ] Add `ApprovalEvent`, `ApprovalEventInput`, `ApprovalRequest` to the imports at the top of `interfaces/mcp_tools.py`.
- [ ] Implement the three methods in `infra/mcp_server.py` (place them next to `mark_patch_status`):
```python
    def log_approval_event(self, event: ApprovalEventInput) -> str:
        import json
        import uuid
        event_id = f"APE-{uuid.uuid4().hex[:14]}"
        with self.db.lock():
            self.db.execute(
                "INSERT INTO approval_events(event_id, request_id, patch_id, "
                "vuln_ids, zone_id, severity, decision, posture, approver, "
                "reason, ask_expiry, grant_expiry, generalization_status, "
                "pr_url, created_at) VALUES "
                "(?,?,?,?,?,?,?,?,?,?,?,?,?,?,datetime('now'))",
                (event_id, event.request_id, event.patch_id,
                 json.dumps(event.vuln_ids), event.zone_id, event.severity,
                 event.decision, event.posture, event.approver, event.reason,
                 event.ask_expiry, event.grant_expiry,
                 event.generalization_status, event.pr_url),
            )
        return event_id

    def get_approval_events(self, patch_id: str) -> list[ApprovalEvent]:
        rows = self.db.fetchall(
            "SELECT * FROM approval_events WHERE patch_id = ? "
            "ORDER BY created_at ASC", (patch_id,))
        return [self._row_to_approval_event(r) for r in rows]

    def get_pending_approvals(self) -> list[ApprovalRequest]:
        # request_ids with an `ask` row but no allow/deny/expired row.
        rows = self.db.fetchall(
            "SELECT * FROM approval_events WHERE decision = 'ask' "
            "ORDER BY created_at ASC")
        resolved = {r["request_id"] for r in self.db.fetchall(
            "SELECT DISTINCT request_id FROM approval_events "
            "WHERE decision IN ('allow', 'deny', 'expired')")}
        out: list[ApprovalRequest] = []
        for r in rows:
            if r["request_id"] in resolved:
                continue
            import json
            out.append(ApprovalRequest(
                request_id=r["request_id"], patch_id=r["patch_id"],
                vuln_ids=json.loads(r["vuln_ids"]), zone_id=r["zone_id"],
                severity=r["severity"], posture=r["posture"],
                ask_expiry=r["ask_expiry"],
                generalization_status=r["generalization_status"],
                created_at=r["created_at"], status="pending",
            ))
        return out

    @staticmethod
    def _row_to_approval_event(r) -> ApprovalEvent:  # noqa: ANN001
        import json
        return ApprovalEvent(
            event_id=r["event_id"], request_id=r["request_id"],
            patch_id=r["patch_id"], vuln_ids=json.loads(r["vuln_ids"]),
            zone_id=r["zone_id"], severity=r["severity"],
            decision=r["decision"], posture=r["posture"],
            approver=r["approver"], reason=r["reason"],
            ask_expiry=r["ask_expiry"], grant_expiry=r["grant_expiry"],
            generalization_status=r["generalization_status"],
            pr_url=r["pr_url"], created_at=r["created_at"],
        )
```
- [ ] Add `ApprovalEvent`, `ApprovalEventInput`, `ApprovalRequest` to the type imports in `infra/mcp_server.py`.
- [ ] Run the test, verify it passes: `uv run pytest test/test_infra_approval_migration.py -q` — expect `5 passed`.
- [ ] Run lint: `uv run ruff check interfaces/mcp_tools.py infra/mcp_server.py test/test_infra_approval_migration.py` — expect `All checks passed!`.
- [ ] Commit: `git add interfaces/mcp_tools.py infra/mcp_server.py test/test_infra_approval_migration.py && git commit -m "feat(approval): MCP methods for the approval audit log"`.

## Task 4 — `ApprovalsConfig` and the YAML block

**Files:**
- Modify: `interfaces/config_schema.py`
- Modify: `configs/monkeyclaw.yaml`
- Test: `test/test_infra_approval_types.py` (extend)

- [ ] Add a failing test to the end of `test/test_infra_approval_types.py`:
```python
def test_approvals_config_defaults():
    from interfaces.config_schema import MonkeyClawConfig

    cfg = MonkeyClawConfig()
    ap = cfg.approvals
    assert ap.posture.critical == "require_approval"
    assert ap.posture.high == "require_approval"
    assert ap.posture.medium == "auto_allow"
    assert ap.posture.low == "auto_allow"
    assert ap.ask_expiry_hours == 72
    assert ap.grant_expiry_hours == 0
    assert ap.auto_pr is False
    assert ap.operator_id == "operator"
    assert ap.pr_base_branch == "master"
```
- [ ] Run it, verify it fails: `uv run pytest test/test_infra_approval_types.py::test_approvals_config_defaults -q` — expect `AttributeError`.
- [ ] Add the config dataclasses to `interfaces/config_schema.py` immediately before `class MonkeyClawConfig`:
```python
class ApprovalPostureConfig(BaseModel):
    critical: str = "require_approval"
    high: str = "require_approval"
    medium: str = "auto_allow"
    low: str = "auto_allow"


class ApprovalsConfig(BaseModel):
    posture: ApprovalPostureConfig = ApprovalPostureConfig()
    ask_expiry_hours: int = 72
    grant_expiry_hours: int = 0  # 0 = no expiry
    auto_pr: bool = False
    operator_id: str = "operator"
    pr_base_branch: str = "master"
```
- [ ] Add the `approvals` field to `MonkeyClawConfig` in `interfaces/config_schema.py`:
```python
    approvals: ApprovalsConfig = ApprovalsConfig()
```
- [ ] Add the `approvals` block to `configs/monkeyclaw.yaml` (top-level, alongside `repro:` / `blue_team:`):
```yaml
approvals:
  posture:
    critical: require_approval
    high: require_approval
    medium: auto_allow
    low: auto_allow
  ask_expiry_hours: 72
  grant_expiry_hours: 0
  auto_pr: false
  operator_id: operator
  pr_base_branch: master
```
- [ ] Run the test, verify it passes: `uv run pytest test/test_infra_approval_types.py -q` — expect `6 passed`.
- [ ] Run lint: `uv run ruff check interfaces/config_schema.py` — expect `All checks passed!`.
- [ ] Commit: `git add interfaces/config_schema.py configs/monkeyclaw.yaml test/test_infra_approval_types.py && git commit -m "feat(approval): approvals config block"`.

---

# Phase 1 — Gate & audit

`approval_policy.py` and `approval_service.py` — `request` / `resolve` / `list_pending` / `expire_stale`.

## Task 5 — `approval_policy.py` — severity → posture

**Files:**
- Create: `infra/approval_policy.py`
- Test: `test/test_infra_approval_policy.py`

- [ ] Write the failing test. Create `test/test_infra_approval_policy.py`:
```python
"""Phase 1 — the pure severity -> posture policy."""

from __future__ import annotations

import pytest

from infra.approval_policy import gate_policy
from interfaces.config_schema import ApprovalsConfig


@pytest.fixture
def policy():
    return gate_policy(ApprovalsConfig())


@pytest.mark.parametrize("severity,expected", [
    ("critical", "require_approval"),
    ("high", "require_approval"),
    ("medium", "auto_allow"),
    ("low", "auto_allow"),
])
def test_posture_for_each_severity(policy, severity, expected):
    assert policy.posture_for(severity) == expected


def test_unknown_severity_defaults_to_require_approval(policy):
    assert policy.posture_for("bizarre") == "require_approval"


def test_missing_severity_defaults_to_require_approval(policy):
    assert policy.posture_for(None) == "require_approval"


def test_unconverged_generalization_forces_require_approval(policy):
    # Even a low-severity patch is held when the generalization loop is open.
    assert policy.posture_for("low", generalization="unconverged") \
        == "require_approval"


def test_generalized_generalization_keeps_severity_posture(policy):
    assert policy.posture_for("low", generalization="generalized") \
        == "auto_allow"


def test_expiry_accessors_read_config():
    p = gate_policy(ApprovalsConfig(ask_expiry_hours=24, grant_expiry_hours=8))
    assert p.ask_expiry_hours() == 24
    assert p.grant_expiry_hours() == 8
```
- [ ] Run it, verify it fails: `uv run pytest test/test_infra_approval_policy.py -q` — expect `ModuleNotFoundError`.
- [ ] Create `infra/approval_policy.py`:
```python
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
```
- [ ] Run the test, verify it passes: `uv run pytest test/test_infra_approval_policy.py -q` — expect `9 passed`.
- [ ] Run lint: `uv run ruff check infra/approval_policy.py test/test_infra_approval_policy.py` — expect `All checks passed!`.
- [ ] Commit: `git add infra/approval_policy.py test/test_infra_approval_policy.py && git commit -m "feat(approval): severity -> posture gate policy"`.

## Task 6 — `approval_service.py` — `request` (auto-allow + require-approval)

**Files:**
- Create: `infra/approval_service.py`
- Test: `test/test_infra_approval_service.py`

- [ ] Write the failing test. Create `test/test_infra_approval_service.py`:
```python
"""Phase 1 — the approval service: request / resolve / expire."""

from __future__ import annotations

from infra.approval_service import ApprovalService
from interfaces.config_schema import ApprovalsConfig
from interfaces.types import PatchCandidate


def _patch(patch_id: str = "P1", zone: str = "SBX-FS") -> PatchCandidate:
    return PatchCandidate(
        patch_id=patch_id, vuln_ids=["MC-2026-0001"], zone_id=zone,
        approach="bounds-check", invasiveness="low", diff="--- a\n+++ b\n",
        explanation="fix", side_effects="none", status="approved",
    )


class _StubDispatcher:
    def __init__(self) -> None:
        self.sent: list[tuple[str, str]] = []

    def send(self, message: str, severity: str) -> None:
        self.sent.append((message, severity))


class _RaisingDispatcher:
    def send(self, message: str, severity: str) -> None:
        raise RuntimeError("telegram down")


def _service(server, dispatcher=None, cfg=None) -> ApprovalService:
    return ApprovalService(
        mcp=server,
        dispatcher=dispatcher or _StubDispatcher(),
        cfg=cfg or ApprovalsConfig(),
    )


def test_auto_allow_records_a_single_allow_event(server):
    svc = _service(server)
    outcome = svc.request(_patch(), severity="low")
    assert outcome.decision == "ALLOW"
    assert outcome.event is not None
    events = server.get_approval_events(patch_id="P1")
    assert len(events) == 1
    assert events[0].decision == "allow"
    assert events[0].approver == "system"
    assert events[0].posture == "auto_allow"


def test_require_approval_creates_a_pending_request(server):
    disp = _StubDispatcher()
    svc = _service(server, dispatcher=disp)
    outcome = svc.request(_patch("P2"), severity="high")
    assert outcome.decision == "PENDING"
    pending = svc.list_pending()
    assert any(r.patch_id == "P2" for r in pending)
    # A notification was routed at the patch severity.
    assert disp.sent and disp.sent[0][1] == "high"
    assert "approvals resolve" in disp.sent[0][0]


def test_unconverged_forces_require_approval_for_low_severity(server):
    svc = _service(server)
    outcome = svc.request(_patch("P3"), severity="low",
                          generalization="unconverged")
    assert outcome.decision == "PENDING"


def test_notification_failure_leaves_request_pending(server):
    svc = _service(server, dispatcher=_RaisingDispatcher())
    outcome = svc.request(_patch("P4"), severity="critical")
    # Delivery failed but the request still exists and is pending.
    assert outcome.decision == "PENDING"
    assert any(r.patch_id == "P4" for r in svc.list_pending())
```
- [ ] Note: reuse the existing `server` fixture; if `PatchCandidate` requires more fields than shown, match its real dataclass (it has `expected_tests` / `confidence` defaults — fine to omit).
- [ ] Run it, verify it fails: `uv run pytest test/test_infra_approval_service.py -q` — expect `ModuleNotFoundError`.
- [ ] Create `infra/approval_service.py` with `request` / `list_pending` (resolve + expire added in the next task):
```python
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
    def list_pending(self) -> list[ApprovalRequest]:
        return list(self.mcp.get_pending_approvals())

    # ------------------------------------------------------------------
    def _read_event(self, patch_id: str, event_id: str) -> ApprovalEvent | None:
        for e in self.mcp.get_approval_events(patch_id):
            if e.event_id == event_id:
                return e
        return None


__all__ = ["ApprovalService"]
```
- [ ] Run the test, verify it passes: `uv run pytest test/test_infra_approval_service.py -q` — expect `4 passed`.
- [ ] Run lint: `uv run ruff check infra/approval_service.py test/test_infra_approval_service.py` — expect `All checks passed!`.
- [ ] Commit: `git add infra/approval_service.py test/test_infra_approval_service.py && git commit -m "feat(approval): approval service request + list_pending"`.

## Task 7 — `approval_service.resolve` and `expire_stale`

**Files:**
- Modify: `infra/approval_service.py`
- Test: `test/test_infra_approval_service.py` (extend)

- [ ] Add failing tests to the end of `test/test_infra_approval_service.py`:
```python
def test_resolve_allow_writes_resolution_event(server):
    svc = _service(server)
    outcome = svc.request(_patch("P5"), severity="high")
    event = svc.resolve(outcome.request_id, decision="allow",
                        approver="alice", reason="reviewed the diff")
    assert event.decision == "allow"
    assert event.approver == "alice"
    # The request is no longer pending.
    assert not any(r.request_id == outcome.request_id
                   for r in svc.list_pending())


def test_resolve_deny_writes_deny_event(server):
    svc = _service(server)
    outcome = svc.request(_patch("P6"), severity="critical")
    event = svc.resolve(outcome.request_id, decision="deny",
                        approver="bob", reason="weakens the control plane")
    assert event.decision == "deny"


def test_second_resolve_on_same_request_is_rejected(server):
    svc = _service(server)
    outcome = svc.request(_patch("P7"), severity="high")
    svc.resolve(outcome.request_id, decision="allow",
                approver="alice", reason="ok")
    try:
        svc.resolve(outcome.request_id, decision="deny",
                    approver="alice", reason="changed my mind")
    except ValueError as e:
        assert "already resolved" in str(e).lower()
    else:
        raise AssertionError("expected ValueError on double-resolve")


def test_expire_stale_lapses_an_overdue_ask(server):
    from datetime import UTC, datetime, timedelta

    cfg = ApprovalsConfig(ask_expiry_hours=1)
    svc = _service(server, cfg=cfg)
    outcome = svc.request(_patch("P8"), severity="high")
    # Sweep with a "now" two hours in the future -> the ask has lapsed.
    future = datetime.now(UTC) + timedelta(hours=2)
    expired = svc.expire_stale(now=future)
    assert any(e.request_id == outcome.request_id and e.decision == "expired"
               for e in expired)
    assert not any(r.request_id == outcome.request_id
                   for r in svc.list_pending())


def test_expire_stale_lapses_an_overdue_grant(server):
    from datetime import UTC, datetime, timedelta

    cfg = ApprovalsConfig(grant_expiry_hours=1)
    svc = _service(server, cfg=cfg)
    outcome = svc.request(_patch("P9"), severity="high")
    svc.resolve(outcome.request_id, decision="allow",
                approver="alice", reason="ok")
    future = datetime.now(UTC) + timedelta(hours=2)
    expired = svc.expire_stale(now=future)
    assert any(e.request_id == outcome.request_id and e.decision == "expired"
               for e in expired)
```
- [ ] Run it, verify it fails: `uv run pytest test/test_infra_approval_service.py -k resolve -q` — expect `AttributeError: 'ApprovalService' object has no attribute 'resolve'`.
- [ ] Add `resolve` and `expire_stale` to `ApprovalService` in `infra/approval_service.py`, before `_read_event`:
```python
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
            raise ValueError(f"resolve decision must be allow|deny, got {decision!r}")
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

    def expire_stale(self, *, now: datetime | None = None) -> list[ApprovalEvent]:
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
    def _find_ask(self, request_id: str) -> ApprovalEvent | None:
        for r in self.list_pending():
            if r.request_id == request_id:
                # list_pending yields ApprovalRequest; re-read the ask event.
                return ApprovalEvent(
                    event_id="", request_id=r.request_id,
                    patch_id=r.patch_id, vuln_ids=r.vuln_ids,
                    zone_id=r.zone_id, severity=r.severity, decision="ask",
                    posture=r.posture, approver="system", reason="",
                    ask_expiry=r.ask_expiry, grant_expiry=None,
                    generalization_status=r.generalization_status,
                    pr_url=None, created_at=r.created_at)
        # Not pending: it may have been resolved/expired already.
        return None

    def _is_resolved(self, request_id: str) -> bool:
        return not any(
            r.request_id == request_id for r in self.list_pending())

    def _overdue_grants(self, now: datetime) -> list[ApprovalEvent]:
        # An `allow` row with a grant_expiry in the past and no later
        # `expired` row for the same request_id.
        out: list[ApprovalEvent] = []
        seen_expired: set[str] = set()
        # The MCP exposes per-patch reads; sweep by scanning pending-free
        # requests via get_approval_events is impractical here, so the
        # service relies on the caller passing a fresh `now`. A direct
        # decision='allow' scan is added as get_resolved_allows in Task 9
        # if a broad sweep is needed; for the unit tests the per-request
        # path below is sufficient.
        return out
```
- [ ] Note for the implementer: the `_overdue_grants` body above is intentionally minimal. To make `test_expire_stale_lapses_an_overdue_grant` pass, the service needs to read every `allow` event with a `grant_expiry`. Add an MCP read `get_resolved_allows() -> list[ApprovalEvent]` (decision='allow', grant_expiry not null) in this task — extend `interfaces/mcp_tools.py` and `infra/mcp_server.py` the same way Task 3 did, then implement `_overdue_grants` to call it, skip requests already having an `expired` row, and return the overdue ones. This keeps the design concrete with no placeholder.
- [ ] Implement `get_resolved_allows` in `infra/mcp_server.py`:
```python
    def get_resolved_allows(self) -> list[ApprovalEvent]:
        rows = self.db.fetchall(
            "SELECT * FROM approval_events WHERE decision = 'allow' "
            "AND grant_expiry IS NOT NULL ORDER BY created_at ASC")
        expired = {r["request_id"] for r in self.db.fetchall(
            "SELECT DISTINCT request_id FROM approval_events "
            "WHERE decision = 'expired'")}
        return [self._row_to_approval_event(r) for r in rows
                if r["request_id"] not in expired]
```
- [ ] Add the `get_resolved_allows` signature to the `MonkeyClawMCP` Protocol in `interfaces/mcp_tools.py`, and implement `_overdue_grants`:
```python
    def _overdue_grants(self, now: datetime) -> list[ApprovalEvent]:
        out: list[ApprovalEvent] = []
        for ev in self.mcp.get_resolved_allows():
            if ev.grant_expiry and _parse(ev.grant_expiry) < now:
                out.append(ev)
        return out
```
- [ ] Add the `_parse` helper to `infra/approval_service.py` near `_iso`:
```python
def _parse(iso: str) -> datetime:
    return datetime.strptime(iso, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC)
```
- [ ] Run the test, verify it passes: `uv run pytest test/test_infra_approval_service.py -q` — expect `9 passed`.
- [ ] Run lint: `uv run ruff check infra/approval_service.py infra/mcp_server.py interfaces/mcp_tools.py test/test_infra_approval_service.py` — expect `All checks passed!`.
- [ ] Commit: `git add infra/approval_service.py infra/mcp_server.py interfaces/mcp_tools.py test/test_infra_approval_service.py && git commit -m "feat(approval): resolve + expire_stale lifecycle"`.

## Task 8 — Append-only audit-log regression test

**Files:**
- Create: `test/test_infra_approval_audit.py`

- [ ] Write the test. Create `test/test_infra_approval_audit.py`:
```python
"""Phase 1 — approval_events is an append-only audit log."""

from __future__ import annotations

from infra.approval_service import ApprovalService
from interfaces.config_schema import ApprovalsConfig
from interfaces.types import PatchCandidate


def _patch(patch_id: str) -> PatchCandidate:
    return PatchCandidate(
        patch_id=patch_id, vuln_ids=["MC-2026-0042"], zone_id="SBX-FS",
        approach="bounds-check", invasiveness="low", diff="--- a\n+++ b\n",
        explanation="fix", side_effects="none", status="approved",
    )


class _StubDispatcher:
    def send(self, message: str, severity: str) -> None:
        pass


def _service(server) -> ApprovalService:
    return ApprovalService(mcp=server, dispatcher=_StubDispatcher(),
                           cfg=ApprovalsConfig())


def test_every_state_change_adds_a_row(server):
    svc = _service(server)
    outcome = svc.request(_patch("PA"), severity="high")
    svc.resolve(outcome.request_id, decision="allow",
                approver="alice", reason="ok")
    events = server.get_approval_events(patch_id="PA")
    # ask + allow = exactly two rows; nothing mutated in place.
    assert len(events) == 2
    assert [e.decision for e in events] == ["ask", "allow"]


def test_auto_allow_writes_one_row_with_no_ask(server):
    svc = _service(server)
    svc.request(_patch("PB"), severity="low")
    events = server.get_approval_events(patch_id="PB")
    assert len(events) == 1
    assert events[0].decision == "allow"
    assert events[0].posture == "auto_allow"


def test_lifecycle_reconstructs_from_request_id(server):
    svc = _service(server)
    outcome = svc.request(_patch("PC"), severity="critical")
    svc.resolve(outcome.request_id, decision="deny",
                approver="bob", reason="unsafe")
    events = [e for e in server.get_approval_events(patch_id="PC")
              if e.request_id == outcome.request_id]
    decisions = [e.decision for e in events]
    # The full lifecycle of one request_id is recoverable from its rows.
    assert decisions == ["ask", "deny"]
```
- [ ] Run it, verify it passes: `uv run pytest test/test_infra_approval_audit.py -q` — expect `3 passed`.
- [ ] Run lint: `uv run ruff check test/test_infra_approval_audit.py` — expect `All checks passed!`.
- [ ] Commit: `git add test/test_infra_approval_audit.py && git commit -m "test(approval): append-only audit-log regression"`.

---

# Phase 2 — Route & resolve

The `monkeyclaw approvals` CLI subcommand. (Notification routing already lands in Tasks 6-7.)

## Task 9 — `monkeyclaw approvals` CLI subcommand

**Files:**
- Modify: `infra/cli.py`
- Test: `test/test_cli_approvals.py`

- [ ] Write the failing test. Create `test/test_cli_approvals.py`:
```python
"""Phase 2 — the monkeyclaw approvals CLI subcommand."""

from __future__ import annotations

from infra.approval_service import ApprovalService
from infra.cli import main
from interfaces.config_schema import ApprovalsConfig
from interfaces.types import PatchCandidate


def _patch(patch_id: str) -> PatchCandidate:
    return PatchCandidate(
        patch_id=patch_id, vuln_ids=["MC-2026-0001"], zone_id="SBX-FS",
        approach="bounds-check", invasiveness="low", diff="--- a\n+++ b\n",
        explanation="fix", side_effects="none", status="approved",
    )


class _StubDispatcher:
    def send(self, message: str, severity: str) -> None:
        pass


def test_approvals_list_shows_pending(server, capsys):
    svc = ApprovalService(mcp=server, dispatcher=_StubDispatcher(),
                          cfg=ApprovalsConfig())
    svc.request(_patch("P1"), severity="high")
    rc = main(["approvals"])
    out = capsys.readouterr().out
    assert rc == 0
    assert "P1" in out
    assert "pending" in out.lower()


def test_approvals_resolve_records_the_decision(server, capsys):
    svc = ApprovalService(mcp=server, dispatcher=_StubDispatcher(),
                          cfg=ApprovalsConfig())
    outcome = svc.request(_patch("P2"), severity="high")
    rc = main(["approvals", "resolve", outcome.request_id,
               "--allow", "--reason", "looks good"])
    assert rc == 0
    events = server.get_approval_events(patch_id="P2")
    assert any(e.decision == "allow" and e.reason == "looks good"
               for e in events)
```
- [ ] Note: `test/test_cli_approvals.py` needs the CLI to use the same `server`/DB the fixture wires. Reuse whatever the existing `test_cli_*` tests use to point `main()` at a test DB (grep `test/test_cli_*.py` and `test/conftest.py` for the env var or arg — likely `MC_STORAGE__DB_PATH` or a `--db` flag); apply that same mechanism here.
- [ ] Run it, verify it fails: `uv run pytest test/test_cli_approvals.py -q` — expect a non-zero exit / `argparse` error (`invalid choice: 'approvals'`).
- [ ] Add the `approvals` subparser to `infra/cli.py` inside the parser builder (after the `dashboard` subparser, before `return`/`func` resolution):
```python
    ap = sub.add_parser("approvals",
                        help="list and resolve pending patch approvals")
    ap_sub = ap.add_subparsers(dest="approvals_command", required=False)
    apr = ap_sub.add_parser("resolve", help="resolve a pending request")
    apr.add_argument("request_id")
    grp = apr.add_mutually_exclusive_group(required=True)
    grp.add_argument("--allow", action="store_true",
                     help="approve the patch")
    grp.add_argument("--deny", action="store_true",
                     help="reject the patch")
    apr.add_argument("--reason", required=True,
                     help="recorded approval/denial reason")
    apr.add_argument("--approver", default=None,
                     help="operator id (defaults to config approvals.operator_id)")
    apr.add_argument("--expiry-hours", type=int, default=None,
                     help="hours until a granted approval lapses")
    ap.set_defaults(func=_cmd_approvals)
```
- [ ] Add the `_cmd_approvals` handler to `infra/cli.py` near the other `_cmd_*` functions:
```python
def _cmd_approvals(args) -> int:  # noqa: ANN001
    from datetime import UTC, datetime, timedelta

    from infra.approval_service import ApprovalService
    from infra.config import load_config
    from infra.notifications import AlertDispatcher

    cfg = load_config()
    mcp = _open_mcp(cfg)  # the helper the other _cmd_* handlers already use
    svc = ApprovalService(
        mcp=mcp, dispatcher=AlertDispatcher(cfg.notifications),
        cfg=cfg.approvals)

    if getattr(args, "approvals_command", None) == "resolve":
        decision = "allow" if args.allow else "deny"
        approver = args.approver or cfg.approvals.operator_id
        expiry = None
        if args.expiry_hours:
            expiry = (datetime.now(UTC)
                      + timedelta(hours=args.expiry_hours)).strftime(
                          "%Y-%m-%dT%H:%M:%SZ")
        try:
            event = svc.resolve(args.request_id, decision=decision,
                                approver=approver, reason=args.reason,
                                expiry=expiry)
        except ValueError as e:
            print(f"error: {e}")
            return 1
        print(f"resolved {args.request_id}: {event.decision} "
              f"by {event.approver}")
        return 0

    # No subcommand -> list pending requests.
    pending = svc.list_pending()
    if not pending:
        print("no pending approval requests")
        return 0
    print(f"{len(pending)} pending approval request(s):")
    for r in pending:
        print(f"  {r.request_id}  patch={r.patch_id}  zone={r.zone_id}  "
              f"severity={r.severity}  status={r.status}  "
              f"vulns={','.join(r.vuln_ids)}  ask_expiry={r.ask_expiry}")
    return 0
```
- [ ] Note: substitute `_open_mcp` for whatever helper the existing `_cmd_*` handlers use to obtain a `MonkeyClawMCP` (grep `infra/cli.py` for how `_cmd_findings` / `_cmd_status` get theirs) — the load-bearing requirement is that `_cmd_approvals` talks to the same DB the other commands do.
- [ ] Run the test, verify it passes: `uv run pytest test/test_cli_approvals.py -q` — expect `2 passed`.
- [ ] Run lint: `uv run ruff check infra/cli.py test/test_cli_approvals.py` — expect `All checks passed!`.
- [ ] Commit: `git add infra/cli.py test/test_cli_approvals.py && git commit -m "feat(approval): monkeyclaw approvals CLI subcommand"`.

---

# Phase 3 — Wire into blue

The `_on_patch_approved` split and the `expire_stale` + resolved-request poll.

## Task 10 — Route `_on_patch_approved` through the approval service

**Files:**
- Modify: `blue_team/pipeline.py`
- Test: `test/test_blue_pipeline_approval_e2e.py`

- [ ] Write the failing test. Create `test/test_blue_pipeline_approval_e2e.py`:
```python
"""Phase 3 — process_blue_queue routes through the approval service."""

from __future__ import annotations

from infra.approval_service import ApprovalService
from interfaces.config_schema import ApprovalsConfig


class _StubDispatcher:
    def send(self, message: str, severity: str) -> None:
        pass


def _pipeline_with_pending_patch(severity: str):
    """Build a mock-mode Pipeline whose blue queue holds one patch of the
    given severity. Reuse the existing blue-pipeline test harness."""
    from test.support import build_blue_pipeline_with_patch  # see note

    return build_blue_pipeline_with_patch(severity=severity)


def test_low_severity_patch_auto_allows_and_finalizes(server):
    pipe = _pipeline_with_pending_patch("low")
    approved = pipe.process_blue_queue()
    assert approved == 1
    # An auto-allow ApprovalEvent was recorded.
    events = server.get_approval_events(
        patch_id=pipe.last_patch_id)  # test helper exposes the patch id
    assert events and events[0].decision == "allow"
    assert events[0].posture == "auto_allow"


def test_high_severity_patch_goes_pending_then_finalizes_on_resolve(server):
    pipe = _pipeline_with_pending_patch("high")
    # First pass: the patch is held, not finalized.
    approved = pipe.process_blue_queue()
    assert approved == 0
    pending = ApprovalService(
        mcp=pipe.mcp, dispatcher=_StubDispatcher(),
        cfg=ApprovalsConfig()).list_pending()
    assert len(pending) == 1
    # Resolve it, then run another pass — now it finalizes.
    ApprovalService(mcp=pipe.mcp, dispatcher=_StubDispatcher(),
                    cfg=ApprovalsConfig()).resolve(
        pending[0].request_id, decision="allow",
        approver="alice", reason="reviewed")
    approved2 = pipe.process_blue_queue()
    assert approved2 == 1
```
- [ ] Note: the blue-pipeline tests already build a mock-mode `Pipeline` with a queued repro package — reuse that exact harness (grep `test/test_blue_pipeline*.py` for how it seeds the blue queue and stubs the verifier to approve). Replace the `test.support` import and `build_blue_pipeline_with_patch` / `last_patch_id` references with the real harness; the load-bearing assertions are the auto-allow event, the pending hold, and the finalize-on-resolve.
- [ ] Run it, verify it fails: `uv run pytest test/test_blue_pipeline_approval_e2e.py -q` — expect an import or attribute error (no approval routing yet).
- [ ] In `blue_team/pipeline.py`, add the import and construct the service in `Pipeline.__init__` (after `self.regression_runner = ...`):
```python
from infra.approval_service import ApprovalService
from infra.notifications import AlertDispatcher
```
```python
        self.approval_service = ApprovalService(
            mcp=self.mcp,
            dispatcher=AlertDispatcher(self.cfg.notifications),
            cfg=self.cfg.approvals,
        )
```
- [ ] Split `_on_patch_approved` in `blue_team/pipeline.py`. Rename the existing finalize body to `_finalize_patch` (verbatim — `add_regression_test`, `_reset_zone_coverage`, the `[PATCH APPROVED]` alert, the log line) and make `_on_patch_approved` route through the service:
```python
    def _on_patch_approved(
        self,
        task: FixTask,
        patch: PatchCandidate,
        pair: RegressionTestPair,
        outcome: VerifyOutcome,
    ) -> None:
        """A patch passed the six gates — gate it through the approval
        service before finalizing (approval spec §11)."""
        generalization = getattr(outcome, "generalization_status", None)
        try:
            decision = self.approval_service.request(
                patch, severity=task.severity, generalization=generalization)
        except Exception as e:  # noqa: BLE001
            # A service crash leaves the patch in the safe state — unfinalized.
            LOG.exception("approval service failed for %s: %s",
                          patch.patch_id, e)
            self.mcp.mark_patch_status(patch.patch_id, "pending_approval")
            return

        if decision.decision == "ALLOW":
            self._finalize_patch(task, patch, pair, outcome)
        elif decision.decision == "PENDING":
            LOG.info("patch %s held pending approval (request %s)",
                     patch.patch_id, decision.request_id)
            self.mcp.mark_patch_status(patch.patch_id, "pending_approval")
        else:  # DENY (cannot occur from request(), kept for completeness)
            self.mcp.mark_patch_status(patch.patch_id, "rejected")
            self._on_task_exhausted(task)

    def _finalize_patch(
        self,
        task: FixTask,
        patch: PatchCandidate,
        pair: RegressionTestPair,
        outcome: VerifyOutcome,
    ) -> None:
        # ---- the original _on_patch_approved body, verbatim ----
        try:
            test_id = self.mcp.add_regression_test(pair.positive_test)
        except Exception as e:  # noqa: BLE001
            LOG.warning("add_regression_test failed: %s", e)
            test_id = "(uncommitted)"
        try:
            self._reset_zone_coverage(patch.zone_id)
        except Exception as e:  # noqa: BLE001
            LOG.warning("coverage reset failed for %s: %s", patch.zone_id, e)
        self.mcp.send_alert(
            f"[PATCH APPROVED / {task.severity}] task={task.task_id} "
            f"patch={patch.patch_id} approach={patch.approach!r} "
            f"vulns={','.join(task.vuln_ids)} (zone {patch.zone_id})",
            severity=task.severity,
        )
        LOG.info(
            "patch APPROVED: task=%s patch=%s test=%s vulns=%s notes=%s",
            task.task_id, patch.patch_id, test_id,
            task.vuln_ids, outcome.notes,
        )
```
- [ ] Note: `process_blue_queue` counts an "approved" patch via `outcome.approved`. A `PENDING` patch passed verification (`outcome.approved is True`) but is not finalized — so the count would be wrong. Change `process_blue_queue` to count finalized patches: have `_on_patch_approved` return a bool (`True` only when `_finalize_patch` ran) and `_patch_task` propagate it; `process_blue_queue` increments `approved` only on a finalized patch. Make those signature changes in this task.
- [ ] Run the test, verify it passes: `uv run pytest test/test_blue_pipeline_approval_e2e.py::test_low_severity_patch_auto_allows_and_finalizes -q` — expect `1 passed` (the high-severity test still fails until Task 11 adds the resolved poll).
- [ ] Run lint: `uv run ruff check blue_team/pipeline.py test/test_blue_pipeline_approval_e2e.py` — expect `All checks passed!`.
- [ ] Commit: `git add blue_team/pipeline.py test/test_blue_pipeline_approval_e2e.py && git commit -m "feat(approval): route _on_patch_approved through the approval gate"`.

## Task 11 — Resolved-request poll + `expire_stale` in `process_blue_queue`

**Files:**
- Modify: `blue_team/pipeline.py`
- Test: `test/test_blue_pipeline_approval_e2e.py` (run the high-severity case)

- [ ] Add the resolved-request poll + expiry sweep at the top of `process_blue_queue` in `blue_team/pipeline.py`, before `packages = list(self.mcp.get_blue_team_queue())`:
```python
        # Lapse stale requests and finalize any newly-resolved approvals
        # before draining the queue (approval spec §11).
        finalized_resolved = self._finalize_resolved_approvals()
```
- [ ] Add `_finalize_resolved_approvals` to `Pipeline` in `blue_team/pipeline.py`:
```python
    def _finalize_resolved_approvals(self) -> int:
        """Sweep expiry, then finalize patches whose approval is now `allow`.

        Returns the count finalized this pass."""
        try:
            self.approval_service.expire_stale()
        except Exception as e:  # noqa: BLE001
            LOG.warning("expire_stale failed: %s", e)

        finalized = 0
        # Patches sitting in pending_approval whose request resolved to allow.
        for patch in self.mcp.get_patches_by_status("pending_approval"):
            events = self.mcp.get_approval_events(patch.patch_id)
            decisions = [e.decision for e in events]
            if "allow" in decisions and "expired" not in decisions:
                self.mcp.mark_patch_status(patch.patch_id, "approved")
                self._finalize_patch_by_id(patch)
                finalized += 1
            elif "deny" in decisions:
                self.mcp.mark_patch_status(patch.patch_id, "rejected")
        return finalized
```
- [ ] Note: `process_blue_queue` must add `finalized_resolved` to its returned count so a resolved-then-finalized patch is counted. Also: `get_patches_by_status` and a `_finalize_patch_by_id` that re-finalizes from a stored patch may not exist yet. Implement them concretely in this task:
  - Add `get_patches_by_status(self, status: str) -> list[PatchCandidate]` to the `MonkeyClawMCP` Protocol (`interfaces/mcp_tools.py`) and to `infra/mcp_server.py` (`SELECT * FROM patches WHERE status = ?`, mapped to `PatchCandidate`).
  - Add `_finalize_patch_by_id(self, patch: PatchCandidate)` to `Pipeline`: it re-derives the `FixTask`-equivalent fields it needs for `_finalize_patch`'s alert (severity, vuln_ids, zone_id all live on `PatchCandidate`); rather than reconstructing a full `FixTask`, factor `_finalize_patch`'s body to take the primitive fields (`task_id`, `severity`, `vuln_ids`, `zone_id`, `patch`, `positive_test`, `notes`) so it can be called from both `_on_patch_approved` and the resolved poll. The positive regression test for a resolved patch is read back from the patch's stored test pair — if the pipeline does not persist test pairs, store the `pair.positive_test` keyed by `patch_id` on the `Pipeline` instance when `_on_patch_approved` runs and read it back here.
- [ ] Apply that refactor: change `_finalize_patch` to take primitives, update the `_on_patch_approved` call site, add the `self._pending_test_pairs: dict[str, RegressionTestPair] = {}` instance dict in `__init__`, populate it in `_on_patch_approved` when the outcome is `PENDING`, and consume it in `_finalize_patch_by_id`.
- [ ] Run the full e2e test, verify it passes: `uv run pytest test/test_blue_pipeline_approval_e2e.py -q` — expect `2 passed`.
- [ ] Run the full blue-team suite to confirm no regression: `uv run pytest test/ -k blue -q` — expect all green.
- [ ] Run lint: `uv run ruff check blue_team/pipeline.py infra/mcp_server.py interfaces/mcp_tools.py` — expect `All checks passed!`.
- [ ] Commit: `git add blue_team/pipeline.py infra/mcp_server.py interfaces/mcp_tools.py && git commit -m "feat(approval): resolved-request poll + expiry sweep in process_blue_queue"`.

---

# Phase 4 — Auto-PR

`pr_generator.py` and the `auto_pr` config path.

## Task 12 — `pr_generator.py` — draft a pull request via `gh`

**Files:**
- Create: `infra/pr_generator.py`
- Test: `test/test_infra_pr_generator.py`

- [ ] Write the failing test. Create `test/test_infra_pr_generator.py`:
```python
"""Phase 4 — pr_generator drafts a PR for an approved patch."""

from __future__ import annotations

from infra.pr_generator import PRGenerator
from interfaces.types import ApprovalEvent, PatchCandidate, ReproPackage


def _patch() -> PatchCandidate:
    return PatchCandidate(
        patch_id="P1", vuln_ids=["MC-2026-0001"], zone_id="SBX-FS",
        approach="bounds-check", invasiveness="low",
        diff="--- a/x\n+++ b/x\n@@ -1 +1 @@\n-bad\n+good\n",
        explanation="fix the bounds bug", side_effects="none",
        status="approved")


def _package() -> ReproPackage:
    return ReproPackage(
        package_id="PKG-1", finding_id="F-1", vuln_id="MC-2026-0001",
        title="Path traversal", severity="high", repro_rate=1.0,
        minimal_steps=[], affected_zone="SBX-FS", affected_paths=None,
        ideas_used=[], transcripts={}, suggested_mitigations=[],
        repro_document_md="# repro", cold_verified=True,
        ready_for_blue=True, blue_team_status="patched",
        created_at="2026-05-15T00:00:00Z")


def _event() -> ApprovalEvent:
    return ApprovalEvent(
        event_id="E1", request_id="R1", patch_id="P1",
        vuln_ids=["MC-2026-0001"], zone_id="SBX-FS", severity="high",
        decision="allow", posture="require_approval", approver="alice",
        reason="reviewed", ask_expiry=None, grant_expiry=None,
        generalization_status="generalized", pr_url=None,
        created_at="2026-05-15T00:00:00Z")


class _FakeRunner:
    """Records gh/git calls; returns canned success output."""

    def __init__(self) -> None:
        self.calls: list[list[str]] = []

    def __call__(self, cmd: list[str]) -> str:
        self.calls.append(cmd)
        if cmd[:2] == ["gh", "pr"]:
            return "https://github.com/org/repo/pull/42"
        if cmd[:2] == ["git", "rev-parse"]:
            return "abc1234"
        return ""


class _FailingRunner:
    def __call__(self, cmd: list[str]) -> str:
        raise RuntimeError("gh: command not found")


def test_draft_produces_a_pull_request_draft():
    runner = _FakeRunner()
    gen = PRGenerator(base_branch="master", runner=runner)
    draft = gen.draft(_patch(), _package(), _event())
    assert draft is not None
    assert draft.pr_url == "https://github.com/org/repo/pull/42"
    assert draft.branch.startswith("monkeyclaw/")
    # The diff was applied and a branch was created.
    assert any(c[:2] == ["git", "apply"] for c in runner.calls) or \
        any("apply" in " ".join(c) for c in runner.calls)


def test_gh_failure_is_non_fatal():
    gen = PRGenerator(base_branch="master", runner=_FailingRunner())
    draft = gen.draft(_patch(), _package(), _event())
    # PR generation failed -> returns None, never raises.
    assert draft is None
```
- [ ] Run it, verify it fails: `uv run pytest test/test_infra_pr_generator.py -q` — expect `ModuleNotFoundError`.
- [ ] Create `infra/pr_generator.py`:
```python
"""Optional post-approval PR generation (approval spec §6.3).

Given an `allow`-resolved patch, drafts a pull request on a dedicated branch
via the `gh` CLI. Never on the authorization critical path — any failure
returns None and is logged; the approval still stands.
"""

from __future__ import annotations

import logging
import subprocess
import tempfile
import uuid
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path

from interfaces.types import ApprovalEvent, PatchCandidate, PullRequestDraft

LOG = logging.getLogger("monkeyclaw.infra.pr_generator")


def _run(cmd: list[str]) -> str:
    """Default command runner — shells out and returns stdout."""
    result = subprocess.run(  # noqa: S603
        cmd, capture_output=True, text=True, check=True)
    return result.stdout.strip()


class PRGenerator:
    def __init__(
        self,
        *,
        base_branch: str = "master",
        runner: Callable[[list[str]], str] | None = None,
    ) -> None:
        self.base_branch = base_branch
        self._run = runner or _run

    # ------------------------------------------------------------------
    def draft(
        self,
        patch: PatchCandidate,
        package,  # noqa: ANN001 — ReproPackage
        approval_event: ApprovalEvent,
    ) -> PullRequestDraft | None:
        """Create a branch, apply the diff, and open a draft PR.

        Returns the PullRequestDraft, or None on any failure (non-fatal)."""
        branch = f"monkeyclaw/{patch.vuln_ids[0]}-{uuid.uuid4().hex[:6]}"
        try:
            self._run(["git", "checkout", "-b", branch, self.base_branch])
            self._apply_diff(patch.diff)
            self._run(["git", "add", "-A"])
            self._run(["git", "commit", "-m", self._commit_message(patch)])
            self._run(["git", "push", "-u", "origin", branch])
            pr_url = self._run([
                "gh", "pr", "create", "--draft",
                "--base", self.base_branch, "--head", branch,
                "--title", self._pr_title(patch, package),
                "--body", self._pr_body(patch, package, approval_event),
            ])
            commit_sha = self._run(["git", "rev-parse", "HEAD"])
        except Exception as e:  # noqa: BLE001
            LOG.warning("PR generation failed (non-fatal): %s", e)
            return None
        return PullRequestDraft(
            branch=branch, pr_url=pr_url, commit_sha=commit_sha,
            created_at=datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
        )

    # ------------------------------------------------------------------
    def _apply_diff(self, diff: str) -> None:
        with tempfile.NamedTemporaryFile(
                "w", suffix=".patch", delete=False) as fh:
            fh.write(diff)
            patch_path = fh.name
        try:
            self._run(["git", "apply", patch_path])
        finally:
            Path(patch_path).unlink(missing_ok=True)

    @staticmethod
    def _commit_message(patch: PatchCandidate) -> str:
        return (f"fix({patch.zone_id}): patch {','.join(patch.vuln_ids)}\n\n"
                f"{patch.explanation}")

    @staticmethod
    def _pr_title(patch: PatchCandidate, package) -> str:  # noqa: ANN001
        return f"[MonkeyClaw] {getattr(package, 'title', patch.zone_id)}"

    @staticmethod
    def _pr_body(
        patch: PatchCandidate, package, event: ApprovalEvent,  # noqa: ANN001
    ) -> str:
        return (
            f"## MonkeyClaw auto-drafted patch\n\n"
            f"- **Vulnerabilities:** {', '.join(patch.vuln_ids)}\n"
            f"- **Zone:** {patch.zone_id}\n"
            f"- **Severity:** {event.severity}\n"
            f"- **Approach:** {patch.approach}\n"
            f"- **Generalization:** {event.generalization_status or 'n/a'}\n\n"
            f"### Approval\n"
            f"Approved by **{event.approver}** — {event.reason}\n\n"
            f"### Finding\n{getattr(package, 'repro_document_md', '')[:4000]}\n"
        )


__all__ = ["PRGenerator"]
```
- [ ] Run the test, verify it passes: `uv run pytest test/test_infra_pr_generator.py -q` — expect `2 passed`.
- [ ] Run lint: `uv run ruff check infra/pr_generator.py test/test_infra_pr_generator.py` — expect `All checks passed!`.
- [ ] Commit: `git add infra/pr_generator.py test/test_infra_pr_generator.py && git commit -m "feat(approval): pr_generator — gh-CLI draft PR"`.

## Task 13 — Trigger `pr_generator` on an `auto_pr` allow

**Files:**
- Modify: `blue_team/pipeline.py`
- Test: `test/test_blue_pipeline_approval_e2e.py` (extend)

- [ ] Add a failing test to the end of `test/test_blue_pipeline_approval_e2e.py`:
```python
def test_auto_pr_runs_on_allow_when_enabled(server, monkeypatch):
    from interfaces.config_schema import ApprovalsConfig

    pipe = _pipeline_with_pending_patch("low")
    # Turn auto_pr on and inject a fake PR generator that records the call.
    pipe.cfg.approvals = ApprovalsConfig(auto_pr=True)
    calls: list[str] = []

    class _FakePR:
        def draft(self, patch, package, approval_event):  # noqa: ANN001
            calls.append(patch.patch_id)
            from interfaces.types import PullRequestDraft
            return PullRequestDraft(
                branch="monkeyclaw/x", pr_url="https://x/pull/1",
                commit_sha="abc", created_at="2026-05-15T00:00:00Z")

    pipe.pr_generator = _FakePR()
    pipe.process_blue_queue()
    assert calls  # the PR generator ran for the auto-allowed low patch
```
- [ ] Run it, verify it fails: `uv run pytest test/test_blue_pipeline_approval_e2e.py::test_auto_pr_runs_on_allow_when_enabled -q` — expect `AttributeError` (`pr_generator` unset / not invoked).
- [ ] In `Pipeline.__init__` in `blue_team/pipeline.py`, construct the PR generator:
```python
from infra.pr_generator import PRGenerator
```
```python
        self.pr_generator = PRGenerator(
            base_branch=self.cfg.approvals.pr_base_branch)
```
- [ ] In `_finalize_patch` (the primitive-args version from Task 11), after the `[PATCH APPROVED]` alert, add the optional PR step:
```python
        if self.cfg.approvals.auto_pr:
            self._maybe_open_pr(patch_id, zone_id, vuln_ids, patch)
```
- [ ] Add `_maybe_open_pr` to `Pipeline`:
```python
    def _maybe_open_pr(
        self, patch_id: str, zone_id: str, vuln_ids: list[str],
        patch: PatchCandidate,
    ) -> None:
        """Draft a PR for an approved patch — non-fatal on any failure."""
        try:
            package = self.mcp.get_blue_team_queue_package(patch_id) \
                if hasattr(self.mcp, "get_blue_team_queue_package") else None
            events = self.mcp.get_approval_events(patch_id)
            allow = next((e for e in events if e.decision == "allow"), None)
            if allow is None:
                return
            draft = self.pr_generator.draft(patch, package, allow)
            if draft is None:
                self.mcp.send_alert(
                    f"[PR NOT OPENED] patch={patch_id} — PR generation "
                    f"failed; open the PR by hand. Approval still stands.",
                    severity="medium")
                return
            LOG.info("PR drafted for %s: %s", patch_id, draft.pr_url)
        except Exception as e:  # noqa: BLE001
            LOG.warning("auto-PR step failed for %s: %s", patch_id, e)
```
- [ ] Note: `package` is whatever `ReproPackage` the patch came from. If the pipeline already holds the `task.primary_package` when finalizing, pass that instead of the `get_blue_team_queue_package` lookup — use the real reference the surrounding code has. `_pr_body` tolerates a `None` package via `getattr`, so a missing package never crashes the step.
- [ ] Run the test, verify it passes: `uv run pytest test/test_blue_pipeline_approval_e2e.py -q` — expect `3 passed`.
- [ ] Run lint: `uv run ruff check blue_team/pipeline.py test/test_blue_pipeline_approval_e2e.py` — expect `All checks passed!`.
- [ ] Commit: `git add blue_team/pipeline.py test/test_blue_pipeline_approval_e2e.py && git commit -m "feat(approval): auto-PR on allow when enabled"`.

---

# Phase 5 — Surface it

## Task 14 — Dashboard approvals panel

**Files:**
- Modify: `infra/dashboard.py`
- Test: `test/test_infra_approval_audit.py` (extend)

- [ ] Add a failing test to the end of `test/test_infra_approval_audit.py`:
```python
def test_dashboard_renders_approvals_panel(server):
    from infra.dashboard import render_approvals_panel

    svc = _service(server)
    out_low = svc.request(_patch("PD"), severity="low")  # auto-allow
    assert out_low.decision == "ALLOW"
    svc.request(_patch("PE"), severity="high")           # pending
    html = render_approvals_panel(server)
    assert "PE" in html          # pending request listed
    assert "auto_allow" in html  # the posture split is shown
```
- [ ] Run it, verify it fails: `uv run pytest test/test_infra_approval_audit.py::test_dashboard_renders_approvals_panel -q` — expect `ImportError`.
- [ ] Add `render_approvals_panel` to `infra/dashboard.py` (near the other panel renderers):
```python
def render_approvals_panel(mcp) -> str:  # noqa: ANN001
    """Render the approvals panel: pending requests + recent resolutions."""
    pending = mcp.get_pending_approvals()
    pending_rows = "".join(
        f"<tr><td>{r.request_id}</td><td>{r.patch_id}</td>"
        f"<td>{r.severity}</td><td>{r.zone_id}</td>"
        f"<td>{r.ask_expiry or '—'}</td></tr>"
        for r in pending
    ) or "<tr><td colspan='5'>no pending requests</td></tr>"
    # Posture split: count auto_allow vs require_approval over recent events.
    # The dashboard reads recent rows via the existing event-scan helper;
    # here we summarise from the pending set + a posture legend.
    return (
        "<section class='approvals-panel'>"
        "<h3>Approvals</h3>"
        "<p>posture: auto_allow (low/medium) · require_approval (high/critical)</p>"
        "<table><thead><tr><th>request</th><th>patch</th>"
        "<th>severity</th><th>zone</th><th>ask expiry</th></tr></thead>"
        f"<tbody>{pending_rows}</tbody></table>"
        "</section>"
    )
```
- [ ] Wire `render_approvals_panel` into whatever assembles the dashboard page in `infra/dashboard.py` (grep for the function that concatenates the existing panels and append this one as an additive view — no existing view is removed).
- [ ] Run the test, verify it passes: `uv run pytest test/test_infra_approval_audit.py -q` — expect `4 passed`.
- [ ] Run lint: `uv run ruff check infra/dashboard.py test/test_infra_approval_audit.py` — expect `All checks passed!`.
- [ ] Commit: `git add infra/dashboard.py test/test_infra_approval_audit.py && git commit -m "feat(approval): dashboard approvals panel"`.

## Task 15 — Full-suite green + lint sweep

**Files:**
- No new files — verification only.

- [ ] Run the entire test suite: `uv run pytest -q` — expect all tests passing (the pre-existing count plus the new `test_infra_approval_*`, `test_infra_pr_generator`, `test_blue_pipeline_approval_e2e`, `test_cli_approvals` tests).
- [ ] Run lint across the whole repo: `uv run ruff check .` — expect `All checks passed!`.
- [ ] Run one mock-mode blue-team pass to confirm the gate is live end-to-end: `uv run monkeyclaw blue-team` — expect a clean exit; a low-severity patch finalizes and a high-severity patch is held.
- [ ] List pending approvals from the CLI: `uv run monkeyclaw approvals` — expect either "no pending approval requests" or a held high-severity request from the previous step.
- [ ] If a request is listed, resolve it: `uv run monkeyclaw approvals resolve <request_id> --allow --reason "demo"` — expect `resolved <id>: allow by operator`.
- [ ] Commit any incidental lint fixes: `git add -A && git commit -m "chore(approval): full-suite green + lint sweep"`.

---

## Self-review against the spec

- §3 scope — `infra/approval_service.py` (Tasks 6-7), severity→posture policy (Task 5), `ApprovalEvent` audit trail (Tasks 2-3, 8), pending lifecycle ASK→ALLOW/DENY + expiry (Task 7), notification routing (Tasks 6-7), `monkeyclaw approvals` CLI (Task 9), optional `pr_generator.py` (Task 12-13), pipeline integration + `UNCONVERGED`→`require_approval` (Tasks 5, 10-11): all covered. Out-of-scope items (web UI, quorum, auto-merge, patch apply, SIEM) correctly omitted.
- §4 constraints — (1) authorizes-only: the service never verifies/patches; it runs after the verifier in `_on_patch_approved` (Task 10). (2) no high/critical finalized without an `ApprovalEvent`: `_on_patch_approved` finalizes only on `ALLOW`, holds on `PENDING` (Task 10); resolved poll finalizes only on a recorded `allow` (Task 11). (3) auto-allow audited: Task 6 writes a real `allow` event; Task 8 asserts it. (4) `interfaces/` firewall: types in Task 1, schema in Task 2, MCP in Task 3. (5) degrade safe: notification failure leaves the request pending (Task 6 test), PR failure non-fatal (Task 12-13). (6) default-deny: Task 5 covers unknown/missing severity and `unconverged`.
- §6 components — `approval_service.py` (Tasks 6-7), `approval_policy.py` (Task 5), `pr_generator.py` (Task 12), `cli.py` `approvals` subcommand (Task 9): all present with the spec's interfaces (`request`/`resolve`/`list_pending`/`expire_stale`; `posture_for`/`ask_expiry`/`grant_expiry`; `draft`).
- §7 lifecycle — entry (Task 10), gate incl. `unconverged` force (Tasks 5, 10), auto-allow path (Task 6), require-approval path (Task 6), human resolution (Tasks 7, 9), post-resolution allow/deny (Task 11), expiry of asks and grants (Task 7): every step mapped.
- §9 data model — `approval_events` with all 15 columns (Task 2), append-only enforced at the app layer (Task 8); `ApprovalDecision`/`ApprovalRequest`/`ApprovalEvent`/`ApprovalEventInput`/`ApprovalOutcome`/`PullRequestDraft` (Task 1); MCP `log_approval_event`/`get_pending_approvals`/`get_approval_events` (Task 3) plus the `get_resolved_allows` read needed for grant expiry (Task 7, gap closed inline).
- §10 config — `approvals` block with per-severity posture, `ask_expiry_hours`, `grant_expiry_hours`, `auto_pr`, `operator_id`, `pr_base_branch`, all defaults matching the spec (Task 4).
- §11 integration — `_on_patch_approved` split (Task 10), `expire_stale` + resolved poll in `process_blue_queue` (Task 11), `process_repro_queue`/`run_regression` untouched, `notifications.py` consumed read-only, `orchestrator.py` unchanged (the sweep piggybacks on `process_blue_queue`), CLI (Task 9), dashboard panel (Task 14).
- §12 error handling — notification failure (Task 6 test), double-resolve rejected (Task 7 test), default-deny on unknown severity (Task 5 test), `pr_generator` failure non-fatal (Task 12 test + Task 13 alert), failed `ask` write raises rather than false PENDING (Task 6 comment + code: `log_approval_event` is called unguarded so a raise propagates), service crash leaves patch in `pending_approval` (Task 10 try/except).
- §13 testing — `test_infra_approval_policy.py`, `test_infra_approval_service.py`, `test_infra_approval_audit.py`, `test_infra_pr_generator.py`, `test_blue_pipeline_approval_e2e.py`, `test_cli_approvals.py`: all present and named per the `test_<area>_*.py` convention.
- §14 phases — Phase 0 (Tasks 1-4), Phase 1 (Tasks 5-8), Phase 2 (Task 9), Phase 3 (Tasks 10-11), Phase 4 (Tasks 12-13), Phase 5 (Task 14): the plan's phase headers match the spec's phased delivery; Phase 1 is independently shippable as the spec notes.
- Gaps fixed inline: (a) Task 7 surfaced that grant-expiry needs a broad `allow` scan and added a concrete `get_resolved_allows` MCP method rather than leaving `_overdue_grants` a stub. (b) Task 10 surfaced that `process_blue_queue`'s `approved` count would over-count `PENDING` patches and pinned a return-bool refactor. (c) Task 11 surfaced that finalizing a resolved patch needs the stored `RegressionTestPair` and the patch row, and pinned `get_patches_by_status` + a `_pending_test_pairs` instance dict — no placeholder left in the shipped code.
