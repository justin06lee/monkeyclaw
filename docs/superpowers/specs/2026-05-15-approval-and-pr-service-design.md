# Approval & PR Service — Design Spec

Date: 2026-05-15
Status: Draft for review
Authors: MonkeyClaw team

## 1. Motivation

MonkeyClaw's blue team today ends a successful patch with `_on_patch_approved`
in `blue_team/pipeline.py`: it commits the positive regression test, resets the
zone's coverage to 0.3, and sends an alert. "Approved" there means *"passed the
six verifier gates"* — a machine verdict, with no human in the loop and no
record of who, if anyone, decided to trust the patch.

Both source documents flag this as premature for high-risk patches:

- The architecture report (`docs/monkeyclaw_full_architecture_report.md`) lists
  under Key Gaps and Risks: *"Auto-patching without human review would be
  premature for high/critical vulnerabilities,"* and under the Phase 5 blue-team
  spec: *"Add optional human approval. Add PR generation later."*
- The General Analysis whitepaper
  (`Securing_Coding_Agents_General_Analysis_1.0.pdf`) treats approvals as a
  first-class control surface. Its `PermissionRequest` concept gates a
  privileged action behind an allow / deny / ask decision, and its
  exception-record concept captures *who* granted an exception, *why*, and for
  *how long* — a bounded, audited deviation from the default-deny posture
  rather than a silent one.

A patch is itself a privileged action: it modifies the NemoClaw control plane.
Applying a high or critical patch with no approval record is exactly the
"silent privileged action" the whitepaper argues against. This spec adds the
missing gate.

The verifier proves a patch is *correct*. The approval service decides whether
a *correct* patch may be *applied*, by *whom*, and produces the audit trail.
Auto-PR generation is the optional last step: once a patch is approved, draft
the pull request so a human reviews a real diff in a real code-review tool
instead of a database row.

## 2. The approval gate model

Every verified patch carries a severity (`critical` / `high` / `medium` /
`low`, already on `PatchCandidate` via the originating finding). The approval
service maps severity to a *gate posture*:

```
severity     gate posture        default disposition
low          auto-allow          ALLOW immediately, audited
medium       auto-allow*         ALLOW immediately, audited  (* config-tunable
                                  to require-approval)
high         require-approval    ASK — held pending a human allow/deny
critical     require-approval    ASK — held pending a human allow/deny
```

This mirrors the whitepaper's `PermissionRequest`: low-risk actions resolve
automatically, high-risk actions raise an explicit request a human must resolve.
An auto-allowed patch is *not* unrecorded — it still produces an
`ApprovalEvent` with `decision=allow`, `approver=system`, and a reason. The
difference between auto-allow and require-approval is whether resolution is
synchronous-by-policy or held for a human; both leave an audit trail.

An approval, once granted, is an **exception record** in the whitepaper's
sense: a bounded, audited deviation. It names the approver and the reason, and
it may carry an expiry — past which the approval lapses and the patch must be
re-approved before application. This stops a stale "approved" verdict from
authorizing an application weeks later against a drifted codebase.

## 3. Scope

In scope:

- An `infra/approval_service.py` module — the severity-gated approval gate,
  peer to `infra/notifications.py`.
- A severity → gate-posture policy, config-driven (`MonkeyClawConfig`).
- An `ApprovalEvent` audit trail — allow / deny / ask, with approver, reason,
  timestamps, and optional expiry — persisted in a new `approval_events` table.
- The pending-request lifecycle: `ASK` → human resolves → `ALLOW` / `DENY`,
  including expiry of unresolved requests and of granted approvals.
- Notification routing through `infra/notifications.py`: an approval *request*
  is delivered to the configured channels; an approval *resolution* is logged.
- A resolution surface: a CLI subcommand to list pending requests and resolve
  them (`monkeyclaw approvals`), since MonkeyClaw has no interactive web auth.
- Optional auto-PR generation as a post-approval step: a `pr_generator.py` that,
  for an approved patch, drafts a pull request (branch + diff + body) via the
  `gh` CLI when PR generation is enabled.
- Integration with `blue_team/pipeline.py` so `_on_patch_approved` routes
  through the approval service instead of finalizing unconditionally, and with
  the patch-generalization loop so an `UNCONVERGED` patch is force-routed to
  `require-approval` regardless of severity.

Explicitly out of scope (YAGNI for this spec):

- A web approval UI or OAuth-backed approver identity. Approvers are identified
  by a configured operator id; a real identity provider is a later concern.
- Multi-approver / quorum approval. One approver resolves a request.
- Auto-merging an approved PR. PR generation drafts the PR; a human merges it
  in the code-review tool. The loop ends at "PR opened".
- Applying the patch to a running NemoClaw victim. That is the real-provisioner
  track. The approval service gates *authorization*; it does not perform the
  build-and-apply.
- SIEM export of approval events (the architecture report's production item).
  Events are persisted locally and queryable; export is a later spec.

## 4. Non-negotiable design constraints

1. **The approval service authorizes; it does not verify and does not patch.**
   It runs strictly *after* the six-gate `PatchVerifier` has approved a patch
   (and after the generalization loop, where that loop is wired). It owns the
   severity gate, the audit trail, and notification routing — nothing about
   patch correctness.
2. **No high or critical patch is finalized without an `ApprovalEvent`.** The
   blue pipeline's coverage reset, regression-test commit, and "fixed" status
   transition for a `require-approval` patch happen *only* after a recorded
   `decision=allow`. A `DENY` or an unresolved/expired `ASK` leaves the patch
   in `pending_approval` and does not finalize.
3. **Auto-allow is still audited.** A `low`-severity patch produces a real
   `ApprovalEvent`. "Auto" describes the resolution policy, not the absence of
   a record. The audit trail is complete by construction.
4. **`interfaces/` stays the contract firewall.** New shared types
   (`ApprovalRequest`, `ApprovalEvent`, `ApprovalDecision`, `PullRequestDraft`)
   and the `approval_events` schema delta land in `interfaces/`. `infra/` and
   `blue_team/` import them read-only.
5. **The service degrades safe.** If notification delivery fails, a request is
   still persisted as pending and surfaced by the CLI — an undelivered alert
   never silently drops a high-severity patch into auto-allow. If PR generation
   fails, the approval still stands and the failure is logged; PR generation is
   never on the critical path of authorizing a fix.
6. **Default-deny on ambiguity.** An unknown severity, a missing config, or a
   patch with no resolvable finding is treated as `require-approval`, never
   auto-allowed.

## 5. Architecture

```
   blue_team.pipeline  (verified patch, post-generalization)
            │  PatchCandidate + ReproPackage + GeneralizationResult
            ▼
   ┌──────────────────────── approval_service ───────────────────────────┐
   │                                                                      │
   │   gate_policy ──► (severity → posture)                               │
   │      │                                                               │
   │      ├── auto-allow ──► record ApprovalEvent(allow, approver=system) │
   │      │                                                               │
   │      └── require-approval ──► create ApprovalRequest (pending)        │
   │                  │                                                   │
   │                  ▼                                                   │
   │          notifications.AlertDispatcher  ──► telegram / webhook        │
   │                  │                                                   │
   │                  ▼                                                   │
   │          (human) monkeyclaw approvals resolve ──► ApprovalEvent       │
   │                                                    (allow | deny)     │
   └──────────────────────────┬───────────────────────────────────────────┘
                              │  decision == allow
                              ▼
   ┌──────────────── pr_generator (optional, post-approval) ──────────────┐
   │   PatchCandidate.diff ──► gh branch + commit + pr create ──► PR URL   │
   └──────────────────────────────────────────────────────────────────────┘
                              │
                              ▼
        approval_events table   +   blue_team.pipeline finalize
                                    (commit regression test, reset coverage)
```

## 6. Components

### 6.1 `infra/approval_service.py`

- **Does:** The gate. Given a verified `PatchCandidate` plus its severity and
  the optional `GeneralizationResult`, it (1) consults `gate_policy` for the
  posture, (2) for `auto-allow`, records an `ApprovalEvent(decision=allow,
  approver="system")` and returns an immediate `ALLOW`; (3) for
  `require-approval`, creates a pending `ApprovalRequest`, persists it, routes a
  notification, and returns `PENDING`. It also exposes the resolution path
  (`resolve`) and the expiry sweep (`expire_stale`). The service is stateless
  beyond the database — all pending state lives in `approval_events`.
- **Interface:**
  - `request(patch, severity, generalization=None) -> ApprovalOutcome`
    (`ALLOW` | `DENY` | `PENDING`).
  - `resolve(request_id, decision, approver, reason, expiry=None) -> ApprovalEvent`.
  - `list_pending() -> list[ApprovalRequest]`.
  - `expire_stale(now=None) -> list[ApprovalEvent]` — lapses unresolved
    requests past their `ask_expiry` and granted approvals past their
    `grant_expiry`.
- **Depends on:** `gate_policy`, `infra.notifications.AlertDispatcher`, the MCP
  (new `log_approval_event` / `get_pending_approvals` / `mark_approval_resolved`
  — see §9), `interfaces.types` (`ApprovalRequest`, `ApprovalEvent`).

### 6.2 `infra/approval_policy.py`

- **Does:** The pure severity → posture mapping (`gate_policy`). Reads the
  `approvals` block of `MonkeyClawConfig`: per-severity posture
  (`auto_allow` | `require_approval`), the `ask_expiry_hours` for unresolved
  requests, and the `grant_expiry_hours` for granted approvals. Kept as its own
  module because this is the one piece of policy operators will tune most.
  Applies the §4.6 default-deny rule: any severity not explicitly mapped, or a
  patch flagged `generalization=unconverged`, resolves to `require_approval`.
- **Interface:** `posture_for(severity, generalization=None) -> GatePosture`,
  `ask_expiry()`, `grant_expiry()`.
- **Depends on:** `interfaces.config_schema.MonkeyClawConfig`.

### 6.3 `infra/pr_generator.py`

- **Does:** The optional post-approval step. Given an `allow`-resolved
  `PatchCandidate`, drafts a pull request: creates a branch off the default
  branch, applies `patch.diff`, commits with a message linking the vuln id(s),
  and opens a draft PR via the `gh` CLI. The PR body summarizes the finding,
  the verifier gate results, the generalization-loop outcome, and the
  `ApprovalEvent` (approver, reason). Returns a `PullRequestDraft` with the
  branch name and PR URL. Enabled only when `config.approvals.auto_pr` is set;
  disabled, the service simply records the approval and stops.
- **Interface:** `draft(patch, package, approval_event) -> PullRequestDraft`.
- **Depends on:** the `gh` CLI (via `subprocess`), `interfaces.types`
  (`PullRequestDraft`). Performs *no* git operations beyond a dedicated branch;
  it never commits to or merges the default branch.

### 6.4 `infra/cli.py` — `approvals` subcommand (extension)

- **Does:** The human resolution surface. `monkeyclaw approvals` lists pending
  `ApprovalRequest`s (id, vuln ids, severity, age, ask-expiry).
  `monkeyclaw approvals resolve <request_id> --allow|--deny --reason "<text>"
  [--expiry-hours N]` records the operator's decision through
  `approval_service.resolve`. `--approver` defaults to the configured operator
  id. This is an extension of the existing CLI, not a new module.
- **Depends on:** `infra.approval_service`.

## 7. The approval lifecycle

1. **Entry.** `blue_team/pipeline.py` has a verified `PatchCandidate` (six
   gates passed) and, where the generalization loop is wired, a
   `GeneralizationResult`. Instead of finalizing directly, it calls
   `approval_service.request(patch, severity, generalization)`.
2. **Gate.** `gate_policy.posture_for(severity, generalization)` returns the
   posture. `generalization=unconverged` forces `require_approval` regardless
   of severity (a patch with a known open bypass always needs a human).
3. **Auto-allow path.** Posture `auto_allow`: the service writes
   `ApprovalEvent(decision=allow, approver="system", reason="auto-allow:
   severity=<sev>")` and returns `ALLOW`. The pipeline finalizes immediately
   (existing `_on_patch_approved` side-effects).
4. **Require-approval path.** Posture `require_approval`: the service creates
   an `ApprovalRequest` with status `pending`, an `ask_expiry` timestamp
   (`now + ask_expiry_hours`), and persists it. It routes a notification
   (§8) and returns `PENDING`. The pipeline leaves the patch in
   `pending_approval` — no coverage reset, no regression-test commit yet.
5. **Human resolution.** An operator runs `monkeyclaw approvals` to see the
   request and `monkeyclaw approvals resolve …` to allow or deny it.
   `approval_service.resolve` validates the request is still `pending` (not
   already resolved, not `ask`-expired), writes an
   `ApprovalEvent(decision=allow|deny, approver=<operator>, reason=<text>,
   grant_expiry=<optional>)`, and marks the request resolved.
6. **Post-resolution.**
   - `allow` → the blue pipeline (on its next `process_blue_queue` pass, or via
     a resolution callback) finalizes the patch: commits regression tests,
     resets coverage, sends the `[PATCH APPROVED]` alert. If `auto_pr` is on,
     `pr_generator.draft` runs and the PR URL is attached to the
     `ApprovalEvent`.
   - `deny` → the patch moves to `rejected`; an alert fires; the originating
     `FixTask` is escalated for manual review (the existing `_on_task_exhausted`
     path is reused). Coverage is not reset.
7. **Expiry.** `approval_service.expire_stale` runs on each blue-pipeline pass:
   - A `pending` request past its `ask_expiry` is lapsed —
     `ApprovalEvent(decision=expired)` — and an alert escalates it. The patch
     stays unfinalized.
   - A granted `allow` past its `grant_expiry` (if one was set) lapses; if the
     patch has not yet been applied/PR'd, it must be re-requested. This is the
     whitepaper's bounded-exception rule: an approval is not permanent.

## 8. Notification routing

Approval requests and resolutions route through the existing
`infra/notifications.py` `AlertDispatcher` — the same Telegram + webhook path
the rest of MonkeyClaw uses, plugged in at bootstrap. No new transport is
built.

- **Request raised** (`require-approval`): the service calls
  `dispatcher.send(message, severity)` with a message naming the request id,
  vuln id(s), severity, the verifier summary, the generalization outcome, and
  the exact `monkeyclaw approvals resolve` command to run. Severity is the
  patch's severity, so the dispatcher's `alert_severity_floor` is respected —
  a `high`/`critical` request always clears the floor.
- **Request resolved**: an informational alert records the decision, approver,
  and reason.
- **Request expired**: a `high`-severity alert escalates an unactioned request
  so it is not silently lost.

A delivery failure is non-fatal (constraint 5): `AlertDispatcher.send` already
swallows per-channel errors and logs them; the request remains pending and
visible to `monkeyclaw approvals` regardless of whether the alert was
delivered.

## 9. Data model additions

Lands in `interfaces/schema.sql` via the versioned migration system
(`schema_meta` already exists). One new table — matching the architecture
report's `approval_events` data-plane addition and the whitepaper's "approval
requested / resolved" evidence shape:

- `approval_events` — `event_id` (PK), `request_id` (groups the `ask` and its
  resolution), `patch_id` (FK `patches.patch_id`), `vuln_ids` (JSON list),
  `zone_id`, `severity`, `decision` (`ask` | `allow` | `deny` | `expired`),
  `posture` (`auto_allow` | `require_approval`), `approver` (operator id or
  `system`), `reason`, `ask_expiry` (nullable ISO timestamp), `grant_expiry`
  (nullable ISO timestamp), `generalization_status` (nullable —
  `generalized` | `unconverged`), `pr_url` (nullable), `created_at`.
  Indexes on `(decision, created_at)` and on `patch_id`.

A request is the `ask` row; its resolution is a second row sharing
`request_id`. A `pending` request = a `request_id` with an `ask` row and no
`allow`/`deny`/`expired` row. Auto-allowed patches write a single `allow` row
with `posture=auto_allow` and no preceding `ask`. This keeps the table a pure
append-only audit log — events are never mutated, only appended — which is
exactly the immutable-audit-log property the architecture report calls for.

New MCP methods (added to `interfaces/mcp_tools.py`, the contract):
`log_approval_event(event: ApprovalEventInput) -> str`,
`get_pending_approvals() -> list[ApprovalRequest]`, and
`get_approval_events(patch_id: str) -> list[ApprovalEvent]`. The
service also reuses the existing `send_alert`, `mark_patch_status`, and
`add_regression_test`.

New `interfaces/types.py` dataclasses:

- `ApprovalDecision` — the enum-like `Literal["ask","allow","deny","expired"]`.
- `ApprovalRequest` — `request_id`, `patch_id`, `vuln_ids`, `zone_id`,
  `severity`, `posture`, `ask_expiry`, `generalization_status`, `created_at`,
  `status` (`pending` | `resolved` | `expired`).
- `ApprovalEvent` / `ApprovalEventInput` — the read / write shapes for an
  `approval_events` row.
- `ApprovalOutcome` — what `request()` returns: `decision`
  (`ALLOW`|`DENY`|`PENDING`), `request_id`, `event` (the `ApprovalEvent` for
  immediate auto-allow, else `None`).
- `PullRequestDraft` — `branch`, `pr_url`, `commit_sha`, `created_at`.

`PatchCandidate` and `ReproPackage` already exist and are reused; severity is
read from the patch's originating finding/package.

## 10. Configuration

A new `approvals` block in `MonkeyClawConfig` (`interfaces/config_schema.py`),
with `MC_APPROVALS__*` env overrides like every other config block:

- `posture.critical` / `posture.high` / `posture.medium` / `posture.low` —
  each `auto_allow` | `require_approval`. Defaults: `critical` and `high` →
  `require_approval`; `medium` and `low` → `auto_allow`.
- `ask_expiry_hours` — how long a pending request stays actionable before it
  lapses. Default 72.
- `grant_expiry_hours` — how long a granted approval authorizes application
  before it must be re-requested. Default 0 (no expiry) — set non-zero to
  enforce the bounded-exception rule.
- `auto_pr` — bool, default `false`. When true, an `allow` resolution triggers
  `pr_generator.draft`.
- `operator_id` — the default `approver` recorded when the CLI omits
  `--approver`. Default `"operator"`.
- `pr_base_branch` — the branch PRs target. Default `"master"`.

## 11. Integration points

- **`blue_team/pipeline.py`** — `_on_patch_approved` is the integration seam.
  Today it unconditionally commits the regression test, resets coverage to
  0.3, and alerts. This spec splits it: the verified patch first goes to
  `approval_service.request(...)`.
  - `ALLOW` (auto or already-resolved) → the existing finalize body runs
    unchanged.
  - `PENDING` → the patch is marked `pending_approval` via `mark_patch_status`;
    finalize is *not* run. On a later `process_blue_queue` pass, the pipeline
    calls `approval_service.expire_stale` and checks for newly-resolved
    requests; a now-`allow`ed patch is finalized then.
  - `DENY` → `mark_patch_status(rejected)` and the existing
    `_on_task_exhausted` escalation.
  This is a branch inside one existing method plus an `expire_stale` +
  resolved-request poll at the top of `process_blue_queue`. `process_repro_queue`
  and `run_regression` are untouched.
- **Patch-generalization loop** (`2026-05-15-patch-generalization-loop-design.md`)
  — when that loop is wired, it runs *before* the approval service. Its
  `GeneralizationResult` is passed into `approval_service.request`; an
  `UNCONVERGED` result forces `require_approval` (§7 step 2). The two specs
  compose cleanly: generalize first, then gate.
- **`infra/notifications.py`** — consumed read-only via the already-bootstrapped
  `AlertDispatcher`. No change to the notifications module.
- **`infra/orchestrator.py`** — no change. The approval service runs inside
  `process_blue_queue`, which the orchestrator already calls per cycle. The
  `expire_stale` sweep piggybacks on that same call, so no scheduler is added.
- **`infra/cli.py`** — gains the `approvals` subcommand (§6.4).
- **Dashboard** — one additive view: the approvals panel — pending requests
  with age and expiry, recent resolutions with approver and reason, and the
  auto-allow / require-approval split per severity.

## 12. Error handling

- **Notification delivery fails** — non-fatal (constraint 5). The request is
  persisted as `pending` and surfaced by `monkeyclaw approvals`; the failure is
  logged. A high-severity patch never falls through to auto-allow because an
  alert did not send.
- **`resolve` called on an already-resolved or `ask`-expired request** — the
  service rejects it with a clear error and does not write a second resolution
  event; the audit log stays consistent (one resolution per `request_id`).
- **Unknown / missing severity, or no resolvable finding** — `gate_policy`
  applies default-deny (constraint 6): posture `require_approval`. The patch is
  held, never auto-allowed.
- **`pr_generator` fails** (`gh` not installed, branch exists, `git apply`
  rejects the diff) — non-fatal. The `allow` `ApprovalEvent` already stands and
  the patch is finalized; the PR failure is logged and an alert notes that the
  PR must be opened by hand. PR generation is never on the authorization
  critical path.
- **The MCP `log_approval_event` write fails** — logged as an alert; for an
  auto-allow this is best-effort and the pipeline continues, but for a
  `require_approval` path a failed `ask` write means no request exists, so the
  service raises rather than returning a false `PENDING` — a request that was
  never recorded must not look pending.
- **The approval service itself raises inside `process_blue_queue`** — the
  pipeline wraps the call in `try/except`; on a crash the patch is left in
  `pending_approval` (the safe state — unfinalized, no coverage reset) and the
  exception is logged. A service bug can never auto-finalize a high-severity
  patch.

## 13. Testing strategy

Tests live in `test/` with `test_<area>_*.py` naming —
`test_infra_approval_*.py`, alongside the existing `test_infra_*` suite.

- `test_infra_approval_policy.py` — table-driven over all four severities ×
  both postures from config; assert default-deny on unknown severity and on
  `generalization=unconverged`.
- `test_infra_approval_service.py` —
  - auto-allow records a single `allow` `ApprovalEvent` with
    `approver=system` and returns `ALLOW`;
  - require-approval creates a `pending` `ApprovalRequest`, routes a
    notification (asserted against a stub dispatcher), and returns `PENDING`;
  - `resolve` with `allow` / `deny` writes the resolution event and flips the
    request to `resolved`; a second `resolve` on the same request is rejected;
  - `expire_stale` lapses an `ask` past `ask_expiry` and a grant past
    `grant_expiry`, emitting `expired` events;
  - a delivery failure leaves the request pending (stub dispatcher raising).
- `test_infra_approval_audit.py` — assert `approval_events` is append-only:
  every state change adds a row, no row is mutated, and the full lifecycle of
  one `request_id` reconstructs from its rows.
- `test_infra_pr_generator.py` — with a stubbed `gh`/`subprocess` boundary,
  assert a `PullRequestDraft` is produced for an `allow`ed patch and that a
  `gh` failure is non-fatal (approval still stands).
- `test_blue_pipeline_approval_e2e.py` — drive `process_blue_queue` against the
  mock victim: a `low` patch auto-allows and finalizes in one pass; a `high`
  patch goes `pending`, is resolved via `approval_service.resolve`, and
  finalizes on the next pass with coverage reset only then.
- `test_cli_approvals.py` — `monkeyclaw approvals` lists pending requests and
  `resolve` records the operator decision.
- All tests run in mock mode with zero model credentials and a stub
  `AlertDispatcher` / `subprocess` boundary, consistent with the existing
  infra-test posture.

## 14. Phased delivery

The subsystem delivers in phases, each independently verifiable:

- **Phase 0 — contracts:** new `interfaces/types.py` dataclasses, the
  `approval_events` table migration, the new MCP methods, and the `approvals`
  config block. No behavior yet.
- **Phase 1 — gate & audit:** `approval_policy.py` and `approval_service.py`
  with `request` / `resolve` / `list_pending` / `expire_stale`. Auto-allow and
  require-approval both record events; pending state lives in the DB.
- **Phase 2 — route & resolve:** notification routing through `AlertDispatcher`
  and the `monkeyclaw approvals` CLI subcommand.
- **Phase 3 — wire into blue:** the `_on_patch_approved` split and the
  `expire_stale` + resolved-request poll in `process_blue_queue`, including the
  `UNCONVERGED` → `require_approval` rule.
- **Phase 4 — auto-PR:** `pr_generator.py` and the `auto_pr` config path.
- **Phase 5 — surface it:** the dashboard approvals panel.

Phase 1 alone is shippable and valuable: every patch — including auto-allowed
low-severity ones — gets an audit record, closing the architecture report's
"no approval audit" gap even before the human-resolution UX exists.

## 15. Open questions

1. **Resolution transport.** This spec resolves requests through the CLI
   because MonkeyClaw has no authenticated web surface. A Telegram inline-button
   resolution path (reply to the request alert to allow/deny) is an attractive
   future addition but needs callback handling and approver-identity binding;
   deferred.
2. **`medium`-severity default.** Defaulted to `auto_allow` to keep the human
   in the loop only for genuinely high-risk patches. If `medium` patches prove
   to warrant review, the config flips with no code change — it is one posture
   constant.
3. **`grant_expiry` default.** Shipped at 0 (no expiry) so the bounded-exception
   behavior is opt-in. Whether a non-zero default is the right posture depends
   on how long approved patches sit before they are applied/PR'd — revisit once
   the real-provisioner apply path exists.
4. **Approver identity.** Approvers are a configured operator id today. A real
   identity provider (so the audit trail names a verified human) is a clear
   production need but is tied to the broader auth story and is out of scope
   here.

## 16. Companion documents recommended

- An architecture-report update marking the "approval service for high-risk
  patches" Phase 5 / Key-Gaps item as designed, and folding the approval gate
  into the documented blue-team flow between patch verification and patch
  finalization.
- A short ADR recording the auto-allow-still-audited and bounded-exception
  (expiry) decisions, so the audit-completeness posture is not weakened later.
