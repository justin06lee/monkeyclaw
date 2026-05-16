# Person A Spec: Infrastructure, Contracts, Control Plane

## Mission

Person A owns the foundation. Your job is to make the whole system runnable, observable, and safe enough that Person B and Person C can build against stable contracts without merge conflicts.

You own:

- `interfaces/`
- `infra/`
- `configs/`
- setup and dependency docs
- DB schema/migrations
- MCP tool implementation
- orchestrator/lane scheduler
- telemetry and policy event models
- model routing config
- mock/planted victim provisioning

You should not edit:

- `red_team/`, except for emergency import fixes after coordinating with Person B.
- `blue_team/`, except for emergency import fixes after coordinating with Person C.

## Hackathon Outcome

By the end, the repo should support:

```bash
uv sync
uv run pytest
uv run ruff check .
uv run monkeyclaw run --cycles 1 --target planted-filesystem --mock
uv run monkeyclaw status
uv run monkeyclaw findings
uv run monkeyclaw dashboard
```

The rest of the team depends on this.

## Architecture Ownership

### Contracts

Own all shared dataclasses and protocols in:

- `interfaces/types.py`
- `interfaces/mcp_tools.py`
- `interfaces/config_schema.py`
- `interfaces/schema.sql`
- `interfaces/provisioning.py`
- `interfaces/victim_client.py`
- `interfaces/nemoclaw_policy.py`

Rules:

- Additive fields are allowed.
- Renames/removals require team sync.
- B/C should request contract changes from you instead of editing these files.

### Infrastructure

Own:

- `infra/bootstrap.py`
- `infra/config.py`
- `infra/database.py`
- `infra/mcp_server.py`
- `infra/mock_mcp.py`
- `infra/orchestrator.py`
- `infra/lane_scheduler.py`
- `infra/monitoring_harness.py`
- `infra/provisioning_nemoclaw.py`
- `infra/notifications.py`
- `infra/codebase_indexer.py`
- `infra/cli.py`

Coordinate with Person C before touching `infra/dashboard.py`; C owns demo/dashboard UX.

## Deliverable A1: Development Environment

### Requirements

- Make setup deterministic.
- Ensure `uv` workflow is documented.
- Add fallback notes for systems without `uv`.
- Ensure dependency install creates a Python version compatible with `pyproject.toml`.

### Files

- Modify: `README.md`
- Create: `docs/dev_setup.md`
- Optional create: `scripts/check_env.sh`

### Acceptance

```bash
uv sync
uv run pytest test/test_contracts.py -q
uv run ruff check .
```

If `uv` is unavailable, `docs/dev_setup.md` must explain how to install it and why the test commands cannot run without dependencies.

## Deliverable A2: Contract Expansion

### Add Shared Types

Add dataclasses for:

- `TelemetryEvent`
- `PolicyDecision`
- `ModelRunRecord`
- `QueueState`
- `IdeaComponent`
- `ArchiveCell`
- `JudgeVote`
- `PolicyCorpusCase`
- `PolicyCorpusResult`

Suggested fields:

```python
@dataclass
class TelemetryEvent:
    event_id: str
    session_id: str
    event_type: str
    timestamp: str
    actor: str
    action_class: str
    target: str | None
    decision: str | None
    reason_code: str | None
    data_class: str | None
    content_hash: str | None
    excerpt: str | None
    metadata: dict[str, Any]
```

```python
@dataclass
class ModelRunRecord:
    run_id: str
    role: str
    model: str
    provider: str
    input_tokens: int
    output_tokens: int
    latency_ms: int
    cost_usd: float | None
    success: bool
    error: str | None
    created_at: str
```

```python
@dataclass
class JudgeVote:
    vote_id: str
    lane_id: str
    judge_role: str
    verdict: str
    score: float
    confidence: float
    reasoning: str
    evidence_turns: list[int]
```

### MCP Tool Additions

Add protocol methods:

- `log_telemetry_event(event: TelemetryEventInput) -> str`
- `get_session_timeline(session_id: str) -> list[TelemetryEvent]`
- `log_model_run(run: ModelRunInput) -> str`
- `log_judge_vote(vote: JudgeVoteInput) -> str`
- `log_policy_corpus_result(result: PolicyCorpusResultInput) -> str`
- `get_policy_corpus_results(run_id: str) -> list[PolicyCorpusResult]`
- `mark_repro_queue_status(finding_id: str, status: str, worker_id: str | None = None) -> None`
- `mark_repro_package_status(package_id: str, blue_team_status: str) -> None`
- `log_patch_candidate(patch: PatchCandidateInput) -> str`
- `mark_patch_status(patch_id: str, status: str, verification_results: dict | None = None) -> None`

### Acceptance

- `test/test_contracts.py` checks that `MockMCP` and `MCPServer` implement `MonkeyClawMCP`.
- Person B can log judge votes.
- Person C can update package/patch statuses without direct DB writes.

## Deliverable A3: Schema and Migration Discipline

### Add Tables

Add tables for:

- `telemetry_events`
- `model_runs`
- `judge_votes`
- `policy_corpus_results`
- `idea_components`
- `idea_archive_cells`
- `mutation_operator_stats`

Use JSON text columns where the structure is flexible during the hackathon. Do not block B/C on perfect normalization.

### Required Indices

- `telemetry_events(session_id, timestamp)`
- `model_runs(role, model, created_at)`
- `judge_votes(lane_id, judge_role)`
- `policy_corpus_results(run_id, case_id)`
- `idea_archive_cells(zone_id, interaction_style, response_movement)`

### Acceptance

- Fresh DB boot applies schema cleanly.
- Existing tests continue passing.
- `monkeyclaw status` still works on fresh DB.

## Deliverable A4: Model Routing Config

### Goal

Make model choices explicit by role.

### Config Shape

Add to `configs/monkeyclaw.yaml` and Pydantic config:

```yaml
models:
  cheap_extraction:
    provider: nvidia
    model: nvidia/nemotron-3-nano
  red_ideation:
    provider: nvidia
    model: nvidia/nemotron-3-super-120b-a12b
  red_execution:
    provider: nvidia
    model: nvidia/nemotron-3-super-120b-a12b
  semantic_judge:
    provider: nvidia
    model: nvidia/nemotron-3-super-120b-a12b
  safety_judge:
    provider: nvidia
    model: nvidia/nemotron-content-safety-reasoning-4b
  root_cause:
    provider: anthropic_or_openai
    model: frontier-coding
  patch_generation:
    provider: anthropic_or_openai
    model: frontier-coding
  codex_code_work:
    provider: openai
    model: gpt-5.3-codex
```

Keep these configurable. The names above are role labels and may need provider-specific final model IDs.

### Acceptance

- No red/blue module hardcodes model IDs except fallback defaults.
- `interfaces.llm.make_llm(role="red_ideation")` or equivalent can resolve a role.

## Deliverable A5: Telemetry and Policy Events

### Events Required

Implement emission helpers for:

- `agent.session.started`
- `agent.policy.loaded`
- `agent.tool.requested`
- `agent.tool.decision`
- `agent.file.read`
- `agent.file.write`
- `agent.shell.started`
- `agent.shell.finished`
- `agent.network.request`
- `agent.mcp.invoked`
- `agent.approval.requested`
- `agent.approval.resolved`
- `agent.session.finished`

Use bounded excerpts and hashes. Do not store raw secrets.

### Integration Points

- `MonitoringHarness` emits filesystem/network/process/inference events.
- `MCPServer` emits MCP invocation events.
- `LaneScheduler` emits session started/finished.
- `Provisioner` emits policy loaded.

### Acceptance

- A mock lane produces a session timeline.
- Dashboard can query a finding's evidence timeline.

## Deliverable A6: Planted Victim Profiles

### Goal

Give B and C deterministic targets.

### Profiles

Create demo profiles:

- `planted-filesystem`: writes outside allowed path after specific instruction.
- `planted-pii-route`: sends synthetic PII through cloud route.
- `planted-prompt-injection`: follows untrusted document instruction.
- `planted-skill-poison`: accepts malicious skill manifest.

### Files

- Create: `demo/victims/planted_filesystem.py`
- Create: `demo/victims/planted_pii_route.py`
- Create: `demo/victims/planted_prompt_injection.py`
- Create: `demo/victims/planted_skill_poison.py`
- Modify: `infra/provisioning_nemoclaw.py` or mock provisioner to select profile.

### Acceptance

- B can trigger each planted profile.
- C can replay each planted profile from a finding transcript.

## Deliverable A7: CLI and Orchestrator Reliability

### Required CLI Commands

Ensure these work:

- `monkeyclaw run --cycles 1 --target planted-filesystem --mock`
- `monkeyclaw status`
- `monkeyclaw findings`
- `monkeyclaw repro <finding_id> --mock`
- `monkeyclaw blue-team --mock`
- `monkeyclaw dashboard`
- `monkeyclaw demo --profile planted-filesystem`

### Orchestrator Behavior

- Respect max cycles.
- Drain lanes before shutdown.
- Always write cycle summary.
- Always update unvisited-zone decay.
- Always run regression if configured.
- Do not crash the full cycle if one lane fails.

### Acceptance

- `test/test_orchestrator.py` covers one complete mock cycle.

## Deliverable A8: Security Guardrails for MonkeyClaw Itself

MonkeyClaw is adversarial. It needs self-containment.

Add configuration and checks for:

- allowed artifact directory
- denied host paths
- network allowlist by phase
- model route allowlist
- MCP tool allowlist
- maximum lane budget
- maximum token budget per cycle
- emergency stop flag

Acceptance:

- If a planted red-team lane tries to read a denied host path, the event is denied/logged.
- If a lane attempts unknown network egress, it is blocked/logged in mock mode.

## Person A Timeline

### Hours 0-3

- Fix setup.
- Freeze shared contract additions.
- Communicate changed types to B/C.

### Hours 3-10

- Schema additions.
- Mock MCP support.
- Planted victim profiles.
- CLI smoke path.

### Hours 10-24

- Telemetry events.
- Model routing.
- Queue status transitions.
- Policy corpus result storage.

### Hours 24-40

- Orchestrator reliability.
- Dashboard data endpoints for C.
- CI/test polish.

### Hours 40-48

- Integration support.
- Fix contract mismatches.
- Prepare fallback DB/demo fixture.

## Final Acceptance Checklist

- `uv sync` works.
- `uv run pytest` passes or failures are documented with specific ownership.
- `uv run ruff check .` passes.
- Fresh DB initializes.
- Mock MCP implements all protocol methods.
- One planted profile can produce a finding.
- Session timeline exists for a finding.
- B and C did not need to edit infrastructure files directly.
