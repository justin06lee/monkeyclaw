# Person A — Infrastructure, Contracts, Control Plane: Design

**Date:** 2026-05-15
**Branch:** `person-a-infrastructure`
**Source spec:** `docs/spec_person_a_infrastructure_control_plane.md`
**Reference:** *How to Secure Coding Agents — A Comprehensive Guide* (General Analysis 1.0)

## 1. Mission & Scope

Person A owns the foundation of MonkeyClaw: the contracts, infrastructure, and
control plane that let Person B (`red_team/`) and Person C (`blue_team/`) build
against stable interfaces without merge conflicts. This design covers all eight
deliverables A1–A8.

Person A files only: `interfaces/`, `infra/` (except `dashboard.py`, which is
coordinated with C), `configs/`, `demo/`, `docs/`, `scripts/`, `test/` for
infra/contracts. `red_team/` and `blue_team/` are not edited except emergency
import fixes.

## 2. Baseline (measured 2026-05-15)

`uv sync` succeeds. `uv run pytest` → **127 passed, 1 failed, 9 errors**.
All 10 failures share one root cause:

```
AttributeError: 'sqlite3.Connection' object has no attribute 'enable_load_extension'
  infra/database.py:108
```

The venv's CPython was compiled without loadable-SQLite-extension support, so
`sqlite-vec` cannot load. `uv run ruff check .` → **156 errors** (134
auto-fixable). Both are A1 scope.

`uv`, `nemoclaw` CLI, and `argyph` on `PATH` were absent at session start.
`uv` is now installed (0.11.14). The `argyph` release binary exists at
`/Volumes/Neural/Argyph/target/release/argyph`. The `claude` CLI is present.
Docker is installed but its daemon is off. NemoClaw is not installed anywhere;
real provisioning is therefore code-complete + mock-tested only this session.

## 3. Argyph Integration Decision

Argyph (github.com/ezzy1630/Argyph) is a local-first, read-only code-context
MCP server: tree-sitter symbol graph, hybrid BM25+vector search, repo packing.
It is a strict superset of monkeyclaw's `infra/codebase_indexer.py` +
`search_codebase` MCP tool. The PDF's threat model treats a well-built
read-only MCP server as the safe baseline; Argyph is exactly that.

Two integrations, both **config-gated and optional** — the `--mock` path never
depends on Argyph:

1. **Code-context backend.** New `infra/argyph_index.py` adapter shells to the
   `argyph` binary (`argyph index <path>`, `argyph search <query>`) to index
   the NemoClaw victim source. `search_codebase` (in `MCPServer`) prefers
   Argyph when `code_context.backend == "argyph"`; the Python tree-sitter
   indexer (`codebase_indexer.py`) remains the default and the fallback when
   the binary is missing. The adapter maps Argyph results to `CodeChunk`.
2. **A8 canonical allowed MCP server.** Argyph is the reference entry in the
   A8 MCP-tool allowlist — a genuinely read-only, path-validated server, ideal
   for demonstrating allowlist governance.

The Argyph repository itself is not modified; monkeyclaw consumes the binary.

## 4. Deliverable Designs

### A1 — Development Environment

- **Python fix.** Pin a uv-managed CPython via `uv python pin` /
  `requires-python`; python-build-standalone enables loadable extensions.
  Verify `sqlite3.Connection.enable_load_extension` exists and `sqlite-vec`
  loads.
- **Lint.** Apply `ruff --fix`; add a `[tool.ruff]` section to `pyproject.toml`
  (line length, target version, import sorting) so `ruff check .` is clean and
  stays clean. Person A files only — do not reformat `red_team/` or
  `blue_team/` if it would conflict with B/C; if their files carry lint debt,
  document ownership rather than editing.
- **Files.** Modify `README.md`; create `docs/dev_setup.md` (uv workflow +
  no-uv fallback explaining install and why test commands need dependencies);
  create `scripts/check_env.sh` (checks Python version range, `enable_load_extension`,
  sqlite-vec load, optional `argyph`/`nemoclaw`/`docker` presence).
- **Acceptance.** `uv sync`; `uv run pytest test/test_contracts.py -q`;
  `uv run ruff check .` all succeed.

### A2 — Contract Expansion

Additive only — renames/removals are out of scope. Add to `interfaces/types.py`
the 9 dataclasses plus write-side `*Input` variants where the spec's protocol
methods take an `*Input`:

- `TelemetryEvent` / `TelemetryEventInput`
- `PolicyDecision`
- `ModelRunRecord` / `ModelRunInput`
- `QueueState`
- `IdeaComponent`
- `ArchiveCell`
- `JudgeVote` / `JudgeVoteInput`
- `PolicyCorpusCase`
- `PolicyCorpusResult` / `PolicyCorpusResultInput`
- `PatchCandidateInput` (write-side for `log_patch_candidate`)

Field shapes follow the spec's suggested fields; `metadata`/flexible fields are
`dict[str, Any]`. New string-literal types as needed (e.g. `ReproQueueStatus`).

Add to `interfaces/mcp_tools.py` `MonkeyClawMCP` protocol the 10 methods:
`log_telemetry_event`, `get_session_timeline`, `log_model_run`,
`log_judge_vote`, `log_policy_corpus_result`, `get_policy_corpus_results`,
`mark_repro_queue_status`, `mark_repro_package_status`, `log_patch_candidate`,
`mark_patch_status`.

Implement all 10 in **both** `infra/mock_mcp.py` (`MockMCP`) and
`infra/mcp_server.py` (`MCPServer`).

**Acceptance.** `test/test_contracts.py` asserts both classes satisfy the
protocol; B can log judge votes; C can update package/patch status without
direct DB writes.

### A3 — Schema & Migration Discipline

Add 7 tables to `interfaces/schema.sql`, all `CREATE TABLE IF NOT EXISTS`:
`telemetry_events`, `model_runs`, `judge_votes`, `policy_corpus_results`,
`idea_components`, `idea_archive_cells`, `mutation_operator_stats`. JSON-text
columns for flexible structures (per spec — no perfect normalization).

Required indices: `telemetry_events(session_id, timestamp)`,
`model_runs(role, model, created_at)`, `judge_votes(lane_id, judge_role)`,
`policy_corpus_results(run_id, case_id)`,
`idea_archive_cells(zone_id, interaction_style, response_movement)`.

**Migration runner.** `infra/database.py` gains a small version-gated step:
read `schema_meta.schema_version`, apply `schema.sql` idempotently, bump
1 → 2. Existing rows/tables untouched. Fresh DB applies cleanly;
`monkeyclaw status` works on a fresh DB; the 127 existing tests stay green.

### A4 — Model Routing Config

Add a `models:` block to `configs/monkeyclaw.yaml` with the 9 role labels
(`cheap_extraction`, `red_ideation`, `red_execution`, `semantic_judge`,
`safety_judge`, `root_cause`, `patch_generation`, `codex_code_work`) — each
`{provider, model}`. Add `ModelRouteConfig` + `ModelsConfig` to
`interfaces/config_schema.py`, nested into `MonkeyClawConfig`.

`interfaces/llm.py` gains `make_llm(role: str, cfg=None) -> LLM` resolving
role → provider/model, with fallback defaults so a missing role still works.
No red/blue module hardcodes model IDs except fallback defaults.

### A5 — Telemetry & Policy Events

New `infra/telemetry.py`: `TelemetryEmitter` — a thin wrapper around the
`log_telemetry_event` MCP method with one helper per event type. Excerpts are
length-bounded; full content is SHA-256 hashed; raw secrets are never stored
(`data_class` + `content_hash` + bounded `excerpt`, per PDF Appendix D field
guidance).

13 events: `agent.session.started`, `agent.policy.loaded`,
`agent.tool.requested`, `agent.tool.decision`, `agent.file.read`,
`agent.file.write`, `agent.shell.started`, `agent.shell.finished`,
`agent.network.request`, `agent.mcp.invoked`, `agent.approval.requested`,
`agent.approval.resolved`, `agent.session.finished`.

Integration points: `MonitoringHarness` (filesystem/network/process/inference),
`MCPServer` (`agent.mcp.invoked`), `LaneScheduler` (session started/finished),
provisioner (`agent.policy.loaded`).

**Acceptance.** A mock lane produces a queryable session timeline via
`get_session_timeline`.

### A6 — Planted Victim Profiles

New `demo/victims/` package, 4 profiles implementing `MockVictimProtocol`
(`chat() -> (str, TurnSideEffects)`):

- `planted_filesystem.py` — writes outside allowed path after a specific
  instruction.
- `planted_pii_route.py` — routes synthetic PII through a cloud route.
- `planted_prompt_injection.py` — follows an untrusted-document instruction.
- `planted_skill_poison.py` — accepts a malicious skill manifest.

Each emits deterministic side effects so B can trigger and C can replay it.
Mock provisioner (`infra/provisioning_nemoclaw.py` `MockProvisioner`, or a
dedicated mock) gains profile selection keyed by name.

### A7 — CLI & Orchestrator Reliability

Verify/repair all 7 CLI commands: `run --cycles 1 --target planted-filesystem --mock`,
`status`, `findings`, `repro <id> --mock`, `blue-team --mock`, `dashboard`,
`demo --profile planted-filesystem` (new).

Orchestrator (`infra/orchestrator.py`) hardening: respect max cycles; drain
lanes before shutdown; always write a cycle summary; always update
unvisited-zone decay; always run regression if configured; never crash the
whole cycle when one lane fails (catch, log, telemetry, continue).

**Acceptance.** `test/test_orchestrator.py` covers one complete mock cycle.

### A8 — Security Guardrails

New `infra/guardrails.py`: `PolicyEnforcer` reading a new `guardrails:` config
block — allowed artifact directory, denied host paths, phase-based network
allowlist, model-route allowlist, MCP-tool allowlist (Argyph canonical),
maximum lane budget, maximum token budget per cycle, emergency-stop flag.

Consulted by `MonitoringHarness` (host-path reads, network egress) and
`LaneScheduler` (budgets, emergency stop). Every denial emits an
`agent.tool.decision` telemetry event. Detection logic is informed by the PDF
detection catalog (denied secret read, unexpected egress, control-plane edit).

**Acceptance.** A planted lane reading a denied host path is denied + logged;
an unknown network egress is blocked + logged in mock mode.

## 5. Testing Strategy

TDD per deliverable. Keep all 127 currently-passing tests green. New/updated
tests: `test_contracts.py` (A2 protocol conformance), `test_config.py` (A4
model routing), `test_orchestrator.py` (A7 full mock cycle), and new files
`test_telemetry.py` (A5), `test_guardrails.py` (A8), `test_planted_victims.py`
(A6), `test_provisioning.py` (real provisioner against mocked subprocess +
fake gateway), `test_argyph_index.py` (adapter, skipped if binary absent).

## 6. Real NemoClaw Provisioning

`infra/provisioning_nemoclaw.py` `NemoClawProvisioner` is hardened and
code-complete: timeouts, snapshot-restore/recover error handling, gateway
token fetch. It is unit-tested against a mocked `subprocess` and a fake
gateway. Live end-to-end verification requires the `nemoclaw` CLI + Docker and
is documented in `docs/dev_setup.md` for later.

## 7. Final Acceptance Gate

- `uv sync` works.
- `uv run pytest` passes (or any residual failure is documented with explicit
  B/C ownership).
- `uv run ruff check .` passes.
- Fresh DB initializes; `monkeyclaw status` works on it.
- `MockMCP` and `MCPServer` implement all `MonkeyClawMCP` methods.
- One planted profile produces a finding with a session timeline.
- All 7 CLI commands run.
- B and C did not need to edit infrastructure files.
