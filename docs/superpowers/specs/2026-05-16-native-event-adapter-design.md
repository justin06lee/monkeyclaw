# Native Event Adapter — Design Spec

Date: 2026-05-16
Status: Draft

## 1. Motivation

The purple-team spec (`2026-05-15-purple-team-design.md`) defined a telemetry
adapter contract in `interfaces/control_telemetry.py` with two planned
implementations: a `DerivedEvidenceAdapter` (ships first, infers control
decisions from `monitoring_harness` side-effects) and a `NativeEventAdapter`
(deferred, binds to the runtime's real control/telemetry stream). The derived
adapter is in production. This spec delivers the native adapter.

Research (`openclaw-hooks-purple-team-reference.md`) confirmed OpenClaw exposes
a typed plugin-hook system: 17 lifecycle hooks, 4 of them **decision hooks**
returning `allow`/`block`/`cancel`/`requireApproval`/`override`, all carrying
correlation IDs (`runId`, `toolCallId`, `sessionKey`, `traceId`, `spanId`).
That is a real allow/deny/ask signal — higher fidelity than inferring control
decisions from observed side-effects.

## 2. Scope

In scope:
- `purple_team/native_event_adapter.py` — a `ControlTelemetryAdapter`
  implementation that ingests OpenClaw hook events and produces purple
  `TelemetryEvent` and `ControlDecision` records.
- `purple_team/openclaw_plugin/` — a minimal OpenClaw `purple-team-telemetry`
  plugin (manifest + JS) that registers the hooks and writes each hook payload
  as one JSONL line to a configured sink.
- Config: an adapter selector (`derived` | `native`) and the native event
  source path, wired into the existing purple config block.
- Tests against fixture JSONL of recorded hook events.

Out of scope (YAGNI):
- A live socket/streaming transport — the adapter reads a JSONL file the
  plugin appends to; that is sufficient and matches the repo's evidence model.
- Replacing the derived adapter — both coexist; the derived adapter stays the
  default so mock mode keeps working with zero credentials.
- Schema changes — the adapter writes the existing `telemetry_events` table
  through the existing MCP methods. No migration.

## 3. Design constraints

1. The native adapter satisfies the **same** `ControlTelemetryAdapter` contract
   as the derived adapter. Purple's oracle, coverage model, correlator, and
   report card do not change.
2. The derived adapter stays the default. The native adapter is selected by
   config only when an OpenClaw event source is available. Mock mode and the
   zero-credential test path are unaffected.
3. `interfaces/` stays the contract firewall. Any contract refinement lands in
   `interfaces/control_telemetry.py`.

## 4. Event source

The OpenClaw `purple-team-telemetry` plugin registers all 17 hooks. On each
fire it appends one JSON line to a sink file (default
`~/.openclaw/logs/purple-telemetry.jsonl`):

```json
{"hook": "before_tool_call", "ts": 1747000000123, "payload": { ... }, "decision": {"decision": "allow"}}
```

`decision` is present only for the 4 decision hooks. The Python adapter tails
this file (offset-tracked, resumable) and converts lines to purple records.

## 5. Components

### 5.1 `purple_team/native_event_adapter.py`

- **Does:** Reads OpenClaw hook-event JSONL, maps each line to a purple
  `TelemetryEvent` and/or `ControlDecision` using the mapping in §6, threads
  records by `runId`/`sessionKey`/`toolCallId`, and writes them through the
  same MCP path the derived adapter uses.
- **Interface:** implements `ControlTelemetryAdapter` —
  `events_for_execution(execution) -> list[TelemetryEvent]` and
  `decisions_for_execution(execution) -> list[ControlDecision]`, plus
  `ingest(source_path, since_offset) -> IngestResult` for the tailing loop.
- **Depends on:** `interfaces/control_telemetry.py`, `interfaces/types.py`
  (`TelemetryEvent`, `ControlDecision`), the MCP telemetry write methods.

### 5.2 Hook → record mapping (`_HOOK_MAP`)

A static table in the adapter. Direct hooks map one-to-one; `after_tool_call`
is polymorphic on `toolName`; decision hooks yield a `ControlDecision`.

### 5.3 `purple_team/openclaw_plugin/`

- `openclaw.json` — plugin manifest declaring all 17 hooks.
- `index.js` — `definePlugin` entrypoint: registers each hook, and in every
  handler appends `{hook, ts, payload, decision?}` to the sink file. Decision
  hooks always return `{decision: "allow"}` — the plugin is **observe-only**;
  it records decisions made by other plugins/the runtime, it never enforces.
- `README.md` — install steps (`openclaw plugins install ./purple_team/openclaw_plugin`).

## 6. Mapping

Per the research reference §6:

| OpenClaw hook | Purple TelemetryEvent | ControlDecision |
|---|---|---|
| `session_start` / `session_resume` | `agent.session.start` | — |
| `session_end` | `agent.session.end` | — |
| `before_agent_run` | `agent.turn.start` | yes |
| `llm_input` / `model_call_started` | `agent.llm.request` | — |
| `model_call_ended` / `llm_output` | `agent.llm.response` | — |
| `before_tool_call` | — | yes |
| `after_tool_call` | tool-specific (see below) | — |
| `subagent_spawning` | `agent.subagent.spawn` | yes |
| `subagent_spawned` / `subagent_ended` | `agent.subagent.*` | — |
| `agent_end` | `agent.turn.end` | — |
| `outbound_dispatch` | `agent.message.out` | yes |
| `message_delivery` | `agent.message.out` | — |
| `network.request.blocked` | `agent.network.blocked` | — |
| `network.request.approved/denied` | `agent.network.approved/denied` | — |

`after_tool_call` by `toolName`: `file_read`→`agent.file.read`,
`file_write`→`agent.file.write`, `file_delete`→`agent.file.delete`,
`bash`/`exec`/`shell`→`agent.shell.ended`, `browser_*`→`agent.browser.*`,
`mcp_*`→`agent.mcp.invoked`, else→`agent.tool.ended`.

A `before_tool_call` returning `block` for a shell/MCP tool also emits
`agent.shell.blocked` / `agent.mcp.blocked`. `requireApproval` decisions emit
`agent.approval.requested`.

## 7. Data flow

1. OpenClaw plugin appends hook events to the sink JSONL during a victim run.
2. `NativeEventAdapter.ingest()` tails the sink from the last offset.
3. Each line → mapped `TelemetryEvent` / `ControlDecision`, written via MCP to
   `telemetry_events`.
4. Purple's `detection_oracle` consumes them exactly as it consumes the derived
   adapter's output — no oracle change.

## 8. Config

Purple config block gains:
- `telemetry_adapter: "derived" | "native"` (default `derived`).
- `native_event_source: <path>` (default `~/.openclaw/logs/purple-telemetry.jsonl`).
- `native_offset_store: <path>` — resumable tail offset.

When `native`, purple constructs `NativeEventAdapter`; otherwise
`DerivedEvidenceAdapter`. Selection is the only purple-pipeline change.

## 9. Error handling

- Missing/empty source file → adapter yields no events, logs once, purple
  degrades to `observability=unknown` (already handled by the oracle).
- Malformed JSONL line → skipped, counted in `IngestResult.skipped`, logged;
  never aborts ingest.
- Unknown hook name → skipped with a counted warning (forward-compatible with
  new OpenClaw hooks).

## 10. Testing

- `test/test_purple_native_adapter.py` — fixture JSONL covering every hook;
  assert each maps to the right `TelemetryEvent`/`ControlDecision`; assert the
  4 decision hooks yield decisions; assert `after_tool_call` polymorphism;
  assert malformed-line and unknown-hook handling; assert offset resume.
- An adapter-parity test: `NativeEventAdapter` and `DerivedEvidenceAdapter`
  both satisfy `ControlTelemetryAdapter` (same contract).
- All mock mode, zero credentials.

## 11. Phasing

- Phase 0 — config selector + `ControlTelemetryAdapter` parity check.
- Phase 1 — `NativeEventAdapter` ingest + mapping + tests.
- Phase 2 — the OpenClaw plugin (`openclaw.json`, `index.js`, README).
- Phase 3 — purple-pipeline adapter selection wiring + docs.

## 12. Open questions

- The OpenClaw plugin runs in a NemoClaw sandboxed Node VM; confirm the sink
  path is writable from inside the sandbox at integration time. The Python
  adapter side is unaffected — it only reads the file.
