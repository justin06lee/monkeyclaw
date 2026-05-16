# purple-team-telemetry — OpenClaw plugin

An **observe-only** OpenClaw plugin that records every agent lifecycle hook
to a JSONL sink file. MonkeyClaw's purple-team `NativeEventAdapter`
(`purple_team/native_event_adapter.py`) tails that file and converts each
line into purple `TelemetryEvent` / `ControlDecision` records.

See `docs/superpowers/specs/2026-05-16-native-event-adapter-design.md` §5.3.

## What it does

- Registers all **17** OpenClaw lifecycle hooks (`openclaw.json` → `hooks`).
- On every hook fire, appends one JSON line to the sink:

  ```json
  {"hook": "before_tool_call", "ts": 1747000000123, "payload": { ... }, "decision": {"decision": "allow"}}
  ```

  `decision` is present only for the **4 decision hooks**
  (`before_agent_run`, `before_tool_call`, `subagent_spawning`,
  `outbound_dispatch`).
- It is **observe-only**: decision-hook handlers always return
  `{decision: "allow"}`. The plugin *records* the decisions other plugins
  or the runtime make; it never enforces or blocks anything.

## Install

```sh
openclaw plugins install ./purple_team/openclaw_plugin
```

## Configure

The sink path is configurable; it defaults to
`~/.openclaw/logs/purple-telemetry.jsonl`:

```sh
openclaw config set plugins.purple-team-telemetry.sink ~/.openclaw/logs/purple-telemetry.jsonl
```

Point MonkeyClaw's purple config at the same file:

```yaml
purple:
  telemetry_adapter: native
  native_event_source: ~/.openclaw/logs/purple-telemetry.jsonl
  native_offset_store: ~/.openclaw/logs/purple-telemetry.offset
```

## Notes

- Sink writes are best-effort: a write failure is swallowed so telemetry
  loss can never break the victim agent.
- The plugin runs in a NemoClaw sandboxed Node VM; confirm the sink path is
  writable from inside the sandbox at integration time (spec §12). The
  Python adapter only *reads* the file and is unaffected.
