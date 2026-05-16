/**
 * purple-team-telemetry — OpenClaw plugin (native-event-adapter spec §5.3).
 *
 * Observe-only. Registers all 17 OpenClaw lifecycle hooks; on each fire it
 * appends one JSON line `{hook, ts, payload, decision?}` to the configured
 * sink file. The 4 decision hooks always return {decision: "allow"} — this
 * plugin RECORDS the decisions other plugins / the runtime make, it never
 * enforces. MonkeyClaw's Python NativeEventAdapter tails the sink.
 */

'use strict';

const fs = require('fs');
const os = require('os');
const path = require('path');

const DEFAULT_SINK = '~/.openclaw/logs/purple-telemetry.jsonl';

// The 17 lifecycle hooks (manifest `hooks`).
const HOOKS = [
  'session_start',
  'session_resume',
  'session_end',
  'before_agent_run',
  'llm_input',
  'model_call_started',
  'model_call_ended',
  'llm_output',
  'before_tool_call',
  'after_tool_call',
  'subagent_spawning',
  'subagent_spawned',
  'subagent_ended',
  'agent_end',
  'outbound_dispatch',
  'message_delivery',
  'network.request',
];

// The 4 decision hooks — handlers return an explicit allow.
const DECISION_HOOKS = new Set([
  'before_agent_run',
  'before_tool_call',
  'subagent_spawning',
  'outbound_dispatch',
]);

function expandHome(p) {
  if (p && p.startsWith('~')) {
    return path.join(os.homedir(), p.slice(1));
  }
  return p;
}

// Append one JSONL line to the sink, creating the directory if needed.
// Best-effort: a write failure must never break the victim agent.
function appendLine(sinkPath, record) {
  try {
    const resolved = expandHome(sinkPath);
    fs.mkdirSync(path.dirname(resolved), { recursive: true });
    fs.appendFileSync(resolved, JSON.stringify(record) + '\n', 'utf8');
  } catch (err) {
    // Observe-only: swallow — telemetry loss must not affect the run.
  }
}

function definePlugin(api) {
  const sink = (api && api.config && api.config.sink) || DEFAULT_SINK;

  for (const hook of HOOKS) {
    api.on(hook, function (payload) {
      const record = {
        hook: hook,
        ts: Date.now(),
        payload: payload || {},
      };
      if (DECISION_HOOKS.has(hook)) {
        // Observe-only: record an allow, never enforce.
        record.decision = { decision: 'allow' };
        appendLine(sink, record);
        return { decision: 'allow' };
      }
      appendLine(sink, record);
      return undefined;
    });
  }

  return {
    name: 'purple-team-telemetry',
    hooks: HOOKS,
  };
}

module.exports = { definePlugin, HOOKS, DECISION_HOOKS, expandHome };
