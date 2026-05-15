# MonkeyClaw 🐒🦞

**Autonomous red-team / blue-team security agent for NVIDIA NemoClaw.**

MonkeyClaw is an OpenClaw agent that continuously probes NemoClaw's security
controls — sandbox isolation, privacy routing, permission enforcement, and
skill-pipeline integrity. It generates attack ideas using NVIDIA Nemotron,
executes them against live NemoClaw sandboxes, judges the results with tiered
programmatic + semantic analysis, reproduces confirmed findings, and runs a
blue-team loop that triages, patches, tests, and verifies the fix.

## Quick Start

```bash
uv sync

# Nemotron credentials (host run); inside a sandbox use the managed route:
#   export MC_NEMOTRON_BASE_URL=https://inference.local/v1
export NVIDIA_API_KEY=<your nvidia api key>

# run 3 red-team cycles against the live victim sandbox
uv run monkeyclaw run --cycles 3 --target monkey-victim

# inspect results
uv run monkeyclaw status
uv run monkeyclaw findings

# reproduce + minimize a confirmed finding
uv run monkeyclaw repro <finding_id>

# blue team: triage -> patch -> test for queued repros (demo mode)
uv run monkeyclaw blue-team

# live demo dashboard — http://127.0.0.1:8787
uv run monkeyclaw dashboard
```

No live NemoClaw sandbox handy? Add `--mock` to `run` / `repro` to drive the
in-memory mock provisioner and planted-vulnerability victim instead.

Optional live Telegram feed of confirmed vulns + cycle summaries:

```bash
export MC_TELEGRAM_BOT_TOKEN=<token from @BotFather>
export MC_TELEGRAM_CHAT_ID=<your chat id>

# verify delivery before a demo
uv run monkeyclaw test notification
```

## CLI

The `monkeyclaw` command is the single entrypoint for the whole loop.

| Command | Purpose |
|---------|---------|
| `run --cycles N --target <sandbox>` | Run N red-team cycles (`--perpetual` to run forever, `--mock` for no live sandbox) |
| `status` | Coverage map + findings / cycles / regression-test summary |
| `findings` | List all confirmed / suspicious findings, severity-sorted |
| `repro <finding_id>` | Run the repro pipeline on a finding (replay-minimize + document) |
| `blue-team [vuln_id]` | Demo mode: triage → patch → test for queued repros (output only, nothing applied) |
| `probe [-m "<msg>"] [--reset]` | Talk directly to the victim — interactive or one-shot, for ad-hoc probing |
| `test notification` | Self-check: send a test message through the Telegram alert path |
| `dashboard [--port 8787]` | Start the live web dashboard |

## Architecture

MonkeyClaw runs a continuous **red → judge → repro → blue** loop over a registry
of **18 NemoClaw attack-surface zones** (sandbox filesystem/network/process/IPC,
privacy routing, permission model & runtime, skill install/exec/supply-chain,
persistent & shared memory, inference routing, agent comms, prompt injection,
social engineering). The orchestrator always steers the next cycle at the
lowest-coverage zone.

**Red team** — `red_team/`

1. **Ideation** — three Nemotron prompt modes (creative, code-grounded,
   history-informed) generate attack ideas for the lowest-coverage zone.
2. **Dedup + priority** — embedding similarity drops repeats; ideas are scored
   by novelty × impact × coverage gap.
3. **Execution** — an attacker agent drives a multi-turn attack against a live
   victim over the OpenClaw gateway WebSocket.
4. **Judgment** — Tier 1 runs six programmatic checks (filesystem, network,
   process, permission, PII routing, policy modification); Tier 2 is a Nemotron
   semantic judge for prompt-injection / social-engineering / memory zones.
5. **Routing** — confirmed/suspicious findings are logged and queued for repro.

**Blue team** — `blue_team/`

Replay-minimizer → root-cause locator → repro writer → cold verifier → triage →
patch generator → test generator → patch verifier → regression runner. Confirmed
findings become minimized, cold-verified vulnerability documents; high-severity
ones get root-cause locations and multiple candidate patches, each validated
through a three-gate check (regression, functionality, full suite).

**Infrastructure** — `infra/`

MCP server + SQLite knowledge base, the snapshot-based NemoClaw victim
provisioner, the serial lane scheduler, the monitoring harness (sandbox fs-diff
via the gateway), Telegram/webhook notifications, and the live web dashboard.

**Interfaces** — `interfaces/`

The merge-conflict firewall: the database schema (`schema.sql`), MCP tool
signatures (`mcp_tools.py`), shared dataclasses (`types.py`), the victim
provisioning API, and the transport-agnostic victim chat client. Everything
else imports from here read-only.

**Persistent memory** — a SQLite knowledge base holds every zone's coverage
score, the full findings history, and a growing regression suite. Ideation
Mode C queries past findings, so each cycle is informed by everything tried
before.

The full design lives in `.agents/` (workload split, interface contracts,
component specs).

## Configuration

Runtime config layers `defaults → configs/monkeyclaw.yaml → MC_CONFIG file →
MC_* env vars`. Nested fields use double-underscore env overrides, e.g.
`MC_LANES__POOL_SIZE=8`. See `configs/monkeyclaw.yaml` for every tunable.

## Tests

```bash
uv run pytest          # 137 tests across red, blue, and infra
uv run ruff check .
```

## Packaged as an OpenClaw skill

`skill/SKILL.md` makes MonkeyClaw installable into any OpenClaw sandbox via
`nemoclaw <sandbox> skill install skill/`. The host agent then drives the
autonomous loop through the `monkeyclaw` CLI.

## Built With

- **OpenClaw** agent framework
- **NVIDIA Nemotron** (`nemotron-3-super-120b-a12b`)
- **NVIDIA NemoClaw** sandbox runtime
- **MCP** (Model Context Protocol) for agent–tool communication

## Team

Justin Lee, Ezzy Rappeport, George Gong

## Hack-a-Claw × NVIDIA @ UCSC — May 2026
