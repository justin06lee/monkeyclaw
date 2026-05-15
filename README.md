# MonkeyClaw 🐒🦞

**Autonomous red-team / blue-team security agent for NVIDIA NemoClaw.**

MonkeyClaw is an OpenClaw agent that continuously probes NemoClaw's security
controls — sandbox isolation, privacy routing, permission enforcement, and
skill-pipeline integrity. It generates attack ideas using NVIDIA Nemotron,
executes them against live NemoClaw sandboxes, judges the results with tiered
programmatic + semantic analysis, and produces reproducible vulnerability
reports.

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

# live demo dashboard — http://127.0.0.1:8787
uv run monkeyclaw dashboard
```

Optional live Telegram feed of confirmed vulns + cycle summaries:

```bash
export MC_NOTIFICATIONS__TELEGRAM_BOT_TOKEN=<token>
export MC_NOTIFICATIONS__TELEGRAM_CHAT_ID=<chat id>
```

## Architecture

MonkeyClaw runs a continuous **red → judge → blue** loop over a registry of
NemoClaw attack-surface *zones* (sandbox filesystem/network/process, privacy
routing, permission model, skill pipeline, prompt injection, memory).

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
patch generator → test generator → patch verifier → regression runner.

**Infrastructure** — `infra/`

MCP server + SQLite knowledge base, the snapshot-based NemoClaw victim
provisioner, the serial lane scheduler, the monitoring harness (sandbox fs-diff
via the gateway), Telegram/webhook notifications, and the live web dashboard.

**Persistent memory** — a SQLite knowledge base holds every zone's coverage
score, the full findings history, and a growing regression suite. Ideation
Mode C queries past findings, so each cycle is informed by everything tried
before.

The full design lives in `.agents/` (workload split, interface contracts,
component specs).

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
