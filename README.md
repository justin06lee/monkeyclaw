# MonkeyClaw

Continuous red-team + repro + blue-team loop targeting NemoClaw / OpenClaw
deployments.

The codebase is split into three vertical slices that develop in parallel
with zero merge conflicts. See `.agents/overview.md` for the full split.

## Layout

```
monkeyclaw/
├── interfaces/          ← Person 1 owns. Read-only for P2 & P3.
│   ├── schema.sql       database schema (frozen after Day-1 signoff)
│   ├── types.py         shared dataclasses
│   ├── mcp_tools.py     MCP tool Protocol — both servers conform
│   ├── provisioning.py  Victim provisioning Protocol
│   └── config_schema.py Pydantic models for runtime config
├── infra/               ← Person 1 ONLY
│   ├── database.py             SQLite + sqlite-vec wrapper, embedding model
│   ├── mock_mcp.py             dummy MCP for Day 2 development
│   ├── mcp_server.py           real MCP backed by the DB
│   ├── monitoring_harness.py   fs/net/proc/mem/inference capture per lane
│   ├── codebase_indexer.py     vector-index the NemoClaw source tree
│   ├── lane_scheduler.py       pool of N concurrent execution lanes
│   ├── orchestrator.py         cycle loop, plug-in red/blue pipelines
│   ├── provisioning_nemoclaw.py  shells to `nemoclaw` CLI; MockProvisioner too
│   ├── notifications.py        Telegram + webhooks
│   ├── config.py               YAML + env override loader
│   └── bootstrap.py            wires it all together
├── red_team/            ← Person 2 ONLY (created when P2 starts)
├── blue_team/           ← Person 3 ONLY (created when P3 starts)
├── configs/             ← YAML defaults
├── test/                ← pytest suite
└── data/                ← SQLite + backups (gitignored)
```

## Quickstart

```bash
# One-time setup
uv sync                                       # installs deps into .venv
uv run python -m infra.codebase_indexer       # index ~/NemoClaw into the vector store

# Run the mock MCP for Day 2 development (Persons 2 & 3 hit this)
uv run python -m infra.mock_mcp --host 127.0.0.1 --port 7321

# Run the real MCP against the SQLite DB
uv run python -m infra.mcp_server --host 127.0.0.1 --port 7322

# Run two stub orchestrator cycles end-to-end with the mock provisioner
uv run python -m infra.orchestrator --use-mock-provisioner --max-cycles 2

# Plug in Persons 2 and 3 (when they're ready)
uv run python -m infra.orchestrator \
    --red red_team.pipeline:Pipeline \
    --blue blue_team.pipeline:Pipeline

# Tests
uv run pytest test/ -q
```

## Configuration

Defaults live in `configs/monkeyclaw.yaml`. Two ways to override:

1. Layer a project-specific YAML: `--config path/to/override.yaml`
2. Environment variables with prefix `MC_` and `__` for nesting:
   - `MC_LANES__POOL_SIZE=8`
   - `MC_IDEATION__DEDUP_THRESHOLD=0.95`
   - `MC_STORAGE__DB_PATH=/var/lib/monkeyclaw.db`

## For Persons 2 and 3

### Calling MCP tools

Both the mock and real MCP servers expose the same surface (`MonkeyClawMCP`
Protocol in `interfaces/mcp_tools.py`). Two transports:

- **In-process:** import `MockMCP` or `MCPServer` and call methods directly.
- **HTTP:** `POST http://host:port/tool/<tool_name>` with a JSON body matching
  the kwarg names of the tool method. Returns the result as JSON.

### Wiring your pipeline into the orchestrator

Your pipeline class must duck-type the appropriate Protocol:

```python
# red_team/pipeline.py
class Pipeline:
    def generate_ideas(self, cycle_id: int, n_lanes: int) -> list[IdeaObject]: ...
    def execute_lane(self, idea, victim, harness, lane_cfg) -> None: ...
    def judge(self, lane_result: LaneResult) -> None: ...

# blue_team/pipeline.py
class Pipeline:
    def process_repro_queue(self) -> int: ...
    def process_blue_queue(self) -> int: ...
    def run_regression(self) -> None: ...
```

The orchestrator instantiates each via `module.path:ClassName` and feeds it
the lane scheduler, MCP server, and provisioner.

### Tier 1 checks (P3 imports from P2)

Person 3 imports `red_team.checks.run_all_tier1_checks` for replay
verification. The function signatures are documented in `.agents/interfaces.md`
Contract 4. Person 2 publishes stub implementations by Day 3.

## Day-by-Day

See `.agents/timeline.md`. Day 1 deliverables (interface contracts + mock MCP)
are complete and shipped — Persons 2 and 3 can begin Day 2 work now.
