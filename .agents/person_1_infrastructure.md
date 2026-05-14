# Person 1 — Infrastructure & Orchestration

**Role:** The foundation everything else plugs into.

---

## Why Person 1 Is the Keystone

Every agent in the system talks to the MCP server. Every agent reads from and writes to the database. The orchestrator controls the cycle loop. Person 1 defines the contracts that the other two build against — if these are wrong, everything is wrong. Publish contracts early, iterate fast.

---

## Phase A — Interface Contracts (Day 1-2, BLOCKING)

This is the most important work in the entire project. Nothing else can start until these are published and signed off by Persons 2 & 3.

### Deliverable 1: Database Schema — All Tables, Finalized

Create the complete SQLite schema file with all tables from the spec:

- `surface_zones` — attack surface map with all columns from spec §4.3 (zone_id, name, description, severity_weight, total_cycles, last_tested_at, vulns_found, vulns_open, vulns_patched, coverage_score, decay_rate, difficulty_estimate, unique_ideas_tried)
- `findings` — every attack outcome with vector column for semantic search (finding_id, cycle_id, idea_id, zone_id, source_mode, idea_summary, idea_embedding, verdict, tier_caught, failure_class, severity, evidence, repro_rate, patch_status, reusability, created_at)
- `cycle_log` — compressed cycle summaries (cycle_id, summary, zones_targeted, ideas_generated, ideas_deduplicated, ideas_executed, vulns_confirmed, vulns_suspicious, total_tokens_used, wall_time_seconds, created_at)
- `repro_packages` — completed reproduction packages (package_id, finding_id, vuln_id, title, severity, repro_rate, minimal_steps, affected_paths, ideas_used, repro_doc_md, cold_verified, ready_for_blue, blue_team_status, created_at)
- `regression_tests` — permanent test registry (test_id, vuln_id, zone_id, test_script, expected_result, functionality_test_script, created_at, deprecated, last_run_at, last_run_result, consecutive_passes)
- `patches` — blue team patch history (patch_id, vuln_ids, zone_id, approach, diff, explanation, status, verification_results, created_at)
- `ideas` — raw idea log for dedup tracking (idea_id, cycle_id, zone_id, source_mode, title, approach, embedding, priority_score, deduplicated, created_at)

Publish as `interfaces/schema.sql`. Persons 2 & 3 review and request changes within 24 hours. After sign-off, the schema is frozen — changes go through a migration process.

### Deliverable 2: MCP Tool Signatures — Every Tool, Typed

Define every MCP tool as a typed interface with full input/output type definitions:

```python
# interfaces/mcp_tools.py

def get_coverage_gaps(top_n: int) -> list[CoverageGap]:
    """Returns top-N zones sorted by priority score (severity × (1-coverage) × (1+vulns_open×0.2))"""

def search_findings(query: str, zone: str | None, top_k: int) -> list[FindingRecord]:
    """Vector search over past findings. Optional zone filter."""

def log_finding(finding: FindingInput) -> str:
    """Writes a judgment result to the findings table. Returns finding_id."""

def get_recent_summaries(n: int) -> list[CycleSummary]:
    """Returns last N cycle summaries ordered by recency."""

def check_duplicate(embedding: list[float], zone: str, threshold: float) -> DupResult:
    """Cosine similarity check against all prior ideas for this zone. Returns max similarity + matching idea_id if above threshold."""

def update_zone_coverage(zone_id: str, delta: float) -> None:
    """Adjusts coverage score for a zone. Positive delta = tested. Negative delta = decay."""

def push_to_repro_queue(finding_id: str, priority: str) -> None:
    """Enqueues a confirmed/suspicious finding for repro processing."""

def get_repro_queue() -> list[FindingRecord]:
    """Pulls next finding from the repro queue. Atomic dequeue — prevents double-processing."""

def push_repro_package(package: ReproPackageInput) -> str:
    """Publishes a completed repro package. Returns package_id."""

def get_blue_team_queue() -> list[ReproPackage]:
    """Pulls repro packages with ready_for_blue=true and blue_team_status=queued."""

def search_codebase(query: str, top_k: int) -> list[CodeChunk]:
    """Vector search over NemoClaw source files. Returns file path, line range, and content."""

def log_cycle_summary(summary: CycleSummaryInput) -> None:
    """Writes a compressed cycle summary."""

def get_regression_suite() -> list[RegressionTest]:
    """Returns all active (non-deprecated) regression tests."""

def add_regression_test(test: RegressionTestInput) -> str:
    """Adds a new test to the permanent suite. Returns test_id."""

def log_idea(idea: IdeaInput) -> str:
    """Logs an idea to the ideas table (for dedup history). Returns idea_id."""

def send_alert(message: str, severity: str) -> None:
    """Sends a Telegram/webhook notification."""
```

Publish as `interfaces/mcp_tools.py`. Include the full type definitions for every input/output object in `interfaces/types.py`.

### Deliverable 3: Mock MCP Server

A lightweight MCP server that implements every tool signature with dummy data. Returns realistic-looking fake responses so Persons 2 & 3 can develop and test their agents without waiting for the real backend. Takes ~2-3 hours to build. This is the single most important enabler for parallel development.

Example mock behavior:
- `get_coverage_gaps(5)` → returns 5 zones with varying coverage scores
- `search_findings("prompt injection", "PROMPT-INJ", 3)` → returns 3 fake finding records
- `check_duplicate(embedding, zone, 0.92)` → always returns `{is_duplicate: false, max_similarity: 0.3}`
- `log_finding(...)` → returns a UUID, prints the finding to stdout

---

## Phase B — Real Infrastructure (Day 2-7, parallel with Persons 2 & 3)

### Deliverable 4: SQLite Database + sqlite-vec Setup

- Initialize the database from the schema
- Set up sqlite-vec extension for vector indexing
- Seed the `surface_zones` table with the 18 attack zones from spec §4.2 (SBX-FS, SBX-NET, SBX-PROC, SBX-IPC, PRV-ROUTE, PRV-LEAK, PERM-MODEL, PERM-RUNTIME, SKILL-INSTALL, SKILL-EXEC, SKILL-SUPPLY, MEM-STATE, MEM-SHARED, INF-ROUTE, INF-LOCAL, AGENT-COMM, PROMPT-INJ, SOCIAL-ENG)
- Write migration tooling for schema changes
- Write backup/restore utilities

### Deliverable 5: Real MCP Server — Full Implementation

Replace mock implementations with real database operations. This is the biggest chunk of work.

Key implementation details:
- **Vector search tools** (`search_findings`, `check_duplicate`, `search_codebase`): Need embedding model integration. Use `nomic-embed-text` locally or `text-embedding-3-small` via API. Embed on write, search on read.
- **Queue tools** (`push_to_repro_queue`, `get_repro_queue`, `get_blue_team_queue`): Need atomic dequeue to prevent double-processing. Use SQLite transactions with `UPDATE ... SET status='processing' WHERE status='queued' RETURNING *`.
- **Coverage tools** (`update_zone_coverage`, `get_coverage_gaps`): Need the decay/increment math from spec §4.4. Coverage increases by `0.05 × (1 - current_score)` on test. Decays by `decay_rate` per inactive cycle. Resets to 0.3 on patch. Resets to 0.0 on NemoClaw version change.

### Deliverable 6: Monitoring Harness

The system that captures observables during execution. This runs inside each lane's sandbox environment. Person 2's execution agent doesn't build this — Person 1 does, and the harness data is automatically available in the lane result object.

Components:
- **Filesystem snapshot + diff:** inotify-based watching or before/after hash comparison. Capture files created, modified, deleted, and accessed outside allowed paths.
- **Network logging:** tcpdump or eBPF-based capture of all outbound requests. Log destination domain, port, payload size, response code.
- **Process monitoring:** seccomp log parsing + /proc scanning. Capture spawned processes, blocked syscall attempts with syscall name and arguments.
- **Memory state serialization:** Dump agent persistent memory before and after the attack interaction. Compute diff.
- **Inference routing log:** Hook into NemoClaw's routing API to capture which inference calls went to local Nemotron vs. cloud, and what content was sent in each direction.

Output: A `LaneResult` object (defined in `interfaces/types.py`) containing all captured data.

### Deliverable 7: Lane Scheduler + Orchestrator

The main loop that drives the entire system:

- Maintains a pool of N available lanes (configurable, default N=4)
- Provisions fresh NemoClaw victim instances per lane (via `provision_victim` from `interfaces/provisioning.py`)
- Dispatches ideas from the priority queue to available lanes (FIFO by priority score)
- Starts the monitoring harness for each lane
- Enforces lane timeouts (default: 10 minutes) and max turn limits (default: 50)
- Force-terminates hung lanes, logs incomplete results with `verdict: timeout`
- Collects lane results and passes them to Person 2's judgment system
- Manages the red/blue cycle cadence: run `red_team_batch_size` cycles (default 50), yield to blue team processing, run regression, repeat
- Handles graceful shutdown and resume (persist queue state to disk)
- Tracks lane utilization metrics

### Deliverable 8: Configuration System + Notifications

- YAML config loader implementing the full config schema from spec §14.1
- Telegram bot integration for real-time alerts
- Generic webhook dispatch for CI/CD integration
- Structured JSON logging for all agent actions and phase transitions
- Log rotation and retention (default: 30 days)

### Deliverable 9: NemoClaw Codebase Indexing

Ingest the NemoClaw source code into the vector DB so `search_codebase` works:

- Walk the NemoClaw source tree
- Chunk files by function/class (use AST parsing for Python, tree-sitter for other languages)
- Embed each chunk with the same embedding model used for findings
- Store with metadata: file path, function name, line range, language
- Build the vector index
- This enables Person 2's Mode B ideation and Person 3's root-cause locator

---

## Phase C — Integration Support (Day 7+)

### Deliverable 10: Integration Testing + Production Hardening

- Help Persons 2 & 3 swap from mock MCP to real MCP
- Run integration smoke tests on Day 7 using sample data before Persons 2 & 3 switch over
- Debug any interface mismatches (type errors, missing fields, unexpected nulls)
- Add error handling and retry logic to MCP tools
- Add graceful degradation (if vector search fails, fall back to keyword search)
- Performance testing under parallel lane load (are there SQLite write contention issues with N lanes?)
- If SQLite contention is a problem under high parallelism, implement WAL mode or migrate to PostgreSQL + pgvector
