# Data Integrity & Migrations — Design Spec

Date: 2026-05-15
Status: Draft for review
Authors: MonkeyClaw team

## 1. Motivation

MonkeyClaw is a continuous loop. A finding flows red → repro queue → repro
package → blue queue → patch → regression test, and the same SQLite database
is touched by the orchestrator thread, the lane scheduler's worker threads, and
(through the MCP server) the red and blue pipelines. Two failure modes are
already latent in that arrangement:

1. **Ambiguous queue state.** Each handoff stage has a status column
   (`repro_queue.status`, `repro_packages.blue_team_status`,
   `findings.patch_status`, `patches.status`), but the *legal transitions*
   between values live nowhere — they are implied by scattered `UPDATE`
   statements in `infra/mcp_server.py`, `red_team/routing.py`, and
   `blue_team/pipeline.py`. Nothing prevents a repro package from going
   `verified → queued`, a finding from being dequeued twice, or a crashed
   worker from leaving a row stuck in `processing` forever. The architecture
   report calls this out directly: *"Make queue completion/failure atomic"*
   (Phase 1) and *"Blue-team code needs stronger queue lifecycle"* (Key Gaps).

2. **No release-safe schema evolution.** `interfaces/schema.sql` carries the
   header *"After Day-1 sign-off this file is frozen. Changes go through
   migration scripts in `infra/migrations/` — never edit a column in-place"*,
   but `infra/migrations/` does not exist. `Database._run_migrations` only
   re-runs the idempotent `CREATE TABLE IF NOT EXISTS` script and bumps a
   version counter; it cannot add a column, backfill data, or rename anything.
   Every other spec in this batch (model routing, the real provisioner, purple
   team) adds tables or columns. Without a real migration runner each of those
   either edits the frozen file in place or ships an out-of-band script.

These two concerns are coupled: the state machines need new columns and a new
table (an audit trail of transitions), and that schema delta is exactly the
first customer of the migration runner. They ship together.

## 2. Scope

In scope:

- Explicit finite-state machines for the five lifecycle entities: findings
  (`patch_status`), the repro queue (`repro_queue.status`), repro packages
  (`repro_packages.blue_team_status`), patches (`patches.status`), and
  regression tests (`regression_tests` run state).
- A single transition engine (`infra/state_machine.py`) that every status
  mutation routes through, enforcing legal transitions and writing an audit
  row atomically with the status change.
- A `queue_transitions` audit table recording every transition.
- Atomic, idempotent claim/complete/fail semantics so no item is lost or
  double-processed, including recovery of items stranded in a `processing`
  state by a crashed worker.
- A versioned migration system (`infra/migrations.py` + `infra/migrations/`):
  ordered, idempotent, forward-only SQL/Python migration files, run on
  `Database` open, recorded in the existing `schema_meta` table.
- A documented procedure that retires in-place edits of `schema.sql`.

Explicitly out of scope (YAGNI for this spec):

- Down-migrations / rollback. Forward-only is sufficient for a SQLite app with
  cheap backups (`StorageConfig.backup_dir` already exists); a reverse
  migration is written only if a specific one is ever needed.
- Distributed locking or a move to Postgres. Concurrency is bounded by the
  single guarded `sqlite3` connection in `infra/database.py`; that is the
  isolation boundary and it stays.
- A general workflow engine. The five state machines are small, fixed, and
  declared as data — not a pluggable rules system.
- Schema-version branching logic inside application code. Code always assumes
  the latest schema; migrations are what bring an old DB to it.

## 3. What already exists vs. what is new

Already built — this spec completes, not rebuilds:

- `schema_meta` table with `schema_version` / `embedding_model` /
  `embedding_dim` keys, seeded at `schema_version = 2`.
- `Database._run_migrations` — a *placeholder* that only reconciles the version
  counter after the idempotent schema script runs. It is replaced by the real
  runner.
- All five status columns exist with sensible defaults and `CHECK`-free `TEXT`
  typing: `findings.patch_status` (`open`), `repro_queue.status` (`queued`),
  `repro_packages.blue_team_status` (`queued`), `patches.status` (`proposed`),
  `regression_tests.last_run_result` (nullable).
- `ReproQueueStatus`, `PatchStatus`, `BlueTeamStatus` literal types in
  `interfaces/types.py`.
- Two atomic primitives in `infra/mcp_server.py`: `get_repro_queue` already
  does a `BEGIN IMMEDIATE` claim with `status='processing'`, and
  `push_repro_package` updates `repro_queue.status='completed'` plus
  `findings.patch_status='in_progress'` inside one `db.lock()`.
- `mark_repro_queue_status` / `mark_repro_package_status` MCP methods — but
  they are *unguarded* `UPDATE`s that accept any string and silently no-op on a
  missing row.
- `QueueState` dataclass and the `persist_queue_state` config flag.

New in this spec:

- `infra/state_machine.py` — the transition engine and the five FSM
  declarations.
- `infra/migrations.py` — the migration runner.
- `infra/migrations/` directory with the first two migration files.
- `queue_transitions` table (added *via* the migration system — it is
  migration 0003, dogfooding the runner).
- `interfaces/types.py` additions: a `RegressionTestStatus` literal, an
  `IllegalTransition` exception is defined in `state_machine.py` (not a shared
  type — it is raised and caught within infra), and a `QueueTransition`
  dataclass for the audit row.
- MCP-server rewiring: `push_to_repro_queue`, `get_repro_queue`,
  `push_repro_package`, `mark_repro_queue_status`, `mark_repro_package_status`,
  `log_patch_candidate`, and the patch-status update path all route through the
  transition engine instead of issuing raw `UPDATE`s.

## 4. Design constraints

1. **`interfaces/` stays the contract firewall.** New shared literals
   (`RegressionTestStatus`) and the `QueueTransition` dataclass land in
   `interfaces/types.py`. The schema delta lands in `interfaces/schema.sql`
   *and* as a migration file — see §8. The engine and runner are infra
   implementation and live in `infra/`.
2. **One status mutation path.** After this spec, no code outside
   `infra/state_machine.py` issues a raw `UPDATE ... SET status`. The MCP
   server calls the engine; the engine owns the SQL. This is enforced by a
   grep-based test (§11).
3. **Transition + audit are one atomic unit.** The status `UPDATE` and the
   `queue_transitions` insert happen inside a single `db.lock()` /
   `BEGIN IMMEDIATE` … `COMMIT`. A reader never sees a new status with no audit
   row, or vice versa.
4. **Migrations are forward-only, ordered, idempotent, and recorded.** A
   migration that has run is never re-run; a partially-applied migration is a
   hard error, not a silent skip (SQLite DDL is auto-committed per statement, so
   each migration wraps its work in an explicit transaction where possible).
5. **`schema.sql` remains the bootstrap-from-empty path and the readable
   reference.** A brand-new DB is created by running `schema.sql` once; an
   existing DB is brought current by migrations. The two must agree — a test
   asserts a freshly-bootstrapped DB and a migrated-from-empty DB have
   identical schema (§11).
6. **No behavioural change for callers that already transition correctly.**
   `route_judgment` calling `push_to_repro_queue` and the blue pipeline calling
   `push_repro_package` keep working unchanged; only illegal transitions —
   which today corrupt state silently — now raise.

## 5. Architecture

```
              interfaces/types.py
       (RegressionTestStatus, QueueTransition)
                      │ read-only
                      ▼
   infra/state_machine.py ──────────────► queue_transitions  (audit)
   ┌───────────────────────────────┐            ▲
   │ FSM declarations (5)          │            │ atomic insert
   │  FINDING_FSM  REPRO_QUEUE_FSM │            │ + status UPDATE
   │  REPRO_PKG_FSM  PATCH_FSM     │     ┌───────┴────────┐
   │  REGRESSION_FSM               │     │  db.lock() /   │
   │ TransitionEngine.transition() │────►│  BEGIN IMMEDIATE│
   └───────────────────────────────┘     └────────────────┘
                      ▲
                      │ every status mutation
   infra/mcp_server.py ── push_to_repro_queue, get_repro_queue,
                          push_repro_package, mark_*_status,
                          log_patch_candidate, patch-status update

   infra/database.py  ──open()──►  infra/migrations.py
                                   ┌──────────────────────────┐
                                   │ discover infra/migrations/│
                                   │ filter already-applied    │
                                   │ apply in order, record    │
                                   │ each in schema_meta        │
                                   └──────────────────────────┘
```

## 6. The five state machines

Each FSM is declared as a frozen mapping `{state: frozenset(legal_next)}` plus
a set of terminal states. A transition not in the map raises
`IllegalTransition`.

### 6.1 `repro_queue.status` — REPRO_QUEUE_FSM

```
queued ──claim──► processing ──┬──complete──► completed   (terminal)
   ▲                           ├──fail──────► failed      (terminal)
   └──────requeue──────────────┘
```

| State | Set by | Meaning |
|-------|--------|---------|
| `queued` | `route_judgment` → `push_to_repro_queue` | awaiting the repro pipeline |
| `processing` | `get_repro_queue` atomic claim | one worker owns it |
| `completed` | `push_repro_package` | a repro package was produced |
| `failed` | repro pipeline on a crash, or the stale-claim sweep | needs review |

`requeue` (`processing → queued`) is the recovery edge: a worker that crashed
mid-repro leaves a row in `processing`; the stale-claim sweep (§7.3) moves it
back to `queued`. The current code has *no* such edge, so a crash strands the
finding permanently.

Note: today the blue pipeline's `replay_minimizer` "downgrade to suspicious"
path returns without pushing a package, leaving the queue row in `processing`
forever. Under this FSM the pipeline must explicitly call the `fail` transition
in that branch — closing a real leak.

### 6.2 `repro_packages.blue_team_status` — REPRO_PKG_FSM

```
queued ──triage──► triaged ──patch──► patching ──┬──verify──► verified  (terminal)
                                                  └──exhaust─► stuck    (terminal)
```

`stuck` is a **new** state, currently absent from the schema. The blue
pipeline's `_on_task_exhausted` only sends an alert; the package stays
`queued`, so `get_blue_team_queue` re-serves it every cycle forever. Adding
`stuck` (terminal) ends that loop and makes the dashboard able to show packages
that need manual review. `stuck` is added to the `BlueTeamStatus` literal.

### 6.3 `findings.patch_status` — FINDING_FSM

```
open ──repro_started──► in_progress ──patched──► patched ──verified──► verified
  ▲                                                                      │
  └─────────────────────reopen (on regression failure)───────────────────┘
```

`in_progress` is set today by `push_repro_package`. `patched` / `verified` are
in the `PatchStatus` literal but nothing writes them — the blue pipeline never
closes the loop back onto the finding. This spec wires `_on_patch_approved` to
transition the linked finding(s) to `verified`. The `reopen` edge
(`verified → open`) is driven by the regression runner: a permanent regression
test that newly fails means a previously-fixed vuln is live again.

### 6.4 `patches.status` — PATCH_FSM

```
proposed ──submit──► testing ──┬──approve──► approved   (terminal)
                               └──reject───► rejected   (terminal)
```

Matches the existing `proposed|testing|approved|rejected` values; this spec
only makes the transitions explicit and audited. `patch_verifier` moves a patch
`proposed → testing` before its six gates and `→ approved`/`→ rejected` after.

### 6.5 `regression_tests` run state — REGRESSION_FSM

Regression tests have no single status column today — they carry
`last_run_result` (`pass|fail|error`, nullable), `consecutive_passes`, and
`deprecated`. This spec adds a derived **run state** as a new column
`run_state` with literal `RegressionTestStatus`:

```
untested ──run(pass)──► passing ──run(fail)──► failing ──run(pass)──► passing
    │                       │                     │
    └──run(fail)──► failing  └──quarantine──► quarantined  ◄──flaky detection
                                                            (deprecated stays
                                                             an orthogonal flag)
```

`quarantined` formalises the architecture report's flaky-test handling and the
existing `RegressionRunResult.flaky_tests` list: a test that oscillates is
moved to `quarantined` and excluded from the pass-rate denominator until a
human clears it. `deprecated` remains a separate boolean (a test for a removed
control), orthogonal to run state.

## 7. The transition engine

`infra/state_machine.py` — one file, one responsibility.

### 7.1 Interface

```python
class TransitionEngine:
    def __init__(self, db: Database) -> None: ...

    def transition(
        self,
        *,
        entity: str,          # "repro_queue" | "repro_package" | "finding"
                              #  | "patch" | "regression_test"
        entity_id: str,
        to_state: str,
        actor: str,           # "repro_pipeline" | "blue_pipeline" | "sweep" | ...
        reason: str = "",
        expected_from: str | None = None,  # optimistic-concurrency guard
    ) -> str:                 # returns the new state
        """Atomically: read current state, check the FSM allows
        current→to_state, UPDATE the status column, INSERT a
        queue_transitions row. Raises IllegalTransition or
        StaleTransition (expected_from mismatch)."""

    def claim_next_repro(self, worker_id: str) -> str | None:
        """Atomic queued→processing claim of the highest-priority row.
        Returns the finding_id or None. Replaces the inline BEGIN
        IMMEDIATE block currently in mcp_server.get_repro_queue."""

    def sweep_stale_claims(self, older_than_seconds: int) -> int:
        """Requeue repro_queue rows stuck in 'processing' past the
        timeout. Returns the count requeued."""
```

`entity` maps to `(table, id_column, status_column, FSM)` via a frozen
registry inside the module, so adding a future state machine is one table-row
edit.

### 7.2 Atomicity

`transition` runs entirely inside `with db.lock(): db.execute("BEGIN
IMMEDIATE") … COMMIT`. The sequence is: `SELECT` current status → validate
against the FSM (and `expected_from` if given) → `UPDATE` the status column →
`INSERT` into `queue_transitions` → `COMMIT`. Any failure rolls back; the
caller sees either both writes or neither. This mirrors the pattern
`get_repro_queue` already uses successfully.

`claim_next_repro` is the same `BEGIN IMMEDIATE` block that exists today, moved
into the engine so the claim and its audit row are written together — the
current code claims without auditing.

### 7.3 Stale-claim recovery

A worker that dies mid-repro leaves a `processing` row. `sweep_stale_claims`
selects rows where `status='processing'` and
`dequeued_at < now - older_than_seconds` and transitions each
`processing → queued` (the `requeue` edge) with `actor="sweep"`. The
orchestrator calls it once at the top of each cycle, before
`red.generate_ideas`. The timeout defaults to
`2 × lanes.lane_timeout_seconds` (a repro can replay several lanes), exposed as
`orchestrator.stale_claim_timeout_s`.

### 7.4 Error handling

- `IllegalTransition` — the requested edge is not in the FSM. Raised, not
  swallowed. The MCP server lets it propagate to the caller; the orchestrator's
  existing per-stage `try/except` (it already isolates judge and blue-queue
  failures) logs it and continues the cycle. An illegal transition is a *bug*,
  and surfacing it is the point.
- `StaleTransition` — `expected_from` did not match the row's current state
  (another worker moved it first). Callers that pass `expected_from` treat this
  as "someone else owns it, skip"; callers that do not pass it never see it.
- Missing row — `transition` raises `KeyError`, unlike today's
  `mark_repro_queue_status` which silently no-ops. A status mutation targeting
  a non-existent row is always a bug.
- Migration failure mid-run — see §9.4.

## 8. Data model additions

### 8.1 `queue_transitions` (new table)

```sql
CREATE TABLE IF NOT EXISTS queue_transitions (
    transition_id  TEXT PRIMARY KEY,
    entity         TEXT NOT NULL,   -- repro_queue|repro_package|finding|patch|regression_test
    entity_id      TEXT NOT NULL,
    from_state     TEXT,            -- NULL for the initial insert
    to_state       TEXT NOT NULL,
    actor          TEXT NOT NULL,
    reason         TEXT NOT NULL DEFAULT '',
    created_at     TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_queue_transitions_entity
    ON queue_transitions(entity, entity_id, created_at);
```

This is the evidence trail for "how did this finding get here" and the data
source for a future dashboard queue-timeline view. It is added by **migration
0003**, not by hand-editing `schema.sql` — see §9.

### 8.2 Column additions (via migrations)

- `repro_packages.blue_team_status` — no schema change, but the
  `BlueTeamStatus` literal gains `stuck`.
- `regression_tests.run_state TEXT NOT NULL DEFAULT 'untested'` — added by
  migration 0004, backfilled from `last_run_result`
  (`pass→passing`, `fail|error→failing`, `NULL→untested`).

### 8.3 `interfaces/types.py` additions

```python
RegressionTestStatus = Literal[
    "untested", "passing", "failing", "quarantined",
]

@dataclass
class QueueTransition:
    transition_id: str
    entity: str
    entity_id: str
    from_state: str | None
    to_state: str
    actor: str
    reason: str
    created_at: str
```

`BlueTeamStatus` is extended to
`Literal["queued", "triaged", "patching", "verified", "stuck"]`. Adding a
literal value is non-breaking per the `types.py` header convention.

### 8.4 `schema_meta` migration bookkeeping

The runner records applied migrations as `schema_meta` rows keyed
`migration:<NNNN>` with the value `<applied_at_iso>`. The `schema_version`
value tracks the highest applied migration number. This reuses the existing
table — no new bookkeeping table is needed, satisfying the brief.

## 9. The migration system

`infra/migrations.py` + `infra/migrations/`.

### 9.1 Migration files

Files live in `infra/migrations/` named `NNNN_short_description.sql` or
`NNNN_short_description.py`, where `NNNN` is a zero-padded ordinal:

- `.sql` files contain one or more statements; the runner wraps them in a
  transaction and `executescript`s them.
- `.py` files export `def migrate(conn: sqlite3.Connection) -> None:` for
  migrations that need a data backfill (e.g. 0004's `last_run_result →
  run_state` mapping) or conditional logic.

Every migration must be **idempotent on its own statements** where SQLite
allows it (`CREATE TABLE IF NOT EXISTS`, `CREATE INDEX IF NOT EXISTS`); for
`ALTER TABLE ADD COLUMN`, which is not idempotent, the runner guarantees
once-only execution via the applied-set check, and the `.py` form may probe
`PRAGMA table_info` before adding.

### 9.2 Initial migration set

- `0001_baseline.sql` — the no-op baseline. Records that a DB already at
  `schema_version = 2` (every existing DB and every fresh `schema.sql`
  bootstrap) is consistent with migration 0001 having run. This lets old DBs
  and new DBs converge on the same migration ledger.
- `0002_state_machine_indexes.sql` — adds covering indexes the FSM queries
  need (`idx_repro_queue_status` already exists; this adds an index on
  `patches.status` if absent and on `findings.patch_status` — both already
  present, so 0002 is effectively a verified no-op kept for ordinal
  continuity / documentation).
- `0003_queue_transitions.sql` — creates the `queue_transitions` table and its
  index (§8.1).
- `0004_regression_run_state.py` — `ALTER TABLE regression_tests ADD COLUMN
  run_state`, then backfills from `last_run_result`.

### 9.3 Runner interface

```python
def discover(migrations_dir: Path) -> list[Migration]: ...
    # sorted by ordinal; rejects duplicate or non-sequential ordinals

def applied_set(conn: sqlite3.Connection) -> set[int]: ...
    # reads schema_meta rows keyed 'migration:NNNN'

def run_pending(conn: sqlite3.Connection,
                migrations_dir: Path = MIGRATIONS_DIR) -> list[int]: ...
    # applies every discovered migration whose ordinal is not in
    # applied_set, in order; records each; returns the list applied.
```

`Database._open` calls `run_pending(conn)` in place of the current
placeholder `_run_migrations`. The call still happens only when
`read_only is False`. The idempotent `schema.sql` `executescript` continues to
run *first* (it bootstraps an empty DB); `run_pending` then applies any
migration past the baseline. Because `schema.sql` and the migration set are
kept in sync (§9.5), running both on a fresh DB is harmless — every migration's
DDL is `IF NOT EXISTS` or guarded.

### 9.4 Migration failure handling

- A `.sql` migration is wrapped in `BEGIN`/`COMMIT`; on any statement error the
  transaction rolls back and `run_pending` raises `MigrationError` — the
  `Database` constructor fails fast rather than opening a half-migrated DB.
  (DDL is auto-committed per statement in SQLite, so a multi-statement DDL
  migration that fails halfway may leave partial state; such migrations are
  written so each statement is independently idempotent, and the failed
  migration is *not* recorded as applied, so a fixed re-run is safe.)
- A `.py` migration's `migrate()` raising propagates the same way.
- The runner never records a migration as applied unless its body completed
  without error.
- Operators recover by restoring from `StorageConfig.backup_dir` (backups run
  every 30 min) or by fixing the migration and re-running — the unrecorded
  migration re-applies cleanly.

### 9.5 Retiring in-place `schema.sql` edits

The new procedure, documented in the `schema.sql` header (replacing the current
stale note that points at a non-existent directory):

1. To add a table/column: write a new `NNNN_*.sql`/`.py` migration.
2. *Also* update `schema.sql` to reflect the post-migration state, so a
   fresh-from-empty bootstrap and a fully-migrated DB are identical.
3. Bump the `schema_version` seed in `schema.sql` to `NNNN`.
4. A test (§11) asserts (1)+(2) stay in sync — it builds one DB from
   `schema.sql` and one from `0001` + all migrations applied to an empty DB and
   diffs `sqlite_master`.

This keeps `schema.sql` as the readable canonical reference *and* makes
migrations the only mechanism that touches a released DB.

## 10. Data flow

### 10.1 Per-process startup

```
Database(db_path) opened
  → executescript(schema.sql)            # bootstrap / idempotent
  → migrations.run_pending(conn)         # apply 0003, 0004, … as needed
  → schema_meta records each applied migration
```

### 10.2 Per-cycle, in the orchestrator

```
cycle start
  → TransitionEngine.sweep_stale_claims(stale_claim_timeout_s)
        # processing→queued for crashed-worker rows
  → red.generate_ideas / lanes / judge
  → route_judgment → push_to_repro_queue
        # engine: (no row)→queued, audited
  → blue.process_repro_queue
        → claim_next_repro            # queued→processing, audited
        → push_repro_package          # repro_queue queued→completed,
                                      #  finding open→in_progress, audited
        → on downgrade: transition repro_queue processing→failed
  → blue.process_blue_queue
        → triage      # repro_package queued→triaged
        → patch       # repro_package triaged→patching;
                      #  patch proposed→testing→approved|rejected
        → on approve  # repro_package patching→verified;
                      #  finding in_progress→verified
        → on exhaust  # repro_package patching→stuck
  → run_regression
        → per test: REGRESSION_FSM run on pass/fail;
          flaky → quarantined; newly-failing fixed vuln → finding verified→open
```

Every arrow above is one `TransitionEngine.transition` (or `claim_next_repro`)
call, each atomic with its audit row.

## 11. Testing strategy

Tests live in `test/`, `test_<area>_*.py`.

- `test_state_machine_transitions.py` — table-driven over all five FSMs:
  every legal edge succeeds and writes one `queue_transitions` row; a
  representative illegal edge per FSM raises `IllegalTransition`; transition +
  audit are confirmed atomic (a forced failure mid-transition leaves neither
  write).
- `test_state_machine_claim.py` — `claim_next_repro` returns the
  highest-priority `queued` row and moves it to `processing`; a second
  concurrent claim never returns the same row (two threads, one DB); a row in
  `processing` is invisible to claims.
- `test_state_machine_sweep.py` — a row stranded in `processing` past the
  timeout is requeued; a fresh `processing` row is left alone.
- `test_migrations_runner.py` — `run_pending` on an empty DB applies the full
  set; a second `run_pending` is a no-op (idempotent); a deliberately failing
  fixture migration raises `MigrationError` and is *not* recorded.
- `test_migrations_schema_parity.py` — the §9.5 invariant: a DB built from
  `schema.sql` and a DB built by applying every migration to an empty DB have
  identical `sqlite_master` (tables, indexes, columns).
- `test_state_machine_no_raw_updates.py` — greps `infra/`, `red_team/`,
  `blue_team/` for `UPDATE`…`SET`…`status`/`patch_status`/`blue_team_status`
  outside `state_machine.py`; asserts none remain (enforces constraint 2).
- Existing suites (`test_blue_pipeline_e2e.py`, `test_red_routing.py`,
  `test_mcp_real.py`, `test_orchestrator.py`) must still pass unchanged — the
  happy-path transitions are unchanged behaviour.
- All tests run in mock mode, zero model credentials.

## 12. Phased delivery

- **Phase 0 — migration runner.** `infra/migrations.py`, `infra/migrations/`
  with `0001`–`0002`, wire `Database._open` to `run_pending`, schema-parity
  test. No behaviour change; the runner has no work to do yet.
- **Phase 1 — schema delta via migration.** `0003_queue_transitions.sql`,
  `0004_regression_run_state.py`, the `interfaces/types.py` literal/dataclass
  additions, `schema.sql` brought in sync. Proves the runner end-to-end on a
  real delta.
- **Phase 2 — the transition engine.** `infra/state_machine.py` with all five
  FSM declarations, `transition`, `claim_next_repro`, `sweep_stale_claims`, and
  the engine's own tests. Not yet wired into the MCP server.
- **Phase 3 — rewire the MCP server.** Route `push_to_repro_queue`,
  `get_repro_queue`, `push_repro_package`, `mark_repro_queue_status`,
  `mark_repro_package_status`, `log_patch_candidate`, and the patch-status
  update through the engine. Run the no-raw-updates test.
- **Phase 4 — close the lifecycle loops.** Wire `_on_patch_approved` to
  transition findings/packages to `verified`, `_on_task_exhausted` to `stuck`,
  the repro-downgrade branch to `failed`, the regression runner to the
  REGRESSION_FSM and the `verified → open` reopen edge. Orchestrator calls
  `sweep_stale_claims` per cycle.

Each phase is independently verifiable; the suite stays green between phases.

## 13. Open questions

1. **`expected_from` adoption.** The engine supports optimistic-concurrency
   via `expected_from`, but with the single guarded SQLite connection the only
   real contender is the stale-claim sweep racing a late worker. Phase 2 ships
   the parameter; whether the blue pipeline passes it is decided in Phase 4
   against observed behaviour.
2. **Audit retention.** `queue_transitions` grows unbounded. A retention job
   (prune transitions for terminal entities older than N days) is deferred —
   the table is small relative to `findings`/`repro_packages` and is useful for
   the dashboard timeline. Revisit if it becomes a size concern.
3. **`schema_version` semantics.** This spec makes `schema_version` track the
   highest applied migration ordinal. Existing code reads it only in the
   now-replaced `_run_migrations`; no consumer depends on the old `2`. Confirmed
   safe to repurpose.
