# Model Ideation Tournament Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Complete the model ideation tournament by adding head-to-head judging of the idea sets different models produce for a zone, a per-zone win-rate accumulated from those head-to-heads plus execution outcomes, and win-rate-driven entrant routing so future ideation favours the model that wins on each zone.

**Architecture:** `red_team/tournament.py` keeps the fan-out runner + config but gains a per-zone counter dimension and persisted-win-rate accessors. A new `red_team/ideation_tournament.py` runs round-robin pairwise comparisons of entrant idea sets and folds the result plus execution outcomes into the §8 win-rate. A new `red_team/entrant_selection.py` routes future ideation by per-zone win-rate with an exploration floor. `red_team/pipeline.py` wires selection → fan-out → head-to-head judging → post-judgment win-rate update; all new shared types, MCP methods, and the schema delta land in `interfaces/`.

**Tech Stack:** Python 3.12, `uv` for env + test running, `pytest`, SQLite via `infra/database.py`, the existing migration runner (`infra/migrations.py` + `infra/migrations/`), `interfaces/types.py` dataclasses, `interfaces/llm.py` (`make_llm`, `LLMClient`), `ruff` for lint. Everything runs in mock mode with zero model credentials — every entrant LLM client and the ideation judge are mocked in tests. The tournament is disabled by default and a disabled tournament is a strict no-op.

---

## File Structure

| File | Create/Modify | Responsibility |
|------|---------------|----------------|
| `interfaces/types.py` | Modify | Add `ModelZoneWinrate`, `TournamentRound`, `PairwiseIdeaSetResult`. |
| `interfaces/schema.sql` | Modify | Add `model_zone_winrate` + `model_tournament_rounds` tables (reference copy, kept in sync with the migration). |
| `interfaces/mcp_tools.py` | Modify | Add `get_model_zone_winrate`, `update_model_zone_winrate`, `log_tournament_round` signatures. |
| `infra/migrations/0005_model_tournament.sql` | Create | Migration adding `model_zone_winrate`, `model_tournament_rounds`; bumps `schema_version` 2→3. |
| `infra/mcp_server.py` | Modify | Implement the three new MCP methods. |
| `infra/mock_mcp.py` | Modify | Mock implementations of the three new MCP methods. |
| `red_team/tournament.py` | Modify | Per-zone counters in `_bump` / `record_outcome` / `leaderboard`; `load_winrates` / `winrate`. |
| `red_team/ideation_tournament.py` | Create | `IdeationTournamentJudge` — `judge_round()` round-robin pairwise; `update_winrate()` §8 fold. |
| `red_team/entrant_selection.py` | Create | `select_entrants()` / `weights()` — per-zone win-rate routing with an exploration floor. |
| `red_team/pipeline.py` | Modify | `generate_ideas()` integration: selection → fan-out → head-to-head → win-rate update. |
| `infra/dashboard.py` | Modify | Additive panel: per-zone model win-rate + recent tournament rounds. |
| `configs/monkeyclaw.yaml` | Modify | `red_team.model_tournament` block gains `tournament_zones_per_cycle`, `h2h_weight`, `exploration_floor`. |
| `test/test_red_tournament.py` | Modify | Per-zone counters; `load_winrates` / `winrate`; existing disabled/optional tests stay green. |
| `test/test_red_ideation_tournament.py` | Create | `judge_round` round-robin + parsing + forfeit; `update_winrate` §8 formula. |
| `test/test_red_entrant_selection.py` | Create | Deterministic selection, win-rate proportionality, exploration floor, cold start. |
| `test/test_red_tournament_pipeline_e2e.py` | Create | One full red cycle in mock mode with the tournament enabled. |
| `test/test_contracts.py` | Modify | Extended for the three new MCP method signatures on both implementations. |

---

# Phase 0 — Contracts

No behaviour yet: shared types, the schema migration, and MCP signatures. This phase is sequenced **after** the model-routing work (the `models:` config and `make_llm(role)`) has landed — constraint 5.

## Task 1 — New interface types

**Files:**
- Modify: `interfaces/types.py`
- Test: `test/test_red_tournament.py` (extend)

- [ ] Write the failing test. Append to the end of `test/test_red_tournament.py`:
```python
from dataclasses import fields

from interfaces.types import (
    ModelZoneWinrate,
    PairwiseIdeaSetResult,
    TournamentRound,
)


def test_model_zone_winrate_has_h2h_and_execution_fields():
    fnames = {f.name for f in fields(ModelZoneWinrate)}
    assert {"zone_id", "model_label", "role", "h2h_wins", "h2h_comparisons",
            "confirmed", "suspicious", "ideas_executed", "winrate"} <= fnames


def test_model_zone_winrate_neutral_prior():
    w = ModelZoneWinrate(zone_id="SBX-FS", model_label="nemotron")
    assert w.winrate == 0.5  # neutral prior — no-history entrant
    assert w.h2h_comparisons == 0
    assert w.ideas_executed == 0


def test_tournament_round_carries_pairwise_records():
    fnames = {f.name for f in fields(TournamentRound)}
    assert {"round_id", "cycle_id", "zone_id", "entrants",
            "pairwise", "winner_label"} <= fnames


def test_pairwise_idea_set_result_has_winner_and_margin():
    r = PairwiseIdeaSetResult(
        zone_id="SBX-FS", winner_label="frontier", loser_label="nemotron",
        margin=0.4, reasoning="frontier set is more distinct")
    assert r.winner_label == "frontier"
    assert 0.0 <= r.margin <= 1.0
```
- [ ] Run it, verify it fails: `uv run pytest test/test_red_tournament.py -q` — expect `ImportError: cannot import name 'ModelZoneWinrate'`.
- [ ] Add the new dataclasses to `interfaces/types.py` before the `__all__` list:
```python
# ---------------------------------------------------------------------------
# Model ideation tournament — per-zone win-rate + rounds
# (model-ideation-tournament spec §9)
# ---------------------------------------------------------------------------


@dataclass
class ModelZoneWinrate:
    """Per-(zone, model) win-rate: a head-to-head record and an execution
    record, plus the stored combined win-rate. Mirrors the
    model_zone_winrate row."""

    zone_id: str
    model_label: str
    role: str = ""
    h2h_wins: int = 0
    h2h_comparisons: int = 0
    confirmed: int = 0
    suspicious: int = 0
    ideas_executed: int = 0
    winrate: float = 0.5  # neutral prior so a no-history entrant is optimistic
    updated_at: str = ""


@dataclass
class PairwiseIdeaSetResult:
    """One head-to-head comparison of two entrants' idea sets for a zone."""

    zone_id: str
    winner_label: str
    loser_label: str
    margin: float  # 0..1
    reasoning: str = ""


@dataclass
class TournamentRound:
    """One head-to-head round (one zone, one cycle). `entrants` and
    `pairwise` are JSON-serialisable lists. Mirrors the
    model_tournament_rounds row."""

    round_id: str
    cycle_id: int
    zone_id: str
    entrants: list[str] = field(default_factory=list)
    pairwise: list[dict[str, Any]] = field(default_factory=list)
    winner_label: str = ""
    created_at: str = ""
```
- [ ] Append the new names to `__all__` in `interfaces/types.py` (alphabetised within the list): `ModelZoneWinrate`, `PairwiseIdeaSetResult`, `TournamentRound`.
- [ ] Confirm `Any` is imported at the top of `interfaces/types.py` (`from typing import Any` — add it if absent).
- [ ] Run the test, verify it passes: `uv run pytest test/test_red_tournament.py -q` — expect all green (existing tests + 4 new).
- [ ] Run lint: `uv run ruff check interfaces/types.py test/test_red_tournament.py` — expect `All checks passed!`.
- [ ] Commit: `git add interfaces/types.py test/test_red_tournament.py && git commit -m "feat(tournament): per-zone win-rate + round interface types"`.

## Task 2 — Schema migration 0005

**Files:**
- Create: `infra/migrations/0005_model_tournament.sql`
- Modify: `interfaces/schema.sql`
- Test: `test/test_red_ideation_tournament.py`

- [ ] Inspect the highest existing migration number: `ls infra/migrations/`. If the highest is not `0004`, rename the file in this task to the next free number and use that number consistently below (coordination rule 1 of the upgrade roadmap). The plan assumes `0005`.
- [ ] Write the failing test. Create `test/test_red_ideation_tournament.py`:
```python
"""Model ideation tournament — schema + head-to-head tests
(model-ideation-tournament spec §8, §9)."""

from __future__ import annotations

from infra.database import Database

NEW_TABLES = {"model_zone_winrate", "model_tournament_rounds"}


def _table_names(db: Database) -> set[str]:
    rows = db.fetchall("SELECT name FROM sqlite_master WHERE type='table'")
    return {r["name"] for r in rows}


def test_migration_creates_tournament_tables(db: Database):
    assert NEW_TABLES <= _table_names(db)


def test_model_zone_winrate_columns(db: Database):
    cols = {r["name"] for r in db.fetchall(
        "PRAGMA table_info(model_zone_winrate)")}
    assert {"zone_id", "model_label", "role", "h2h_wins", "h2h_comparisons",
            "confirmed", "suspicious", "ideas_executed", "winrate"} <= cols


def test_model_tournament_rounds_columns(db: Database):
    cols = {r["name"] for r in db.fetchall(
        "PRAGMA table_info(model_tournament_rounds)")}
    assert {"round_id", "cycle_id", "zone_id", "entrants",
            "pairwise", "winner_label"} <= cols


def test_schema_version_is_three(db: Database):
    row = db.fetchone("SELECT schema_version FROM schema_meta")
    assert row["schema_version"] >= 3
```
- [ ] Run it, verify it fails: `uv run pytest test/test_red_ideation_tournament.py -q` — expect `AssertionError` (tables absent).
- [ ] Create `infra/migrations/0005_model_tournament.sql`:
```sql
-- Migration 0005 — model ideation tournament tables
-- (model-ideation-tournament spec §9).
-- Forward-only, idempotent. Applied by infra/migrations.py on Database open.

BEGIN;

CREATE TABLE IF NOT EXISTS model_zone_winrate (
    zone_id          TEXT NOT NULL,
    model_label      TEXT NOT NULL,
    role             TEXT NOT NULL DEFAULT '',
    h2h_wins         INTEGER NOT NULL DEFAULT 0,
    h2h_comparisons  INTEGER NOT NULL DEFAULT 0,
    confirmed        INTEGER NOT NULL DEFAULT 0,
    suspicious       INTEGER NOT NULL DEFAULT 0,
    ideas_executed   INTEGER NOT NULL DEFAULT 0,
    winrate          REAL NOT NULL DEFAULT 0.5,
    updated_at       TEXT NOT NULL DEFAULT (datetime('now')),
    PRIMARY KEY (zone_id, model_label)
);
CREATE INDEX IF NOT EXISTS idx_model_zone_winrate_zone
    ON model_zone_winrate(zone_id, winrate);

CREATE TABLE IF NOT EXISTS model_tournament_rounds (
    round_id      TEXT PRIMARY KEY,
    cycle_id      INTEGER NOT NULL,
    zone_id       TEXT NOT NULL,
    entrants      TEXT NOT NULL DEFAULT '[]',
    pairwise      TEXT NOT NULL DEFAULT '[]',
    winner_label  TEXT NOT NULL DEFAULT '',
    created_at    TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_model_tournament_rounds_zone
    ON model_tournament_rounds(zone_id, cycle_id);

UPDATE schema_meta SET schema_version = 3 WHERE schema_version < 3;

COMMIT;
```
- [ ] Mirror the two `CREATE TABLE` / `CREATE INDEX` blocks into `interfaces/schema.sql` (append after the `model_runs` block) so the bootstrap-from-empty path and the migrated path agree. Drop the `BEGIN;`/`COMMIT;` and the `UPDATE` line — `schema.sql` is the fresh-DB definition.
- [ ] Run the test, verify it passes: `uv run pytest test/test_red_ideation_tournament.py -q` — expect `4 passed`.
- [ ] Run the migration-runner test to confirm 0005 is discovered: `uv run pytest test/ -k migration -q` — expect all green.
- [ ] Run lint: `uv run ruff check test/test_red_ideation_tournament.py` — expect `All checks passed!`.
- [ ] Commit: `git add infra/migrations/0005_model_tournament.sql interfaces/schema.sql test/test_red_ideation_tournament.py && git commit -m "feat(tournament): migration 0005 — win-rate + rounds tables"`.

## Task 3 — MCP write/read methods

**Files:**
- Modify: `interfaces/mcp_tools.py`
- Modify: `infra/mcp_server.py`
- Modify: `infra/mock_mcp.py`
- Test: `test/test_red_ideation_tournament.py` (extend)

- [ ] Add failing tests to the end of `test/test_red_ideation_tournament.py`:
```python
def test_mcp_upserts_and_reads_model_zone_winrate(server):
    from interfaces.types import ModelZoneWinrate

    server.update_model_zone_winrate(ModelZoneWinrate(
        zone_id="SBX-FS", model_label="nemotron", role="red_ideation",
        h2h_wins=2, h2h_comparisons=3, confirmed=1, suspicious=0,
        ideas_executed=4, winrate=0.62))
    rows = server.get_model_zone_winrate("SBX-FS")
    assert len(rows) == 1
    assert rows[0].winrate == 0.62
    # upsert: a second write replaces, not appends.
    server.update_model_zone_winrate(ModelZoneWinrate(
        zone_id="SBX-FS", model_label="nemotron", role="red_ideation",
        h2h_wins=3, h2h_comparisons=4, confirmed=2, suspicious=0,
        ideas_executed=5, winrate=0.71))
    rows2 = server.get_model_zone_winrate("SBX-FS")
    assert len(rows2) == 1
    assert rows2[0].winrate == 0.71


def test_mcp_get_model_zone_winrate_all_zones(server):
    from interfaces.types import ModelZoneWinrate

    server.update_model_zone_winrate(ModelZoneWinrate(
        zone_id="SBX-FS", model_label="a"))
    server.update_model_zone_winrate(ModelZoneWinrate(
        zone_id="SBX-NET", model_label="b"))
    assert len(server.get_model_zone_winrate()) == 2


def test_mcp_logs_and_reads_tournament_round(server):
    from interfaces.types import TournamentRound

    round_id = server.log_tournament_round(TournamentRound(
        round_id="", cycle_id=7, zone_id="SBX-FS",
        entrants=["nemotron", "frontier"],
        pairwise=[{"a": "nemotron", "b": "frontier",
                   "winner": "frontier", "margin": 0.4}],
        winner_label="frontier"))
    assert round_id
    rows = server.db.fetchall(
        "SELECT * FROM model_tournament_rounds WHERE zone_id='SBX-FS'")
    assert rows[0]["winner_label"] == "frontier"
    assert rows[0]["cycle_id"] == 7
```
- [ ] Run it, verify it fails: `uv run pytest test/test_red_ideation_tournament.py -k mcp -q` — expect `AttributeError: 'MCPServer' object has no attribute 'update_model_zone_winrate'`.
- [ ] Add the three method signatures to the MCP protocol/base in `interfaces/mcp_tools.py` (after the `log_model_run` definition near line 175):
```python
    def get_model_zone_winrate(
        self, zone_id: str | None = None,
    ) -> list[ModelZoneWinrate]:
        """All win-rate rows, or one zone's, for routing decisions."""
        raise NotImplementedError

    def update_model_zone_winrate(self, row: ModelZoneWinrate) -> None:
        """Upsert one (zone_id, model_label) win-rate row."""
        raise NotImplementedError

    def log_tournament_round(self, round: TournamentRound) -> str:
        """Record one head-to-head round. Returns round_id."""
        raise NotImplementedError
```
- [ ] Add `ModelZoneWinrate` and `TournamentRound` to the `interfaces.types` import block at the top of `interfaces/mcp_tools.py`.
- [ ] Implement the three methods in `infra/mcp_server.py`. Add `ModelZoneWinrate`, `TournamentRound` to the imports and ensure `import uuid` / `import json` are present:
```python
    def get_model_zone_winrate(
        self, zone_id: str | None = None,
    ) -> list[ModelZoneWinrate]:
        if zone_id is None:
            rows = self.db.fetchall(
                "SELECT * FROM model_zone_winrate ORDER BY winrate DESC")
        else:
            rows = self.db.fetchall(
                "SELECT * FROM model_zone_winrate WHERE zone_id=? "
                "ORDER BY winrate DESC", (zone_id,))
        return [ModelZoneWinrate(
            zone_id=r["zone_id"], model_label=r["model_label"],
            role=r["role"], h2h_wins=r["h2h_wins"],
            h2h_comparisons=r["h2h_comparisons"], confirmed=r["confirmed"],
            suspicious=r["suspicious"], ideas_executed=r["ideas_executed"],
            winrate=r["winrate"], updated_at=r["updated_at"],
        ) for r in rows]

    def update_model_zone_winrate(self, row: ModelZoneWinrate) -> None:
        self.db.execute(
            """INSERT INTO model_zone_winrate
               (zone_id, model_label, role, h2h_wins, h2h_comparisons,
                confirmed, suspicious, ideas_executed, winrate, updated_at)
               VALUES (?,?,?,?,?,?,?,?,?, datetime('now'))
               ON CONFLICT(zone_id, model_label) DO UPDATE SET
                 role=excluded.role, h2h_wins=excluded.h2h_wins,
                 h2h_comparisons=excluded.h2h_comparisons,
                 confirmed=excluded.confirmed,
                 suspicious=excluded.suspicious,
                 ideas_executed=excluded.ideas_executed,
                 winrate=excluded.winrate, updated_at=excluded.updated_at""",
            (row.zone_id, row.model_label, row.role, row.h2h_wins,
             row.h2h_comparisons, row.confirmed, row.suspicious,
             row.ideas_executed, row.winrate),
        )

    def log_tournament_round(self, round: TournamentRound) -> str:
        round_id = round.round_id or f"round-{uuid.uuid4().hex[:12]}"
        self.db.execute(
            """INSERT INTO model_tournament_rounds
               (round_id, cycle_id, zone_id, entrants, pairwise,
                winner_label)
               VALUES (?,?,?,?,?,?)""",
            (round_id, round.cycle_id, round.zone_id,
             json.dumps(round.entrants), json.dumps(round.pairwise),
             round.winner_label),
        )
        return round_id
```
- [ ] Implement the same three methods in `infra/mock_mcp.py` against the mock's in-memory store (mirror the existing `log_model_run` mock pattern: a dict keyed `(zone_id, model_label)` for upsert, a list for rounds; `get_model_zone_winrate(None)` returns all rows; `log_tournament_round` generates and returns a `round_id`).
- [ ] Run the test, verify it passes: `uv run pytest test/test_red_ideation_tournament.py -q` — expect `7 passed`.
- [ ] Extend `test/test_contracts.py` — add `get_model_zone_winrate`, `update_model_zone_winrate`, `log_tournament_round` to the list of expected MCP methods the contract test checks across both `MCPServer` and `MockMCP`.
- [ ] Run: `uv run pytest test/test_contracts.py -q` — expect all green.
- [ ] Run lint: `uv run ruff check interfaces/mcp_tools.py infra/mcp_server.py infra/mock_mcp.py test/test_red_ideation_tournament.py` — expect `All checks passed!`.
- [ ] Commit: `git add interfaces/mcp_tools.py infra/mcp_server.py infra/mock_mcp.py test/test_red_ideation_tournament.py test/test_contracts.py && git commit -m "feat(tournament): MCP win-rate + tournament-round methods"`.

---

# Phase 1 — Per-zone stats + persistence

Extend `ModelTournament` with the per-zone counter dimension and persisted-win-rate accessors. No new judging yet.

## Task 4 — Per-zone counters in ModelTournament

**Files:**
- Modify: `red_team/tournament.py`
- Test: `test/test_red_tournament.py` (extend)

- [ ] Write the failing test. Append to `test/test_red_tournament.py`:
```python
from red_team.tournament import Entrant, ModelTournament, ModelTournamentConfig


def _tournament():
    return ModelTournament(ModelTournamentConfig(
        enabled=True, entrants=[Entrant(role="red_ideation")]))


def test_record_outcome_counts_per_zone():
    t = _tournament()
    t.record_outcome("nemotron", verdict="confirmed", zone_id="SBX-FS")
    t.record_outcome("nemotron", verdict="suspicious", zone_id="SBX-NET")
    fs = t.leaderboard(zone_id="SBX-FS")
    net = t.leaderboard(zone_id="SBX-NET")
    assert fs["nemotron"]["confirmed"] == 1
    assert fs["nemotron"]["suspicious"] == 0
    assert net["nemotron"]["suspicious"] == 1


def test_leaderboard_global_rollup_sums_zones():
    t = _tournament()
    t.record_outcome("nemotron", verdict="confirmed", zone_id="SBX-FS")
    t.record_outcome("nemotron", verdict="confirmed", zone_id="SBX-NET")
    # no zone_id -> global rollup across all zones.
    assert t.leaderboard()["nemotron"]["confirmed"] == 2


def test_record_outcome_without_zone_uses_global_bucket():
    t = _tournament()
    t.record_outcome("nemotron", verdict="confirmed")
    assert t.leaderboard()["nemotron"]["confirmed"] == 1
```
- [ ] Run it, verify it fails: `uv run pytest test/test_red_tournament.py -k "per_zone or rollup or global_bucket" -q` — expect `TypeError` (`record_outcome` has no `zone_id`).
- [ ] Replace the `_stats`, `_bump`, `record_outcome`, `leaderboard`, and `generate` (the `_bump` call) members of `ModelTournament` in `red_team/tournament.py` so counters are keyed `(model_label, zone_id)`:
```python
    def __init__(self, cfg: ModelTournamentConfig | None = None) -> None:
        self.cfg = cfg or ModelTournamentConfig()
        # (model_label, zone_id) -> {"ideas","confirmed","suspicious","tokens"}
        self._stats: dict[tuple[str, str], dict[str, int]] = {}
        # persisted per-(zone, model) win-rates, loaded via load_winrates().
        self._winrates: dict[tuple[str, str], float] = {}

    _GLOBAL_ZONE = "*"

    def _bump(self, label: str, zone_id: str = _GLOBAL_ZONE,
              **deltas: int) -> None:
        row = self._stats.setdefault(
            (label, zone_id),
            {"ideas": 0, "confirmed": 0, "suspicious": 0, "tokens": 0})
        for k, v in deltas.items():
            row[k] = row.get(k, 0) + v

    def record_outcome(self, model_label: str, *, verdict: str,
                       tokens: int = 0,
                       zone_id: str | None = None) -> None:
        """Record a judged outcome against the model that produced the idea,
        bucketed by zone (the global bucket when zone_id is omitted)."""
        self._bump(
            model_label,
            zone_id or self._GLOBAL_ZONE,
            confirmed=1 if verdict == "confirmed" else 0,
            suspicious=1 if verdict == "suspicious" else 0,
            tokens=tokens,
        )

    def leaderboard(
        self, zone_id: str | None = None,
    ) -> dict[str, dict[str, int]]:
        """Per-model performance snapshot. With `zone_id`, only that zone;
        without it, the global rollup summed across every zone."""
        out: dict[str, dict[str, int]] = {}
        for (label, zid), row in self._stats.items():
            if zone_id is not None and zid != zone_id:
                continue
            agg = out.setdefault(
                label, {"ideas": 0, "confirmed": 0,
                        "suspicious": 0, "tokens": 0})
            for k, v in row.items():
                agg[k] = agg.get(k, 0) + v
        return out
```
- [ ] Update `generate()` in `red_team/tournament.py` — its `self._bump(entrant.label, ideas=len(ideas))` call now needs no zone (ideas are counted before the zone is judged), so it uses the global bucket. Leave that line as `self._bump(entrant.label, ideas=len(ideas))` (the new `_bump` signature defaults `zone_id` to `_GLOBAL_ZONE`).
- [ ] Update `summary()` in `red_team/tournament.py` to iterate the global rollup rather than `self._stats.items()` directly:
```python
    def summary(self) -> str:
        rollup = self.leaderboard()
        if not rollup:
            return "model tournament: no entrants recorded"
        parts = [
            f"{label}: {row['confirmed']} confirmed / {row['ideas']} ideas, "
            f"{row['tokens']} tokens"
            for label, row in sorted(rollup.items())
        ]
        return "model tournament — " + "; ".join(parts)
```
- [ ] Run the test, verify it passes: `uv run pytest test/test_red_tournament.py -q` — expect all green (existing disabled-tournament and optional-entrant-failure tests stay green).
- [ ] Run lint: `uv run ruff check red_team/tournament.py test/test_red_tournament.py` — expect `All checks passed!`.
- [ ] Commit: `git add red_team/tournament.py test/test_red_tournament.py && git commit -m "feat(tournament): per-zone outcome counters"`.

## Task 5 — load_winrates / winrate accessors

**Files:**
- Modify: `red_team/tournament.py`
- Test: `test/test_red_tournament.py` (extend)

- [ ] Write the failing test. Append to `test/test_red_tournament.py`:
```python
def test_load_winrates_round_trips():
    from interfaces.types import ModelZoneWinrate

    t = _tournament()
    t.load_winrates([
        ModelZoneWinrate(zone_id="SBX-FS", model_label="nemotron",
                         winrate=0.72),
        ModelZoneWinrate(zone_id="SBX-FS", model_label="frontier",
                         winrate=0.41),
    ])
    assert t.winrate("SBX-FS", "nemotron") == 0.72
    assert t.winrate("SBX-FS", "frontier") == 0.41


def test_winrate_returns_neutral_prior_for_unknown_pair():
    t = _tournament()
    # no history at all -> neutral prior so routing treats it optimistically.
    assert t.winrate("SBX-FS", "never-seen") == 0.5
```
- [ ] Run it, verify it fails: `uv run pytest test/test_red_tournament.py -k "load_winrates or winrate" -q` — expect `AttributeError`.
- [ ] Add `load_winrates` and `winrate` to `ModelTournament` in `red_team/tournament.py`, and add `from interfaces.types import IdeaObject, ModelZoneWinrate` to the imports (extend the existing import line):
```python
    _NEUTRAL_WINRATE = 0.5

    def load_winrates(self, rows: list[ModelZoneWinrate]) -> None:
        """Load persisted per-(zone, model) win-rates so routing decisions
        read accumulated state. Replaces any previously loaded set."""
        self._winrates = {
            (r.zone_id, r.model_label): r.winrate for r in rows
        }

    def winrate(self, zone_id: str, model_label: str) -> float:
        """The persisted win-rate for (zone, model), or the neutral prior
        (0.5) for a pair with no history — the starvation-avoidance prior."""
        return self._winrates.get(
            (zone_id, model_label), self._NEUTRAL_WINRATE)
```
- [ ] Run the test, verify it passes: `uv run pytest test/test_red_tournament.py -q` — expect all green.
- [ ] Run lint: `uv run ruff check red_team/tournament.py test/test_red_tournament.py` — expect `All checks passed!`.
- [ ] Commit: `git add red_team/tournament.py test/test_red_tournament.py && git commit -m "feat(tournament): persisted win-rate accessors"`.

---

# Phase 2 — Head-to-head judging

`ideation_tournament.py`: the round-robin pairwise judge and the §8 win-rate fold.

## Task 6 — IdeationTournamentJudge.judge_round

**Files:**
- Create: `red_team/ideation_tournament.py`
- Test: `test/test_red_ideation_tournament.py` (extend)

- [ ] Write the failing test. Append to `test/test_red_ideation_tournament.py`:
```python
from interfaces.llm import LLMResponse
from red_team.ideation_tournament import IdeationTournamentJudge


class _Idea:
    def __init__(self, title):
        self.title = title
        self.approach = "approach text"
        self.novelty_note = "novel"
        self.tactic_tags = ["t1"]


class _ScriptedLLM:
    """Returns 'A' as winner each call unless told to fail."""

    def __init__(self, raise_exc=None):
        self.raise_exc = raise_exc
        self.calls = 0

    def complete(self, *, messages, system, max_tokens, temperature):
        self.calls += 1
        if self.raise_exc is not None:
            raise self.raise_exc
        return LLMResponse(text=(
            '{"winner": "A", "margin": 0.5, '
            '"reasoning": "A is more distinct"}'),
            input_tokens=5, output_tokens=10)


def test_judge_round_two_entrants_runs_one_comparison():
    llm = _ScriptedLLM()
    judge = IdeationTournamentJudge(llm)
    idea_sets = {"nemotron": [_Idea("i1")], "frontier": [_Idea("i2")]}
    rnd = judge.judge_round(zone_id="SBX-FS", cycle_id=1,
                            idea_sets=idea_sets)
    assert llm.calls == 1
    assert len(rnd.pairwise) == 1
    assert rnd.winner_label in ("nemotron", "frontier")


def test_judge_round_three_entrants_runs_round_robin():
    llm = _ScriptedLLM()
    judge = IdeationTournamentJudge(llm)
    idea_sets = {"a": [_Idea("x")], "b": [_Idea("y")], "c": [_Idea("z")]}
    rnd = judge.judge_round(zone_id="Z", cycle_id=1, idea_sets=idea_sets)
    assert llm.calls == 3  # round-robin of 3 entrants -> 3 comparisons
    assert len(rnd.pairwise) == 3


def test_judge_round_treats_empty_idea_set_as_forfeit():
    llm = _ScriptedLLM()
    judge = IdeationTournamentJudge(llm)
    idea_sets = {"nemotron": [_Idea("i1")], "frontier": []}
    rnd = judge.judge_round(zone_id="Z", cycle_id=1, idea_sets=idea_sets)
    # the entrant with ideas wins by forfeit; no LLM call needed.
    assert llm.calls == 0
    assert rnd.pairwise[0]["winner"] == "nemotron"


def test_judge_round_survives_a_failed_pairwise_call():
    llm = _ScriptedLLM(raise_exc=RuntimeError("judge down"))
    judge = IdeationTournamentJudge(llm)
    idea_sets = {"a": [_Idea("x")], "b": [_Idea("y")]}
    rnd = judge.judge_round(zone_id="Z", cycle_id=1, idea_sets=idea_sets)
    # the failed comparison is dropped, the round still returns.
    assert rnd.pairwise == []
```
- [ ] Run it, verify it fails: `uv run pytest test/test_red_ideation_tournament.py -k judge_round -q` — expect `ModuleNotFoundError`.
- [ ] Create `red_team/ideation_tournament.py`:
```python
"""Head-to-head ideation judging + win-rate update — model-ideation-tournament
spec §5, §7.2, §8.

Counting confirmed findings conflates idea quality with execution and judging
luck. This module adds a cheaper, more direct signal that runs BEFORE
execution: a round-robin of pairwise comparisons of the idea SETS the entrant
models produced for one zone. A direct comparison is more reliable than two
absolute scores — the same principle the judge-ensemble spec uses for attack
ranking, applied one level earlier.

Never raises: a failed pairwise call drops that comparison; an empty idea set
is a forfeit, not a crash.
"""

from __future__ import annotations

import itertools
import logging
import uuid

from interfaces.llm import LLMClient, LLMMessage, extract_json
from interfaces.types import ModelZoneWinrate, TournamentRound

LOG = logging.getLogger("monkeyclaw.red.ideation_tournament")

_H2H_WEIGHT_DEFAULT = 0.6
_NEUTRAL_WINRATE = 0.5

_COMPARE_SYSTEM = """\
You are the IDEATION TOURNAMENT judge in a red-team exercise. You are given
two entrant models' idea sets (A and B) for the SAME attack-surface zone.
Answer ONE question: which entrant's idea set is the stronger basis for
attacking this zone — more genuinely distinct approaches, more zone-relevant
exploitation, fewer textbook repeats?

Output JSON only — no prose, no markdown fences:

{
  "winner": "A" | "B",
  "margin": 0.0 to 1.0,
  "reasoning": "one paragraph"
}
"""


def _idea_set_block(label: str, ideas: list[object]) -> str:
    lines = [f"# Entrant {label}"]
    for i, idea in enumerate(ideas):
        lines.append(
            f"  idea {i + 1}: {getattr(idea, 'title', '?')} | "
            f"approach: {getattr(idea, 'approach', '')} | "
            f"novelty: {getattr(idea, 'novelty_note', '')} | "
            f"tactics: {getattr(idea, 'tactic_tags', [])}"
        )
    return "\n".join(lines)


class IdeationTournamentJudge:
    """Round-robin pairwise judge of entrant idea sets + win-rate fold."""

    def __init__(self, llm: LLMClient, mcp: object | None = None,
                 h2h_weight: float = _H2H_WEIGHT_DEFAULT) -> None:
        self.llm = llm
        self.mcp = mcp
        self.h2h_weight = h2h_weight

    def _compare(self, zone_id: str, label_a: str, ideas_a: list[object],
                 label_b: str, ideas_b: list[object]) -> dict | None:
        """One pairwise comparison. Forfeit on empty set; None on LLM failure."""
        if not ideas_a and not ideas_b:
            return None
        if not ideas_b:
            return {"a": label_a, "b": label_b,
                    "winner": label_a, "margin": 1.0}
        if not ideas_a:
            return {"a": label_a, "b": label_b,
                    "winner": label_b, "margin": 1.0}
        user = (
            f"Zone: {zone_id}\n\n"
            f"{_idea_set_block('A', ideas_a)}\n\n"
            f"{_idea_set_block('B', ideas_b)}\n\n"
            f"Compare now. Output JSON only."
        )
        try:
            resp = self.llm.complete(
                messages=[LLMMessage(role="user", content=user)],
                system=_COMPARE_SYSTEM, max_tokens=600, temperature=0.2,
            )
        except Exception as e:  # noqa: BLE001 - a failed pair is dropped
            LOG.warning("ideation pairwise call failed (%s vs %s): %r",
                        label_a, label_b, e)
            return None
        try:
            data = extract_json(resp.text)
        except ValueError:
            LOG.warning("ideation pairwise unparseable: %r", resp.text[:200])
            return None
        if isinstance(data, list):
            data = data[0] if data else {}
        if not isinstance(data, dict):
            return None
        winner = str(data.get("winner", "")).upper()
        if winner not in ("A", "B"):
            return None
        margin = max(0.0, min(1.0, float(data.get("margin", 0.0) or 0.0)))
        win_label = label_a if winner == "A" else label_b
        return {"a": label_a, "b": label_b,
                "winner": win_label, "margin": margin}

    def judge_round(self, zone_id: str, cycle_id: int,
                    idea_sets: dict[str, list[object]]) -> TournamentRound:
        """Run the round-robin pairwise comparisons for one zone."""
        labels = sorted(idea_sets)
        pairwise: list[dict] = []
        for label_a, label_b in itertools.combinations(labels, 2):
            result = self._compare(zone_id, label_a, idea_sets[label_a],
                                   label_b, idea_sets[label_b])
            if result is not None:
                pairwise.append(result)
        wins: dict[str, int] = {label: 0 for label in labels}
        for p in pairwise:
            wins[p["winner"]] = wins.get(p["winner"], 0) + 1
        winner_label = max(wins, key=wins.get) if wins else ""
        rnd = TournamentRound(
            round_id=f"round-{uuid.uuid4().hex[:12]}",
            cycle_id=cycle_id, zone_id=zone_id,
            entrants=labels, pairwise=pairwise, winner_label=winner_label,
        )
        if self.mcp is not None:
            try:
                self.mcp.log_tournament_round(rnd)
            except Exception as e:  # noqa: BLE001 - persistence is best-effort
                LOG.warning("failed to log tournament round: %r", e)
        return rnd


__all__ = ["IdeationTournamentJudge"]
```
- [ ] Run the test, verify it passes: `uv run pytest test/test_red_ideation_tournament.py -k judge_round -q` — expect `4 passed`.
- [ ] Run lint: `uv run ruff check red_team/ideation_tournament.py test/test_red_ideation_tournament.py` — expect `All checks passed!`.
- [ ] Commit: `git add red_team/ideation_tournament.py test/test_red_ideation_tournament.py && git commit -m "feat(tournament): round-robin head-to-head ideation judge"`.

## Task 7 — update_winrate — the §8 fold

**Files:**
- Modify: `red_team/ideation_tournament.py`
- Test: `test/test_red_ideation_tournament.py` (extend)

- [ ] Write the failing test. Append to `test/test_red_ideation_tournament.py`:
```python
from interfaces.types import ModelZoneWinrate, TournamentRound


def _round(zone, pairwise, entrants):
    return TournamentRound(round_id="r1", cycle_id=1, zone_id=zone,
                           entrants=entrants, pairwise=pairwise,
                           winner_label="")


def test_update_winrate_folds_h2h_and_execution_signals():
    judge = IdeationTournamentJudge(llm=None, h2h_weight=0.6)
    rnd = _round("Z",
                 [{"a": "nemotron", "b": "frontier",
                   "winner": "nemotron", "margin": 0.5}],
                 ["nemotron", "frontier"])
    # nemotron: 1 confirmed of 2 executed -> exec_rate 0.5; h2h 1/1 = 1.0
    # winrate = 0.6*1.0 + 0.4*0.5 = 0.8
    outcomes = {"nemotron": {"confirmed": 1, "suspicious": 0,
                             "ideas_executed": 2},
                "frontier": {"confirmed": 0, "suspicious": 0,
                             "ideas_executed": 2}}
    rows = judge.update_winrate(rnd, outcomes,
                                prior={})
    by_label = {r.model_label: r for r in rows}
    assert abs(by_label["nemotron"].winrate - 0.8) < 1e-9
    # frontier: h2h 0/1 = 0.0; exec 0/2 = 0.0 -> winrate 0.0
    assert abs(by_label["frontier"].winrate - 0.0) < 1e-9


def test_update_winrate_neutral_prior_for_no_history_entrant():
    judge = IdeationTournamentJudge(llm=None, h2h_weight=0.6)
    # an entrant in the round but with no comparisons and no execution.
    rnd = _round("Z", [], ["lonely"])
    rows = judge.update_winrate(rnd, execution_outcomes={}, prior={})
    by_label = {r.model_label: r for r in rows}
    # no h2h evidence, no execution evidence -> neutral prior preserved.
    assert by_label["lonely"].winrate == 0.5


def test_update_winrate_accumulates_onto_prior():
    judge = IdeationTournamentJudge(llm=None, h2h_weight=0.6)
    prior = {("Z", "nemotron"): ModelZoneWinrate(
        zone_id="Z", model_label="nemotron", h2h_wins=1,
        h2h_comparisons=1, confirmed=1, suspicious=0, ideas_executed=2)}
    rnd = _round("Z",
                 [{"a": "nemotron", "b": "frontier",
                   "winner": "nemotron", "margin": 0.5}],
                 ["nemotron", "frontier"])
    outcomes = {"nemotron": {"confirmed": 1, "suspicious": 0,
                             "ideas_executed": 2}}
    rows = judge.update_winrate(rnd, outcomes, prior=prior)
    nemotron = {r.model_label: r for r in rows}["nemotron"]
    # counters accumulate: 2 h2h comparisons, 2 h2h wins, 4 ideas executed.
    assert nemotron.h2h_comparisons == 2
    assert nemotron.h2h_wins == 2
    assert nemotron.ideas_executed == 4
```
- [ ] Run it, verify it fails: `uv run pytest test/test_red_ideation_tournament.py -k update_winrate -q` — expect `AttributeError`.
- [ ] Add the `update_winrate` method to `IdeationTournamentJudge` in `red_team/ideation_tournament.py`:
```python
    def update_winrate(
        self,
        round: TournamentRound,
        execution_outcomes: dict[str, dict[str, int]],
        prior: dict[tuple[str, str], ModelZoneWinrate] | None = None,
    ) -> list[ModelZoneWinrate]:
        """Fold the round's head-to-head wins and the cycle's execution
        verdicts into the per-zone win-rate (spec §8). `prior` is the
        persisted state keyed (zone_id, model_label); each returned row is
        the accumulated, recomputed win-rate. Best-effort MCP persistence."""
        prior = prior or {}
        zone = round.zone_id
        # Tally this round's head-to-head wins / comparisons per entrant.
        h2h_w: dict[str, int] = {label: 0 for label in round.entrants}
        h2h_c: dict[str, int] = {label: 0 for label in round.entrants}
        for p in round.pairwise:
            for side in ("a", "b"):
                label = p.get(side)
                if label in h2h_c:
                    h2h_c[label] += 1
            if p.get("winner") in h2h_w:
                h2h_w[p["winner"]] += 1

        rows: list[ModelZoneWinrate] = []
        labels = set(round.entrants) | set(execution_outcomes)
        for label in sorted(labels):
            base = prior.get((zone, label))
            row = ModelZoneWinrate(
                zone_id=zone, model_label=label,
                role=base.role if base else "",
                h2h_wins=(base.h2h_wins if base else 0) + h2h_w.get(label, 0),
                h2h_comparisons=(base.h2h_comparisons if base else 0)
                + h2h_c.get(label, 0),
            )
            exec_out = execution_outcomes.get(label, {})
            row.confirmed = ((base.confirmed if base else 0)
                             + int(exec_out.get("confirmed", 0)))
            row.suspicious = ((base.suspicious if base else 0)
                              + int(exec_out.get("suspicious", 0)))
            row.ideas_executed = ((base.ideas_executed if base else 0)
                                  + int(exec_out.get("ideas_executed", 0)))
            row.winrate = self._combined_winrate(row)
            rows.append(row)
            if self.mcp is not None:
                try:
                    self.mcp.update_model_zone_winrate(row)
                except Exception as e:  # noqa: BLE001 - best-effort
                    LOG.warning("failed to persist win-rate: %r", e)
        return rows

    def _combined_winrate(self, row: ModelZoneWinrate) -> float:
        """The §8 win-rate. With no h2h and no execution evidence at all,
        the neutral prior (0.5) is preserved so routing stays optimistic."""
        if row.h2h_comparisons == 0 and row.ideas_executed == 0:
            return _NEUTRAL_WINRATE
        h2h_rate = row.h2h_wins / max(row.h2h_comparisons, 1)
        exec_rate = ((row.confirmed + 0.5 * row.suspicious)
                     / max(row.ideas_executed, 1))
        return (self.h2h_weight * h2h_rate
                + (1.0 - self.h2h_weight) * exec_rate)
```
- [ ] Run the test, verify it passes: `uv run pytest test/test_red_ideation_tournament.py -q` — expect all green.
- [ ] Run lint: `uv run ruff check red_team/ideation_tournament.py test/test_red_ideation_tournament.py` — expect `All checks passed!`.
- [ ] Commit: `git add red_team/ideation_tournament.py test/test_red_ideation_tournament.py && git commit -m "feat(tournament): win-rate fold of h2h + execution signals"`.

---

# Phase 3 — Win-rate routing

`entrant_selection.py`: the per-zone routing draw with an exploration floor.

## Task 8 — entrant_selection.weights + select_entrants

**Files:**
- Create: `red_team/entrant_selection.py`
- Test: `test/test_red_entrant_selection.py`

- [ ] Write the failing test. Create `test/test_red_entrant_selection.py`:
```python
"""Model ideation tournament — entrant routing tests
(model-ideation-tournament spec §7.3)."""

from __future__ import annotations

from collections import Counter

from interfaces.types import ModelZoneWinrate
from red_team.entrant_selection import select_entrants, weights
from red_team.tournament import Entrant

ENTRANTS = [Entrant(role="red_ideation"),
            Entrant(role="frontier_creative_optional")]


def _winrates(zone, mapping):
    return [ModelZoneWinrate(zone_id=zone, model_label=label, winrate=wr)
            for label, wr in mapping.items()]


def test_weights_floor_every_entrant():
    wr = _winrates("Z", {"red_ideation": 0.9})
    w = weights("Z", ENTRANTS, wr, exploration_floor=0.2)
    # frontier has no win-rate row -> still gets at least the floor.
    assert w["frontier_creative_optional"] >= 0.2
    assert w["red_ideation"] >= 0.2


def test_no_history_zone_runs_all_entrants():
    selected = select_entrants("Z", ENTRANTS, [], exploration_floor=0.2,
                               seed=1)
    assert {e.label for e in selected} == {e.label for e in ENTRANTS}


def test_selection_is_deterministic_under_seed():
    wr = _winrates("Z", {"red_ideation": 0.8,
                         "frontier_creative_optional": 0.2})
    a = select_entrants("Z", ENTRANTS, wr, exploration_floor=0.1, seed=42)
    b = select_entrants("Z", ENTRANTS, wr, exploration_floor=0.1, seed=42)
    assert [e.label for e in a] == [e.label for e in b]


def test_high_winrate_entrant_selected_more_often():
    wr = _winrates("Z", {"red_ideation": 0.9,
                         "frontier_creative_optional": 0.1})
    counts = Counter()
    for s in range(400):
        for e in select_entrants("Z", ENTRANTS, wr,
                                 exploration_floor=0.05, seed=s):
            counts[e.label] += 1
    assert counts["red_ideation"] > counts["frontier_creative_optional"]


def test_exploration_floor_guarantees_minimum_sampling():
    wr = _winrates("Z", {"red_ideation": 0.99,
                         "frontier_creative_optional": 0.01})
    counts = Counter()
    for s in range(400):
        for e in select_entrants("Z", ENTRANTS, wr,
                                 exploration_floor=0.25, seed=s):
            counts[e.label] += 1
    # the weak entrant is sampled in a meaningful fraction of draws.
    assert counts["frontier_creative_optional"] > 0.15 * 400
```
- [ ] Run it, verify it fails: `uv run pytest test/test_red_entrant_selection.py -q` — expect `ModuleNotFoundError`.
- [ ] Create `red_team/entrant_selection.py`:
```python
"""Win-rate-driven entrant routing — model-ideation-tournament spec §7.3.

Future ideation for a zone draws entrants in proportion to their per-zone
win-rate, but every configured entrant keeps an exploration-floor probability
so a new or currently-weak entrant is sampled often enough to discover a zone
where it is actually strong. A zone with no win-rate history runs ALL
entrants — a cold start is full competition.

`random` only; deterministic under `seed`.
"""

from __future__ import annotations

import random

from interfaces.types import ModelZoneWinrate
from red_team.tournament import Entrant

_NEUTRAL_WINRATE = 0.5


def _winrate_index(
    zone_id: str, winrates: list[ModelZoneWinrate],
) -> dict[str, float]:
    """Per-model win-rate for one zone, from the persisted rows."""
    return {w.model_label: w.winrate
            for w in winrates if w.zone_id == zone_id}


def weights(
    zone_id: str, all_entrants: list[Entrant],
    winrates: list[ModelZoneWinrate], *, exploration_floor: float = 0.1,
) -> dict[str, float]:
    """Routing weight per entrant label: its per-zone win-rate (neutral prior
    when unknown), floored at `exploration_floor` so no entrant is starved."""
    idx = _winrate_index(zone_id, winrates)
    return {
        e.label: max(idx.get(e.label, _NEUTRAL_WINRATE), exploration_floor)
        for e in all_entrants
    }


def select_entrants(
    zone_id: str, all_entrants: list[Entrant],
    winrates: list[ModelZoneWinrate], *, exploration_floor: float = 0.1,
    seed: int | None = None,
) -> list[Entrant]:
    """Pick which entrants run this cycle for `zone_id`.

    A no-history zone runs every entrant (cold start = full competition).
    Otherwise each entrant is included independently with probability equal
    to its routing weight, and the exploration floor guarantees every
    configured entrant a minimum inclusion rate. The result is never empty:
    if no entrant is drawn, the highest-weighted one is forced in."""
    if not _winrate_index(zone_id, winrates):
        return list(all_entrants)
    rng = random.Random(seed)
    w = weights(zone_id, all_entrants, winrates,
                exploration_floor=exploration_floor)
    selected = [e for e in all_entrants if rng.random() < w[e.label]]
    if not selected:
        selected = [max(all_entrants, key=lambda e: w[e.label])]
    return selected


__all__ = ["select_entrants", "weights"]
```
- [ ] Run the test, verify it passes: `uv run pytest test/test_red_entrant_selection.py -q` — expect `5 passed`.
- [ ] Run lint: `uv run ruff check red_team/entrant_selection.py test/test_red_entrant_selection.py` — expect `All checks passed!`.
- [ ] Commit: `git add red_team/entrant_selection.py test/test_red_entrant_selection.py && git commit -m "feat(tournament): win-rate entrant routing with exploration floor"`.

---

# Phase 4 — Pipeline wiring

`generate_ideas()` integration, the config additions, and the dashboard panel.

## Task 9 — Config block

**Files:**
- Modify: `configs/monkeyclaw.yaml`
- Modify: `red_team/tournament.py`
- Test: `test/test_config.py` (extend)

- [ ] Write the failing test. Append to `test/test_config.py`:
```python
def test_model_tournament_config_gains_routing_keys():
    import yaml
    from pathlib import Path
    cfg = yaml.safe_load(Path("configs/monkeyclaw.yaml").read_text())
    mt = cfg["red_team"]["model_tournament"]
    assert mt["enabled"] is False  # disabled-by-default unchanged
    assert mt["tournament_zones_per_cycle"] == 1
    assert mt["h2h_weight"] == 0.6
    assert mt["exploration_floor"] == 0.1


def test_load_tournament_config_reads_routing_keys():
    from red_team.tournament import load_tournament_config
    cfg = load_tournament_config()
    assert cfg.tournament_zones_per_cycle == 1
    assert cfg.h2h_weight == 0.6
    assert cfg.exploration_floor == 0.1
```
- [ ] Run it, verify it fails: `uv run pytest test/test_config.py -k "model_tournament_config or tournament_config_reads" -q` — expect `KeyError`/`AttributeError`.
- [ ] Extend the `red_team.model_tournament` block in `configs/monkeyclaw.yaml` (keep `enabled`/`entrants` as-is, add the three keys):
```yaml
    model_tournament:
      enabled: false
      tournament_zones_per_cycle: 1
      h2h_weight: 0.6
      exploration_floor: 0.1
      entrants:
        - role: red_ideation
        - role: cyber_specialist_optional
        - role: frontier_creative_optional
```
- [ ] Add the three fields to `ModelTournamentConfig` in `red_team/tournament.py`:
```python
@dataclass
class ModelTournamentConfig:
    enabled: bool = False
    entrants: list[Entrant] = field(default_factory=list)
    tournament_zones_per_cycle: int = 1
    h2h_weight: float = 0.6
    exploration_floor: float = 0.1
```
- [ ] Extend `_coerce_config` in `red_team/tournament.py` to read the three keys (with the same defaults) and pass them to the `ModelTournamentConfig(...)` constructor:
```python
    return ModelTournamentConfig(
        enabled=bool(raw.get("enabled", False)),
        entrants=entrants,
        tournament_zones_per_cycle=int(
            raw.get("tournament_zones_per_cycle", 1)),
        h2h_weight=float(raw.get("h2h_weight", 0.6)),
        exploration_floor=float(raw.get("exploration_floor", 0.1)),
    )
```
- [ ] Run the test, verify it passes: `uv run pytest test/test_config.py -q` — expect all green.
- [ ] Run lint: `uv run ruff check red_team/tournament.py configs/monkeyclaw.yaml test/test_config.py 2>/dev/null; uv run ruff check red_team/tournament.py test/test_config.py` — expect `All checks passed!`.
- [ ] Commit: `git add configs/monkeyclaw.yaml red_team/tournament.py test/test_config.py && git commit -m "feat(tournament): routing config keys"`.

## Task 10 — generate_ideas() integration

**Files:**
- Modify: `red_team/pipeline.py`
- Test: `test/test_red_pipeline_e2e.py` (extend)

- [ ] Write the failing test. Append to `test/test_red_pipeline_e2e.py`:
```python
def test_tournament_disabled_pipeline_is_single_model(server):
    """Disabled tournament -> the single-model ideation path, unchanged."""
    from red_team.pipeline import Pipeline  # match the file's class name

    pipeline = Pipeline.for_mock(mcp=server, tournament_enabled=False)
    ideas = pipeline.generate_ideas(zone_id="planted-filesystem", cycle_id=1)
    assert ideas  # ideas produced, no tournament machinery touched
    assert all(getattr(i, "model_label", "") in ("", "red_ideation")
               for i in ideas)


def test_tournament_enabled_pipeline_judges_and_persists_a_round(server):
    """Enabled tournament -> entrants fan out, a head-to-head round is
    judged and persisted, win-rates are written."""
    from red_team.pipeline import Pipeline

    pipeline = Pipeline.for_mock(mcp=server, tournament_enabled=True)
    pipeline.generate_ideas(zone_id="planted-filesystem", cycle_id=1)
    rounds = server.db.fetchall(
        "SELECT * FROM model_tournament_rounds "
        "WHERE zone_id='planted-filesystem'")
    assert len(rounds) >= 1
```
> `Pipeline.for_mock(...)` is a shorthand for whatever the test file already uses to build a mock-mode pipeline — adapt to the existing construction helper. If `red_team/pipeline.py` exposes a function (`run_red_cycle`, `generate_ideas`) rather than a `Pipeline` class, target that surface instead; the assertions (a round row exists when enabled, single-model when disabled) are what matters.
- [ ] Run it, verify it fails: `uv run pytest test/test_red_pipeline_e2e.py -k tournament -q` — expect `AssertionError` (no round persisted) or an integration error.
- [ ] In `red_team/pipeline.py`, extend `generate_ideas()`. Add the imports at the top:
```python
from red_team.entrant_selection import select_entrants
from red_team.ideation_tournament import IdeationTournamentJudge
```
- [ ] In `generate_ideas()`, when the tournament is enabled and the zone is within `tournament_zones_per_cycle`, replace the bare `tournament_ideas(...)` call with the selection + judging flow:
```python
        if self.tournament.enabled:
            # 1. route: which entrants run this zone this cycle.
            winrates = []
            try:
                winrates = self.mcp.get_model_zone_winrate(zone_id)
            except Exception as e:  # noqa: BLE001 - cold start tolerated
                LOG.warning("could not load win-rates for %s: %r",
                            zone_id, e)
            self.tournament.load_winrates(winrates)
            entrants = select_entrants(
                zone_id, self.tournament.cfg.entrants, winrates,
                exploration_floor=self.tournament.cfg.exploration_floor,
                seed=cycle_id,
            )
            # 2. fan out: each selected entrant generates a tagged idea set.
            per_entrant: dict[str, list] = {}

            def _gen(entrant):
                ideas = self._three_mode_ideation(
                    zone_id, self._llm_for_entrant(entrant))
                per_entrant[entrant.label] = ideas
                return ideas

            merged = self.tournament.generate_for(entrants, _gen)
            # 3. head-to-head judge the entrant idea sets, persist the round.
            judge = IdeationTournamentJudge(
                self._llm_for_role("semantic_judge"), mcp=self.mcp,
                h2h_weight=self.tournament.cfg.h2h_weight,
            )
            self._pending_round = judge.judge_round(
                zone_id, cycle_id, per_entrant)
            self._pending_judge = judge
            self._pending_winrate_prior = {
                (w.zone_id, w.model_label): w for w in winrates}
            return merged
```
> `ModelTournament.generate()` today fans out across `self.cfg.entrants`. Add a thin `generate_for(entrants, generate_fn)` method to `red_team/tournament.py` that does exactly what `generate()` does but over a caller-supplied entrant list (extract the loop body, keep `generate()` as `self.generate_for(self.cfg.entrants, fn)`); the per-zone routing needs to fan out over the selected subset, not the full config.
- [ ] Add the post-judgment win-rate update to `red_team/pipeline.py` — after the zone's ideas are executed and judged, fold the execution outcomes into the win-rate. In whatever method runs after judging (the plan calls it `record_zone_outcomes`), add:
```python
    def record_zone_outcomes(self, zone_id: str, cycle_id: int,
                             judged) -> None:
        # ... existing per-idea record_outcome calls, now passing zone_id ...
        for jr in judged:
            label = getattr(jr.idea, "model_label", "")
            if label:
                self.tournament.record_outcome(
                    label, verdict=jr.verdict, zone_id=zone_id)
        # fold the head-to-head round + execution outcomes into the win-rate.
        if getattr(self, "_pending_round", None) is not None:
            execution_outcomes: dict[str, dict[str, int]] = {}
            for jr in judged:
                label = getattr(jr.idea, "model_label", "")
                if not label:
                    continue
                row = execution_outcomes.setdefault(
                    label, {"confirmed": 0, "suspicious": 0,
                            "ideas_executed": 0})
                row["ideas_executed"] += 1
                if jr.verdict == "confirmed":
                    row["confirmed"] += 1
                elif jr.verdict == "suspicious":
                    row["suspicious"] += 1
            self._pending_judge.update_winrate(
                self._pending_round, execution_outcomes,
                prior=self._pending_winrate_prior)
            self._pending_round = None
```
> Adapt member/attribute names (`jr.idea`, `jr.verdict`, `judged`) to whatever the pipeline's judged-result objects already use. The behaviour to wire is: per-idea `record_outcome` carries `zone_id`, and after the zone is judged `update_winrate` runs once with the execution outcomes and the persisted prior.
- [ ] Run the test, verify it passes: `uv run pytest test/test_red_pipeline_e2e.py -k tournament -q` — expect `2 passed`.
- [ ] Run lint: `uv run ruff check red_team/pipeline.py red_team/tournament.py test/test_red_pipeline_e2e.py` — expect `All checks passed!`.
- [ ] Commit: `git add red_team/pipeline.py red_team/tournament.py test/test_red_pipeline_e2e.py && git commit -m "feat(tournament): wire selection + head-to-head + win-rate into generate_ideas"`.

## Task 11 — Dashboard panel

**Files:**
- Modify: `infra/dashboard.py`
- Test: `test/test_dashboard.py` (extend)

- [ ] Write the failing test. Append to `test/test_dashboard.py`:
```python
def test_dashboard_exposes_model_winrate_panel(server):
    from infra.dashboard import build_dashboard_state
    from interfaces.types import ModelZoneWinrate, TournamentRound

    server.update_model_zone_winrate(ModelZoneWinrate(
        zone_id="SBX-FS", model_label="nemotron", role="red_ideation",
        h2h_wins=3, h2h_comparisons=4, confirmed=2, suspicious=1,
        ideas_executed=5, winrate=0.74))
    server.log_tournament_round(TournamentRound(
        round_id="", cycle_id=1, zone_id="SBX-FS",
        entrants=["nemotron", "frontier"],
        pairwise=[{"a": "nemotron", "b": "frontier",
                   "winner": "nemotron", "margin": 0.4}],
        winner_label="nemotron"))
    state = build_dashboard_state(server)
    assert "model_tournament" in state
    panel = state["model_tournament"]
    assert panel["winrates"]
    assert panel["winrates"][0]["model_label"] == "nemotron"
    assert panel["recent_rounds"]
```
- [ ] Run it, verify it fails: `uv run pytest test/test_dashboard.py -k model_winrate_panel -q` — expect `KeyError`.
- [ ] In `infra/dashboard.py`, extend the dashboard-state builder to add a `model_tournament` key (match the builder's actual name; the plan calls it `build_dashboard_state`):
```python
    winrate_rows = mcp.get_model_zone_winrate()
    round_rows = mcp.db.fetchall(
        "SELECT zone_id, cycle_id, entrants, winner_label, created_at "
        "FROM model_tournament_rounds ORDER BY created_at DESC LIMIT 10")
    state["model_tournament"] = {
        "winrates": sorted(
            ({"zone_id": w.zone_id, "model_label": w.model_label,
              "winrate": w.winrate, "h2h_wins": w.h2h_wins,
              "h2h_comparisons": w.h2h_comparisons,
              "confirmed": w.confirmed,
              "ideas_executed": w.ideas_executed}
             for w in winrate_rows),
            key=lambda r: -r["winrate"]),
        "recent_rounds": [
            {"zone_id": r["zone_id"], "cycle_id": r["cycle_id"],
             "winner": r["winner_label"]}
            for r in round_rows
        ],
    }
```
- [ ] Run the test, verify it passes: `uv run pytest test/test_dashboard.py -k model_winrate_panel -q` — expect `1 passed`.
- [ ] Run lint: `uv run ruff check infra/dashboard.py test/test_dashboard.py` — expect `All checks passed!`.
- [ ] Commit: `git add infra/dashboard.py test/test_dashboard.py && git commit -m "feat(tournament): per-zone model win-rate dashboard panel"`.

## Task 12 — End-to-end cycle

**Files:**
- Create: `test/test_red_tournament_pipeline_e2e.py`

- [ ] Write the end-to-end test. Create `test/test_red_tournament_pipeline_e2e.py`:
```python
"""Model ideation tournament — one full red cycle in mock mode with the
tournament enabled (model-ideation-tournament spec §13)."""

from __future__ import annotations

from red_team.pipeline import Pipeline  # match the file's class name


def test_full_cycle_with_tournament_enabled(server):
    pipeline = Pipeline.for_mock(mcp=server, tournament_enabled=True)
    result = pipeline.run_cycle(zone_id="planted-filesystem", cycle_id=1)

    # multiple entrants generated -> ideas carry distinct model labels.
    labels = {getattr(i, "model_label", "") for i in result.ideas}
    assert len([lbl for lbl in labels if lbl]) >= 1

    # a head-to-head round was judged and persisted.
    rounds = server.db.fetchall(
        "SELECT * FROM model_tournament_rounds "
        "WHERE zone_id='planted-filesystem'")
    assert len(rounds) >= 1

    # win-rates were written for this zone.
    winrates = server.get_model_zone_winrate("planted-filesystem")
    assert len(winrates) >= 1
    assert all(0.0 <= w.winrate <= 1.0 for w in winrates)


def test_disabled_tournament_reproduces_single_model_cycle(server):
    pipeline = Pipeline.for_mock(mcp=server, tournament_enabled=False)
    result = pipeline.run_cycle(zone_id="planted-filesystem", cycle_id=1)
    # no tournament rounds, no win-rate rows — the single-model path.
    assert server.db.fetchall("SELECT * FROM model_tournament_rounds") == []
    assert server.get_model_zone_winrate() == []
    assert result.ideas  # the cycle still produced ideas
```
> Adapt `Pipeline.for_mock` / `run_cycle` / `result.ideas` to the pipeline's actual mock-mode construction and run surface — the load-bearing assertions are: enabled → a round + win-rate rows exist; disabled → neither table is touched and the cycle still produces ideas.
- [ ] Run it, verify it passes: `uv run pytest test/test_red_tournament_pipeline_e2e.py -q` — expect `2 passed`.
- [ ] Run the full suite to confirm nothing regressed: `uv run pytest -q` — expect all green (the pre-existing count plus the new tests).
- [ ] Run lint across the whole tree: `uv run ruff check .` — expect `All checks passed!`.
- [ ] Commit: `git add test/test_red_tournament_pipeline_e2e.py && git commit -m "test(tournament): end-to-end enabled + disabled cycle"`.

---

# Verification checklist

- [ ] `uv run pytest -q` — full suite green, mock mode, zero credentials.
- [ ] `uv run ruff check .` — `All checks passed!`.
- [ ] Tournament disabled (`red_team.model_tournament.enabled: false`, the default) is a strict no-op — verified by `test_disabled_tournament_reproduces_single_model_cycle`: no `model_tournament_rounds` rows, no `model_zone_winrate` rows, single-model ideation.
- [ ] An optional entrant's failure never breaks a cycle — the head-to-head round treats a missing/empty idea set as a forfeit (`test_judge_round_treats_empty_idea_set_as_forfeit`).
- [ ] `uv run monkeyclaw run --cycles 1 --target planted-filesystem --mock` completes — the demo path still works.
- [ ] Migration 0005 applies on a fresh DB and on an existing schema_version-2 DB; `schema.sql` and the migration agree.
- [ ] Entrant roles resolve through `make_llm(role)` (constraint 5) — `_llm_for_entrant()` / `_llm_for_role()` use the model-routing surface, never a hardcoded model ID.
