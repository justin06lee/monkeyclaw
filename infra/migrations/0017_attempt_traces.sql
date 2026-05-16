-- Migration 0017 — learned-ranking trace tables (learned-ranking spec §7).
-- Forward-only, idempotent. Applied by infra/migrations.py on Database open.
-- The runner wraps this body in its own BEGIN/COMMIT and records the
-- schema_version; do not add a transaction or schema_version update here.

CREATE TABLE IF NOT EXISTS attempt_traces (
    trace_id               TEXT PRIMARY KEY,
    idea_id                TEXT NOT NULL,
    finding_id             TEXT,
    cycle_id               INTEGER NOT NULL,
    zone_id                TEXT NOT NULL,
    feature_schema_version INTEGER NOT NULL DEFAULT 1,
    idea_summary           TEXT NOT NULL DEFAULT '',
    tactic_tags            TEXT NOT NULL DEFAULT '[]',  -- JSON list
    mutation_operator      TEXT,
    interaction_style      TEXT NOT NULL DEFAULT 'direct',
    progress_dims          TEXT NOT NULL DEFAULT '{}',  -- JSON object
    judge_scores           TEXT NOT NULL DEFAULT '{}',  -- JSON object
    token_cost             INTEGER NOT NULL DEFAULT 0,
    repro_outcome          TEXT NOT NULL DEFAULT 'pending',
    judge_verdict          TEXT NOT NULL DEFAULT 'clean',
    search_score           REAL NOT NULL DEFAULT 0.0,
    archive_niche          TEXT NOT NULL DEFAULT '',
    usefulness_label       REAL NOT NULL DEFAULT 0.0,
    created_at             TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_attempt_traces_zone
    ON attempt_traces(zone_id, created_at);
CREATE INDEX IF NOT EXISTS idx_attempt_traces_repro
    ON attempt_traces(repro_outcome);

CREATE TABLE IF NOT EXISTS pairwise_labels (
    pair_id          TEXT PRIMARY KEY,
    trace_a          TEXT NOT NULL,
    trace_b          TEXT NOT NULL,
    preferred        TEXT NOT NULL,            -- a | b | tie
    judge_confidence REAL NOT NULL DEFAULT 0.0,
    created_at       TEXT NOT NULL DEFAULT (datetime('now'))
);

INSERT OR IGNORE INTO schema_meta(key, value)
    VALUES ('feature_schema_version', '1');
