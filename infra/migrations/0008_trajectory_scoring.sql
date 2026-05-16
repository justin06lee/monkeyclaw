-- Migration 0008 — trajectory + near-miss tables (trajectory spec §8).
-- Forward-only, idempotent. Applied by infra/migrations.py on Database open.
-- The runner wraps this body in its own BEGIN/COMMIT; do not add one here.

CREATE TABLE IF NOT EXISTS trajectory_scores (
    trajectory_id   TEXT PRIMARY KEY,
    lane_id         TEXT NOT NULL,
    idea_id         TEXT NOT NULL,
    zone_id         TEXT NOT NULL,
    max_stage       INTEGER NOT NULL DEFAULT 0,
    final_stage     INTEGER NOT NULL DEFAULT 0,
    erosion_slope   REAL NOT NULL DEFAULT 0.0,
    stalled_at_turn INTEGER NOT NULL DEFAULT -1,
    monotonic       INTEGER NOT NULL DEFAULT 1,   -- 0/1
    turn_scores     TEXT NOT NULL DEFAULT '[]',   -- JSON list of TurnScore
    created_at      TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_trajectory_scores_zone_idea
    ON trajectory_scores(zone_id, idea_id);

CREATE TABLE IF NOT EXISTS near_misses (
    near_miss_id      TEXT PRIMARY KEY,
    idea_id           TEXT NOT NULL,
    lane_id           TEXT NOT NULL,
    zone_id           TEXT NOT NULL,
    max_stage         INTEGER NOT NULL DEFAULT 0,
    stalled_at_turn   INTEGER NOT NULL DEFAULT -1,
    erosion_excerpt   TEXT NOT NULL DEFAULT '',
    useful_components TEXT NOT NULL DEFAULT '[]', -- JSON list
    mutation_seeds    TEXT NOT NULL DEFAULT '[]', -- JSON list
    consumed          INTEGER NOT NULL DEFAULT 0, -- 0/1
    created_at        TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_near_misses_zone_consumed
    ON near_misses(zone_id, consumed);
