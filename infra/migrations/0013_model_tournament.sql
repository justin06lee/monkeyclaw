-- Migration 0013 — model ideation tournament tables
-- (model-ideation-tournament spec §9). Forward-only, idempotent.
-- The runner wraps this script in BEGIN/COMMIT and records schema_version.

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
