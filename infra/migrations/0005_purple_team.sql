-- Migration 0005 — purple-team detection tables (purple-team spec §8).
-- Forward-only, idempotent. Applied by infra/migrations on Database open.
-- The runner wraps this body in its own BEGIN/COMMIT, so no transaction
-- statements appear here.

CREATE TABLE IF NOT EXISTS detection_rules (
    rule_id                       TEXT PRIMARY KEY,
    zone_id                       TEXT NOT NULL,
    source_finding_id             TEXT NOT NULL,
    logic                         TEXT NOT NULL,
    expected_telemetry_signature  TEXT NOT NULL,
    response_action               TEXT NOT NULL,
    status                        TEXT NOT NULL DEFAULT 'candidate',
    created_at                    TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_detection_rules_zone
    ON detection_rules(zone_id, status);

CREATE TABLE IF NOT EXISTS detection_results (
    result_id      TEXT PRIMARY KEY,
    session_id     TEXT NOT NULL,
    execution_id   TEXT NOT NULL,
    zone_id        TEXT NOT NULL,
    quadrant       TEXT NOT NULL,            -- PASS|PARTIAL|WEAK|FAIL
    prevention     TEXT NOT NULL,            -- blocked|succeeded
    observability  TEXT NOT NULL,            -- observed|silent|unknown
    rule_id        TEXT,
    evidence       TEXT NOT NULL DEFAULT '{}',
    created_at     TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_detection_results_zone
    ON detection_results(zone_id, created_at);
CREATE INDEX IF NOT EXISTS idx_detection_results_session
    ON detection_results(session_id);

CREATE TABLE IF NOT EXISTS detection_coverage (
    zone_id        TEXT PRIMARY KEY,
    coverage_score REAL NOT NULL DEFAULT 0.0,
    sample_count   INTEGER NOT NULL DEFAULT 0,
    updated_at     TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS control_validation_runs (
    run_id          TEXT PRIMARY KEY,
    kind            TEXT NOT NULL,           -- inline|full
    cases_total     INTEGER NOT NULL DEFAULT 0,
    cases_passed    INTEGER NOT NULL DEFAULT 0,
    regressions     TEXT NOT NULL DEFAULT '[]',
    victim_build_id TEXT NOT NULL DEFAULT 'mock',
    status          TEXT NOT NULL DEFAULT 'ok',  -- ok|errored
    created_at      TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_control_validation_kind
    ON control_validation_runs(kind, created_at);

CREATE TABLE IF NOT EXISTS report_cards (
    card_id      TEXT PRIMARY KEY,
    generated_at TEXT NOT NULL DEFAULT (datetime('now')),
    dimensions   TEXT NOT NULL DEFAULT '[]',
    summary      TEXT NOT NULL DEFAULT ''
);
