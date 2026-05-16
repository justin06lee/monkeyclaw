-- Migration 0020 — attack_skills preloaded ideation priors (Mode E) +
-- agent_events live dashboard stream.
-- Forward-only, idempotent. Applied by infra/migrations runner on Database open.
-- The runner wraps this body in its own BEGIN/COMMIT and records schema_version.
-- attack_skills is a derived index over red_team/attack_skills/*.yaml (the
-- source of truth), seeded at bootstrap by infra.seed_attack_skills.

CREATE TABLE IF NOT EXISTS agent_events (
    event_id      TEXT PRIMARY KEY,
    session_id    TEXT NOT NULL,
    agent_id      TEXT NOT NULL,
    agent_kind    TEXT NOT NULL,
    event_type    TEXT NOT NULL,
    role          TEXT,
    cycle_id      INTEGER,
    lane_id       TEXT,
    idea_id       TEXT,
    model         TEXT,
    provider      TEXT,
    text          TEXT,
    tool_name     TEXT,
    status        TEXT,
    metadata      TEXT NOT NULL DEFAULT '{}',
    created_at    TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_agent_events_session
    ON agent_events(session_id, created_at);
CREATE INDEX IF NOT EXISTS idx_agent_events_agent
    ON agent_events(agent_id, created_at);

CREATE TABLE IF NOT EXISTS attack_skills (
    skill_id                   TEXT PRIMARY KEY,
    name                       TEXT NOT NULL,
    kind                       TEXT NOT NULL DEFAULT 'pattern',  -- pattern|modifier
    provenance                 TEXT NOT NULL,                    -- research|extrapolated
    sources                    TEXT NOT NULL DEFAULT '[]',       -- JSON list
    zone_ids                   TEXT NOT NULL,                    -- JSON list
    failure_class              TEXT NOT NULL,
    interaction_style          TEXT NOT NULL,
    target_defense             TEXT NOT NULL,
    tactic_tags                TEXT NOT NULL DEFAULT '[]',        -- JSON list
    severity_hint              TEXT NOT NULL,
    estimated_turns            INTEGER NOT NULL DEFAULT 5,
    preconditions              TEXT NOT NULL DEFAULT '',
    technique                  TEXT NOT NULL,
    approach_template          TEXT NOT NULL,
    success_criteria_template  TEXT NOT NULL,
    example_payloads           TEXT NOT NULL DEFAULT '[]',        -- JSON list
    variants                   TEXT NOT NULL DEFAULT '[]',        -- JSON list
    expected_observables       TEXT NOT NULL DEFAULT '[]',        -- JSON list
    mutation_seeds             TEXT NOT NULL DEFAULT '[]',        -- JSON list
    content_hash               TEXT NOT NULL,
    created_at                 TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at                 TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_attack_skills_kind ON attack_skills(kind);

-- Vector index over (name + technique + approach_template) for zone retrieval.
CREATE VIRTUAL TABLE IF NOT EXISTS attack_skills_vec USING vec0(
    skill_id  TEXT PRIMARY KEY,
    embedding FLOAT[384]
);
