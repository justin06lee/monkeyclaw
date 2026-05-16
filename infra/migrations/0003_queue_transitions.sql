-- 0003_queue_transitions.sql — audit trail of every status transition.
CREATE TABLE IF NOT EXISTS queue_transitions (
    transition_id  TEXT PRIMARY KEY,
    entity         TEXT NOT NULL,
    entity_id      TEXT NOT NULL,
    from_state     TEXT,
    to_state       TEXT NOT NULL,
    actor          TEXT NOT NULL,
    reason         TEXT NOT NULL DEFAULT '',
    created_at     TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_queue_transitions_entity
    ON queue_transitions(entity, entity_id, created_at);
