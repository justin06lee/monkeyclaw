-- Migration 0017 — approval_events audit table (approval spec §9).
-- Forward-only, idempotent. Applied by infra/migrations runner on Database open.
-- The runner wraps this body in its own BEGIN/COMMIT and records schema_version.
-- Append-only at the application layer.

CREATE TABLE IF NOT EXISTS approval_events (
    event_id              TEXT PRIMARY KEY,
    request_id            TEXT NOT NULL,
    patch_id              TEXT NOT NULL,
    vuln_ids              TEXT NOT NULL DEFAULT '[]',  -- JSON list
    zone_id               TEXT NOT NULL,
    severity              TEXT NOT NULL,
    decision              TEXT NOT NULL,            -- ask|allow|deny|expired
    posture               TEXT NOT NULL,            -- auto_allow|require_approval
    approver              TEXT NOT NULL,            -- operator id or 'system'
    reason                TEXT NOT NULL DEFAULT '',
    ask_expiry            TEXT,
    grant_expiry          TEXT,
    generalization_status TEXT,                     -- generalized|unconverged
    pr_url                TEXT,
    created_at            TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_approval_events_decision
    ON approval_events(decision, created_at);
CREATE INDEX IF NOT EXISTS idx_approval_events_patch
    ON approval_events(patch_id);
CREATE INDEX IF NOT EXISTS idx_approval_events_request
    ON approval_events(request_id);
