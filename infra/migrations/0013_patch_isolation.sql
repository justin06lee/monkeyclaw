-- Migration 0013 — patch-isolation build audit table (patch-isolation §7).
-- Forward-only, idempotent. Applied by infra/migrations runner on Database open.
-- NOTE: placeholder ordinal — renumbered at merge time per the upgrade roadmap.
-- The runner wraps this body in its own BEGIN/COMMIT and records schema_version.

CREATE TABLE IF NOT EXISTS patch_builds (
    build_id                TEXT PRIMARY KEY,
    patch_id                TEXT NOT NULL,
    base_ref                TEXT,
    worktree_path           TEXT,
    diff_applied            INTEGER NOT NULL DEFAULT 0,  -- 0/1
    rejected_hunks          TEXT NOT NULL DEFAULT '[]',  -- JSON list
    build_status            TEXT NOT NULL,               -- built|apply_failed|build_failed|mock
    victim_instance_id      TEXT,
    isolation_mode          TEXT NOT NULL DEFAULT 'mock',  -- live|mock
    build_duration_seconds  REAL NOT NULL DEFAULT 0.0,
    torn_down               INTEGER NOT NULL DEFAULT 0,  -- 0/1
    created_at              TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_patch_builds_patch
    ON patch_builds(patch_id);
CREATE INDEX IF NOT EXISTS idx_patch_builds_torn_down
    ON patch_builds(torn_down);
