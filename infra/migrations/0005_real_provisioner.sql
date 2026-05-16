-- 0005_real_provisioner.sql — real-provisioner tables (real-nemoclaw-provisioner spec §8).
-- Forward-only, idempotent. Applied by infra/migrations runner on Database open.
-- NOTE: placeholder ordinal — renumbered at merge time per the upgrade roadmap.
-- The runner wraps this body in its own BEGIN/COMMIT and records schema_version.

CREATE TABLE IF NOT EXISTS victim_snapshots (
    snapshot_id    TEXT PRIMARY KEY,
    name           TEXT NOT NULL,
    sandbox_id     TEXT NOT NULL,
    deterministic  INTEGER NOT NULL DEFAULT 0,   -- 0/1
    patched        INTEGER NOT NULL DEFAULT 0,   -- 0/1
    base_snapshot  TEXT,
    created_at     TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_victim_snapshots_name
    ON victim_snapshots(name);

CREATE TABLE IF NOT EXISTS sandbox_runs (
    run_id          TEXT PRIMARY KEY,
    instance_id     TEXT NOT NULL,
    lane_id         TEXT,
    mode            TEXT NOT NULL,               -- ephemeral|recover_only|mock
    deterministic   INTEGER NOT NULL DEFAULT 0,  -- 0/1
    patch_applied   INTEGER NOT NULL DEFAULT 0,  -- 0/1
    capabilities    TEXT NOT NULL DEFAULT '{}',  -- JSON SandboxCapabilities
    provisioned_at  TEXT NOT NULL DEFAULT (datetime('now')),
    torn_down_at    TEXT
);
CREATE INDEX IF NOT EXISTS idx_sandbox_runs_lane
    ON sandbox_runs(lane_id);
