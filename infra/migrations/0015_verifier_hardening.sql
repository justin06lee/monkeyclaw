-- Migration 0015 — verifier gate hardening result tables
-- (verifier-gate-hardening spec §7). Forward-only, idempotent.
-- The runner wraps this body in its own BEGIN/COMMIT and records the
-- schema_version; do not add a transaction or schema_meta update here.

CREATE TABLE IF NOT EXISTS patch_variant_results (
    result_id     TEXT PRIMARY KEY,
    patch_id      TEXT NOT NULL,
    vuln_id       TEXT NOT NULL,
    operator      TEXT NOT NULL,
    variant_hash  TEXT NOT NULL,
    blocked       INTEGER NOT NULL DEFAULT 0,   -- 0|1
    judge_verdict TEXT NOT NULL,
    created_at    TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_patch_variant_results_patch
    ON patch_variant_results(patch_id);

CREATE TABLE IF NOT EXISTS patch_detection_results (
    result_id     TEXT PRIMARY KEY,
    patch_id      TEXT NOT NULL,
    vuln_id       TEXT NOT NULL,
    zone_id       TEXT NOT NULL,
    quadrant      TEXT NOT NULL,                -- PASS|PARTIAL|WEAK|FAIL
    observability TEXT NOT NULL,
    prevention    TEXT NOT NULL,
    passed        INTEGER NOT NULL DEFAULT 0,   -- 0|1
    evidence      TEXT NOT NULL DEFAULT '{}',
    created_at    TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_patch_detection_results_patch
    ON patch_detection_results(patch_id);
