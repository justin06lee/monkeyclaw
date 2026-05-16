-- Migration 0017 — patch generalization loop (patch-generalization-loop §11).
-- Forward-only, idempotent. Applied by infra/migrations runner on Database open.
-- The runner wraps this body in its own BEGIN/COMMIT and records schema_version.

CREATE TABLE IF NOT EXISTS generalization_rounds (
    round_id              TEXT PRIMARY KEY,
    patch_id              TEXT NOT NULL,
    finding_id            TEXT NOT NULL,
    vuln_id               TEXT NOT NULL,
    zone_id               TEXT NOT NULL,
    round_index           INTEGER NOT NULL,
    operators_tried       TEXT NOT NULL DEFAULT '[]',   -- JSON list
    variants_total        INTEGER NOT NULL DEFAULT 0,
    variants_bypassed     INTEGER NOT NULL DEFAULT 0,
    variants_inconclusive INTEGER NOT NULL DEFAULT 0,
    bypass_operators      TEXT NOT NULL DEFAULT '[]',   -- JSON list
    outcome               TEXT NOT NULL,                -- generalized|bounced|unconverged
    repatch_patch_id      TEXT,
    evidence              TEXT NOT NULL DEFAULT '[]',   -- JSON list
    created_at            TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_generalization_rounds_finding
    ON generalization_rounds(finding_id, round_index);
CREATE INDEX IF NOT EXISTS idx_generalization_rounds_patch
    ON generalization_rounds(patch_id);
