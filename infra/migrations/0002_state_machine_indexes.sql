-- 0002_state_machine_indexes.sql — covering indexes for the FSM queries.
-- idx_repro_queue_status, idx_findings_status and idx_patches_status already
-- exist in schema.sql; these IF NOT EXISTS statements make 0002 a verified
-- no-op kept for ordinal continuity and documentation.
CREATE INDEX IF NOT EXISTS idx_repro_queue_status
    ON repro_queue(status, priority DESC, enqueued_at);
CREATE INDEX IF NOT EXISTS idx_findings_status ON findings(patch_status);
CREATE INDEX IF NOT EXISTS idx_patches_status ON patches(status);
