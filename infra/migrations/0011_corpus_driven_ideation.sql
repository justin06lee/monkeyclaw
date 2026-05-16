-- Migration 0011 — corpus-driven ideation technique tables
-- (corpus-driven-ideation spec §8). Forward-only, idempotent.

CREATE TABLE IF NOT EXISTS idea_techniques (
    idea_id        TEXT NOT NULL,
    technique_kind TEXT NOT NULL,            -- atlas|owasp
    technique_id   TEXT NOT NULL,
    corpus_version TEXT NOT NULL,
    resolved_by    TEXT NOT NULL,            -- model|keyword
    created_at     TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_idea_techniques_idea
    ON idea_techniques(idea_id);
CREATE INDEX IF NOT EXISTS idx_idea_techniques_technique
    ON idea_techniques(technique_kind, technique_id);

CREATE TABLE IF NOT EXISTS finding_techniques (
    finding_id     TEXT NOT NULL,
    technique_kind TEXT NOT NULL,
    technique_id   TEXT NOT NULL,
    corpus_version TEXT NOT NULL,
    resolved_by    TEXT NOT NULL,
    created_at     TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_finding_techniques_finding
    ON finding_techniques(finding_id);
CREATE INDEX IF NOT EXISTS idx_finding_techniques_technique
    ON finding_techniques(technique_kind, technique_id);

CREATE TABLE IF NOT EXISTS technique_coverage (
    zone_id        TEXT NOT NULL,
    technique_kind TEXT NOT NULL,
    technique_id   TEXT NOT NULL,
    attempts       INTEGER NOT NULL DEFAULT 0,
    confirmations  INTEGER NOT NULL DEFAULT 0,
    last_seen_at   TEXT NOT NULL DEFAULT (datetime('now')),
    PRIMARY KEY (zone_id, technique_kind, technique_id)
);

UPDATE schema_meta SET value = '11' WHERE key = 'schema_version';
INSERT OR REPLACE INTO schema_meta (key, value)
    VALUES ('taxonomy_corpus_version', 'atlas-5.4.0+owasp-2025');
