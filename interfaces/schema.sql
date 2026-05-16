-- MonkeyClaw database schema — Contract owned by Person 1.
--
-- After Day-1 sign-off this file is frozen. Changes go through migration scripts
-- in infra/migrations/ — never edit a column in-place.
--
-- All embeddings are 384-dim float32 (sentence-transformers all-MiniLM-L6-v2).
-- Vector tables use sqlite-vec's vec0 virtual table extension.

PRAGMA journal_mode = WAL;
PRAGMA synchronous = NORMAL;
PRAGMA foreign_keys = ON;
PRAGMA temp_store = MEMORY;

--------------------------------------------------------------------------------
-- surface_zones — the attack surface map (spec §4.2, §4.3)
--------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS surface_zones (
    zone_id              TEXT PRIMARY KEY,
    name                 TEXT NOT NULL,
    description          TEXT NOT NULL,
    severity_weight      REAL NOT NULL DEFAULT 1.0,        -- 0.3..1.0
    total_cycles         INTEGER NOT NULL DEFAULT 0,
    last_tested_at       TEXT,                              -- ISO-8601
    vulns_found          INTEGER NOT NULL DEFAULT 0,
    vulns_open           INTEGER NOT NULL DEFAULT 0,
    vulns_patched        INTEGER NOT NULL DEFAULT 0,
    coverage_score       REAL NOT NULL DEFAULT 0.0,         -- 0..1
    decay_rate           REAL NOT NULL DEFAULT 0.02,        -- per inactive cycle
    difficulty_estimate  REAL NOT NULL DEFAULT 0.5,
    unique_ideas_tried   INTEGER NOT NULL DEFAULT 0
);

CREATE INDEX IF NOT EXISTS idx_zones_coverage ON surface_zones(coverage_score);

--------------------------------------------------------------------------------
-- findings — every attack outcome (spec §6.1)
--------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS findings (
    finding_id     TEXT PRIMARY KEY,
    cycle_id       INTEGER NOT NULL,
    idea_id        TEXT NOT NULL,
    zone_id        TEXT NOT NULL REFERENCES surface_zones(zone_id),
    source_mode    TEXT NOT NULL,                          -- creative|code_grounded|history_informed
    idea_summary   TEXT NOT NULL,
    verdict        TEXT NOT NULL,                          -- confirmed|suspicious|clean|timeout|error
    tier_caught    TEXT NOT NULL,                          -- programmatic|semantic|none
    failure_class  TEXT NOT NULL,
    severity       TEXT NOT NULL,                          -- critical|high|medium|low
    evidence       TEXT NOT NULL,                          -- JSON blob (list[CheckResult])
    repro_rate     REAL,
    patch_status   TEXT NOT NULL DEFAULT 'open',           -- open|in_progress|patched|verified
    reusability    REAL NOT NULL DEFAULT 0.5,
    created_at     TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_findings_zone     ON findings(zone_id);
CREATE INDEX IF NOT EXISTS idx_findings_verdict  ON findings(verdict);
CREATE INDEX IF NOT EXISTS idx_findings_status   ON findings(patch_status);
CREATE INDEX IF NOT EXISTS idx_findings_cycle    ON findings(cycle_id);
CREATE INDEX IF NOT EXISTS idx_findings_created  ON findings(created_at);

-- Vector index for semantic search over findings (search_findings MCP tool).
-- 384 dimensions = all-MiniLM-L6-v2 output.
CREATE VIRTUAL TABLE IF NOT EXISTS findings_vec USING vec0(
    finding_id   TEXT PRIMARY KEY,
    embedding    FLOAT[384]
);

--------------------------------------------------------------------------------
-- ideas — raw idea log for dedup history (spec §5.5)
--------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS ideas (
    idea_id         TEXT PRIMARY KEY,
    cycle_id        INTEGER NOT NULL,
    zone_id         TEXT NOT NULL REFERENCES surface_zones(zone_id),
    source_mode     TEXT NOT NULL,
    title           TEXT NOT NULL,
    approach        TEXT NOT NULL,
    success_criteria TEXT NOT NULL,
    estimated_turns INTEGER NOT NULL DEFAULT 10,
    novelty_notes   TEXT,
    relevant_files  TEXT,                                   -- JSON list
    code_weakness   TEXT,
    builds_on       TEXT,                                   -- JSON list of finding_ids
    variation_notes TEXT,
    priority_score  REAL NOT NULL DEFAULT 0.0,
    deduplicated    INTEGER NOT NULL DEFAULT 0,             -- 0|1
    created_at      TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_ideas_zone     ON ideas(zone_id);
CREATE INDEX IF NOT EXISTS idx_ideas_dedup    ON ideas(deduplicated);
CREATE INDEX IF NOT EXISTS idx_ideas_priority ON ideas(priority_score DESC);

CREATE VIRTUAL TABLE IF NOT EXISTS ideas_vec USING vec0(
    idea_id   TEXT PRIMARY KEY,
    embedding FLOAT[384]
);

--------------------------------------------------------------------------------
-- cycle_log — compressed cycle summaries (spec §5.7)
--------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS cycle_log (
    cycle_id            INTEGER PRIMARY KEY,
    summary             TEXT NOT NULL,
    zones_targeted      TEXT NOT NULL,                     -- JSON list[zone_id]
    ideas_generated     INTEGER NOT NULL DEFAULT 0,
    ideas_deduplicated  INTEGER NOT NULL DEFAULT 0,
    ideas_executed      INTEGER NOT NULL DEFAULT 0,
    vulns_confirmed     INTEGER NOT NULL DEFAULT 0,
    vulns_suspicious    INTEGER NOT NULL DEFAULT 0,
    total_tokens_used   INTEGER NOT NULL DEFAULT 0,
    wall_time_seconds   REAL NOT NULL DEFAULT 0,
    created_at          TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_cycle_created ON cycle_log(created_at DESC);

--------------------------------------------------------------------------------
-- repro_queue — handoff between red team and repro pipeline
-- A separate table keyed by finding_id (one queue row per finding), so the
-- queue can be drained and re-prioritised without touching the findings row.
-- Atomic dequeue uses UPDATE ... RETURNING on this table.
-- status: queued|processing|completed|failed.
--------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS repro_queue (
    finding_id   TEXT PRIMARY KEY REFERENCES findings(finding_id),
    priority     TEXT NOT NULL DEFAULT 'low',              -- high|low
    status       TEXT NOT NULL DEFAULT 'queued',           -- queued|processing|completed|failed
    enqueued_at  TEXT NOT NULL DEFAULT (datetime('now')),
    dequeued_at  TEXT,
    worker_id    TEXT
);

CREATE INDEX IF NOT EXISTS idx_repro_queue_status
    ON repro_queue(status, priority DESC, enqueued_at);

--------------------------------------------------------------------------------
-- repro_packages — completed reproduction packages (spec §8.4)
--------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS repro_packages (
    package_id           TEXT PRIMARY KEY,
    finding_id           TEXT NOT NULL REFERENCES findings(finding_id),
    vuln_id              TEXT NOT NULL UNIQUE,             -- MC-YYYY-NNNN
    title                TEXT NOT NULL,
    severity             TEXT NOT NULL,
    repro_rate           REAL NOT NULL,
    minimal_steps        TEXT NOT NULL,                    -- JSON list
    affected_zone        TEXT NOT NULL REFERENCES surface_zones(zone_id),
    affected_paths       TEXT,                              -- JSON list[FixSite]
    ideas_used           TEXT NOT NULL,                     -- JSON list
    transcripts          TEXT NOT NULL,                     -- JSON {original,minimal}
    suggested_mitigations TEXT NOT NULL,                    -- JSON list
    repro_document_md    TEXT NOT NULL,
    cold_verified        INTEGER NOT NULL DEFAULT 0,
    ready_for_blue       INTEGER NOT NULL DEFAULT 0,
    blue_team_status     TEXT NOT NULL DEFAULT 'queued',    -- queued|triaged|patching|verified
    created_at           TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_repro_blue_status ON repro_packages(blue_team_status, ready_for_blue);
CREATE INDEX IF NOT EXISTS idx_repro_zone        ON repro_packages(affected_zone);

--------------------------------------------------------------------------------
-- regression_tests — permanent test registry (spec §10)
--------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS regression_tests (
    test_id                    TEXT PRIMARY KEY,
    vuln_id                    TEXT NOT NULL,
    zone_id                    TEXT NOT NULL REFERENCES surface_zones(zone_id),
    test_script                TEXT NOT NULL,
    expected_result            TEXT NOT NULL,
    functionality_test_script  TEXT,
    -- spec C6 third test type: confirms the security telemetry / policy
    -- decision record still exists after a patch (RegressionTestInput).
    policy_regression_test_script TEXT,
    created_at                 TEXT NOT NULL DEFAULT (datetime('now')),
    deprecated                 INTEGER NOT NULL DEFAULT 0,
    last_run_at                TEXT,
    last_run_result            TEXT,
    consecutive_passes         INTEGER NOT NULL DEFAULT 0
);

CREATE INDEX IF NOT EXISTS idx_regression_zone   ON regression_tests(zone_id);
CREATE INDEX IF NOT EXISTS idx_regression_active ON regression_tests(deprecated, zone_id);

--------------------------------------------------------------------------------
-- patches — blue team patch history (spec §9)
--------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS patches (
    patch_id              TEXT PRIMARY KEY,
    vuln_ids              TEXT NOT NULL,                   -- JSON list
    zone_id               TEXT NOT NULL REFERENCES surface_zones(zone_id),
    approach              TEXT NOT NULL,
    invasiveness          TEXT NOT NULL DEFAULT 'medium',
    diff                  TEXT NOT NULL,
    explanation           TEXT NOT NULL,
    side_effects          TEXT,
    status                TEXT NOT NULL DEFAULT 'proposed', -- proposed|testing|approved|rejected|verified
    verification_results  TEXT,                             -- JSON
    created_at            TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_patches_zone   ON patches(zone_id);
CREATE INDEX IF NOT EXISTS idx_patches_status ON patches(status);

--------------------------------------------------------------------------------
-- code_chunks — indexed NemoClaw source for search_codebase MCP tool
--------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS code_chunks (
    chunk_id       TEXT PRIMARY KEY,
    file_path      TEXT NOT NULL,
    function_name  TEXT,
    line_start     INTEGER NOT NULL,
    line_end       INTEGER NOT NULL,
    language       TEXT NOT NULL,
    content        TEXT NOT NULL,
    content_sha256 TEXT NOT NULL,
    indexed_at     TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_code_path ON code_chunks(file_path);
CREATE INDEX IF NOT EXISTS idx_code_lang ON code_chunks(language);

CREATE VIRTUAL TABLE IF NOT EXISTS code_chunks_vec USING vec0(
    chunk_id  TEXT PRIMARY KEY,
    embedding FLOAT[384]
);

--------------------------------------------------------------------------------
-- alerts — outbound notification log (for replay / debugging)
--------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS alerts (
    alert_id    INTEGER PRIMARY KEY AUTOINCREMENT,
    message     TEXT NOT NULL,
    severity    TEXT NOT NULL,
    channel     TEXT NOT NULL,                             -- telegram|webhook|stdout
    delivered   INTEGER NOT NULL DEFAULT 0,
    created_at  TEXT NOT NULL DEFAULT (datetime('now'))
);

--------------------------------------------------------------------------------
-- telemetry_events — A5 session timeline. Bounded excerpts + hashes only.
--------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS telemetry_events (
    event_id      TEXT PRIMARY KEY,
    session_id    TEXT NOT NULL,
    event_type    TEXT NOT NULL,
    timestamp     TEXT NOT NULL DEFAULT (datetime('now')),
    actor         TEXT NOT NULL,
    action_class  TEXT NOT NULL,
    target        TEXT,
    decision      TEXT,
    reason_code   TEXT,
    data_class    TEXT,
    content_hash  TEXT,
    excerpt       TEXT,
    metadata      TEXT NOT NULL DEFAULT '{}'
);
CREATE INDEX IF NOT EXISTS idx_telemetry_session
    ON telemetry_events(session_id, timestamp);

--------------------------------------------------------------------------------
-- model_runs — A2/A4 per-LLM-call accounting
--------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS model_runs (
    run_id        TEXT PRIMARY KEY,
    role          TEXT NOT NULL,
    model         TEXT NOT NULL,
    provider      TEXT NOT NULL,
    input_tokens  INTEGER NOT NULL DEFAULT 0,
    output_tokens INTEGER NOT NULL DEFAULT 0,
    latency_ms    INTEGER NOT NULL DEFAULT 0,
    cost_usd      REAL,
    success       INTEGER NOT NULL DEFAULT 1,
    error         TEXT,
    created_at    TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_model_runs_role
    ON model_runs(role, model, created_at);

--------------------------------------------------------------------------------
-- agent_events — live LLM / deployed-agent activity stream for the dashboard
--------------------------------------------------------------------------------
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

--------------------------------------------------------------------------------
-- judge_votes — A2 multi-judge ensemble
--------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS judge_votes (
    vote_id        TEXT PRIMARY KEY,
    lane_id        TEXT NOT NULL,
    judge_role     TEXT NOT NULL,
    verdict        TEXT NOT NULL,
    score          REAL NOT NULL,
    confidence     REAL NOT NULL,
    reasoning      TEXT NOT NULL,
    evidence_turns TEXT NOT NULL DEFAULT '[]',
    created_at     TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_judge_votes_lane
    ON judge_votes(lane_id, judge_role);

--------------------------------------------------------------------------------
-- policy_corpus_results — A2 adversarial-corpus outcomes
--------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS policy_corpus_results (
    result_id         TEXT PRIMARY KEY,
    run_id            TEXT NOT NULL,
    case_id           TEXT NOT NULL,
    observed_decision TEXT NOT NULL,
    expected_decision TEXT NOT NULL,
    passed            INTEGER NOT NULL DEFAULT 0,
    evidence          TEXT NOT NULL DEFAULT '',
    notes             TEXT NOT NULL DEFAULT '',
    created_at        TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_policy_corpus_run
    ON policy_corpus_results(run_id, case_id);

--------------------------------------------------------------------------------
-- idea_components — A2 building blocks of an idea (MAP-Elites)
--------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS idea_components (
    component_id   TEXT PRIMARY KEY,
    idea_id        TEXT NOT NULL,
    component_type TEXT NOT NULL,
    content        TEXT NOT NULL,
    created_at     TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_idea_components_idea
    ON idea_components(idea_id);

--------------------------------------------------------------------------------
-- idea_archive_cells — A2 MAP-Elites archive grid
--------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS idea_archive_cells (
    cell_id           TEXT PRIMARY KEY,
    zone_id           TEXT NOT NULL,
    interaction_style TEXT NOT NULL,
    response_movement TEXT NOT NULL,
    best_idea_id      TEXT,
    best_score        REAL NOT NULL DEFAULT 0.0,
    occupancy         INTEGER NOT NULL DEFAULT 0,
    updated_at        TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_archive_cells_grid
    ON idea_archive_cells(zone_id, interaction_style, response_movement);

--------------------------------------------------------------------------------
-- mutation_operator_stats — A2 operator success tracking
--------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS mutation_operator_stats (
    operator    TEXT PRIMARY KEY,
    uses        INTEGER NOT NULL DEFAULT 0,
    successes   INTEGER NOT NULL DEFAULT 0,
    avg_score   REAL NOT NULL DEFAULT 0.0,
    updated_at  TEXT NOT NULL DEFAULT (datetime('now'))
);

--------------------------------------------------------------------------------
-- attack_skills — preloaded research-grounded ideation priors (Mode D)
-- Derived index over red_team/attack_skills/*.yaml (the source of truth).
-- Seeded at bootstrap by infra.seed_attack_skills; re-seedable, hash-keyed.
--------------------------------------------------------------------------------
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

--------------------------------------------------------------------------------
-- schema_meta — track schema version for migrations
--------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS schema_meta (
    key    TEXT PRIMARY KEY,
    value  TEXT NOT NULL
);

INSERT OR IGNORE INTO schema_meta(key, value) VALUES
    ('schema_version', '3'),
    ('embedding_model', 'sentence-transformers/all-MiniLM-L6-v2'),
    ('embedding_dim',   '384');

--------------------------------------------------------------------------------
-- Seed the 18 attack zones from spec §4.2
--------------------------------------------------------------------------------
INSERT OR IGNORE INTO surface_zones(zone_id, name, description, severity_weight, decay_rate) VALUES
    ('SBX-FS',        'Sandbox / Filesystem',            'Sandboxed filesystem boundaries — escapes, symlink games, mount tricks.', 1.0, 0.02),
    ('SBX-NET',       'Sandbox / Network',               'Outbound network policy — exfiltration, DNS smuggling, blocked-domain bypass.', 1.0, 0.02),
    ('SBX-PROC',      'Sandbox / Process',               'Process boundary — child processes, syscalls, seccomp evasion.', 1.0, 0.02),
    ('SBX-IPC',       'Sandbox / IPC',                   'IPC channels — Unix sockets, named pipes, shared memory escapes.', 0.8, 0.02),
    ('PRV-ROUTE',     'Privacy / Inference Routing',     'Privacy router — local vs cloud routing decisions, PII leakage.', 1.0, 0.02),
    ('PRV-LEAK',      'Privacy / Data Leak',             'Direct PII or secret leaks via responses, logs, or tools.', 1.0, 0.02),
    ('PERM-MODEL',    'Permission Model',                'Policy model integrity — capability grants, role boundaries.', 1.0, 0.02),
    ('PERM-RUNTIME',  'Permission Runtime',              'Runtime enforcement of permissions — TOCTOU, race conditions.', 0.8, 0.02),
    ('SKILL-INSTALL', 'Skill Installation',              'Installation pipeline — manifest validation, signature checks.', 1.0, 0.02),
    ('SKILL-EXEC',    'Skill Execution',                 'Skill runtime — sandboxing of skill code, capability binding.', 1.0, 0.02),
    ('SKILL-SUPPLY',  'Skill Supply Chain',              'Marketplace / source integrity, malicious skills, dependency confusion.', 0.8, 0.03),
    ('MEM-STATE',     'Memory / Persistent State',       'Long-term agent memory — poisoning, false-fact injection.', 0.8, 0.03),
    ('MEM-SHARED',    'Memory / Shared State',           'Cross-agent or cross-session memory bleed.', 0.5, 0.03),
    ('INF-ROUTE',     'Inference Routing Integrity',     'Integrity of routing decisions, MITM between agent and model.', 0.8, 0.02),
    ('INF-LOCAL',     'Local Inference',                 'Local Nemotron-served inference — model swap, prompt leak.', 0.5, 0.03),
    ('AGENT-COMM',    'Agent Communication',             'Channel messaging between agents — spoofing, replay.', 0.5, 0.03),
    ('PROMPT-INJ',    'Prompt Injection',                'Classic prompt injection via inputs, documents, tools.', 1.0, 0.02),
    ('SOCIAL-ENG',    'Social Engineering',              'Multi-turn manipulation to subvert policy.', 0.8, 0.03);
