-- MonkeyClaw database schema — Contract owned by Person 1.
--
-- This file is the readable canonical reference AND the bootstrap-from-empty
-- path. To add a table or column after Day-1 sign-off:
--   1. Write a new infra/migrations/NNNN_*.sql or .py migration.
--   2. Also update this file to the post-migration state so a fresh bootstrap
--      and a fully-migrated DB are identical (test_migrations_schema_parity).
--   3. Bump the schema_version seed below to NNNN.
-- Never edit a released DB by hand — migrations are the only mechanism.
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
-- Implemented as a column on findings to enable atomic dequeue with a single
-- UPDATE ... RETURNING. status: queued|processing|completed|failed.
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
    created_at                 TEXT NOT NULL DEFAULT (datetime('now')),
    deprecated                 INTEGER NOT NULL DEFAULT 0,
    last_run_at                TEXT,
    last_run_result            TEXT,
    consecutive_passes         INTEGER NOT NULL DEFAULT 0,
    run_state                  TEXT NOT NULL DEFAULT 'untested'  -- untested|passing|failing|quarantined
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
    status                TEXT NOT NULL DEFAULT 'proposed', -- proposed|testing|approved|rejected
    verification_results  TEXT,                             -- JSON
    created_at            TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_patches_zone   ON patches(zone_id);
CREATE INDEX IF NOT EXISTS idx_patches_status ON patches(status);

--------------------------------------------------------------------------------
-- patch_variant_results / patch_detection_results — verifier gate hardening
-- (verifier-gate-hardening spec §7). Mirrored from migration 0013.
--------------------------------------------------------------------------------
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

--------------------------------------------------------------------------------
-- code-graph tables (real-root-cause spec §7) — kept in sync with
-- infra/migrations/0012_code_graph.sql
--------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS code_symbols (
    symbol_id    TEXT PRIMARY KEY,
    chunk_id     TEXT NOT NULL,
    file_path    TEXT NOT NULL,
    symbol_name  TEXT NOT NULL,
    symbol_kind  TEXT NOT NULL,            -- function|method|class
    line_start   INTEGER NOT NULL,
    line_end     INTEGER NOT NULL,
    language     TEXT NOT NULL,
    indexed_at   TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_code_symbols_name
    ON code_symbols(symbol_name);
CREATE INDEX IF NOT EXISTS idx_code_symbols_file
    ON code_symbols(file_path, line_start);

CREATE TABLE IF NOT EXISTS code_edges (
    edge_id        TEXT PRIMARY KEY,
    src_symbol_id  TEXT NOT NULL,
    dst_symbol_id  TEXT,                   -- NULL for an unresolved reference
    dst_name       TEXT NOT NULL,
    edge_kind      TEXT NOT NULL,          -- call|reference
    resolved       INTEGER NOT NULL DEFAULT 0,
    indexed_at     TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_code_edges_src ON code_edges(src_symbol_id);
CREATE INDEX IF NOT EXISTS idx_code_edges_dst ON code_edges(dst_symbol_id);

CREATE TABLE IF NOT EXISTS executed_paths (
    path_id        TEXT PRIMARY KEY,
    finding_id     TEXT NOT NULL,
    zone_id        TEXT NOT NULL,
    anchor_symbols TEXT NOT NULL DEFAULT '[]',  -- JSON list of symbol ids
    sink_symbols   TEXT NOT NULL DEFAULT '[]',  -- JSON list of symbol ids
    node_count     INTEGER NOT NULL DEFAULT 0,
    backend        TEXT NOT NULL DEFAULT 'python',  -- python|argyph
    degraded       INTEGER NOT NULL DEFAULT 0,
    created_at     TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_executed_paths_finding
    ON executed_paths(finding_id);

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
    is_appeal      INTEGER NOT NULL DEFAULT 0,
    weight         REAL NOT NULL DEFAULT 1.0,
    model          TEXT NOT NULL DEFAULT '',
    created_at     TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_judge_votes_lane
    ON judge_votes(lane_id, judge_role);

--------------------------------------------------------------------------------
-- appeal_verdicts — judge-ensemble frontier-model appeal re-decisions
--------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS appeal_verdicts (
    appeal_id           TEXT PRIMARY KEY,
    lane_id             TEXT NOT NULL,
    ensemble_verdict    TEXT NOT NULL,
    appeal_verdict      TEXT NOT NULL,
    disagreement        REAL NOT NULL,
    ensemble_confidence REAL NOT NULL,
    appeal_confidence   REAL NOT NULL,
    failure_class       TEXT NOT NULL DEFAULT 'none',
    severity            TEXT NOT NULL DEFAULT 'low',
    sided_with_roles    TEXT NOT NULL DEFAULT '[]',
    reasoning           TEXT NOT NULL DEFAULT '',
    model               TEXT NOT NULL DEFAULT '',
    errored             INTEGER NOT NULL DEFAULT 0,
    created_at          TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_appeal_verdicts_lane
    ON appeal_verdicts(lane_id);

--------------------------------------------------------------------------------
-- attack_elo — judge-ensemble per-zone pairwise Elo ratings
--------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS attack_elo (
    zone_id      TEXT NOT NULL,
    attack_id    TEXT NOT NULL,
    rating       REAL NOT NULL DEFAULT 1000.0,
    comparisons  INTEGER NOT NULL DEFAULT 0,
    wins         INTEGER NOT NULL DEFAULT 0,
    losses       INTEGER NOT NULL DEFAULT 0,
    updated_at   TEXT NOT NULL DEFAULT (datetime('now')),
    PRIMARY KEY (zone_id, attack_id)
);
CREATE INDEX IF NOT EXISTS idx_attack_elo_zone
    ON attack_elo(zone_id, rating);

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
-- purple-team detection tables (purple-team spec §8) — mirror of 0005
--------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS detection_rules (
    rule_id                       TEXT PRIMARY KEY,
    zone_id                       TEXT NOT NULL,
    source_finding_id             TEXT NOT NULL,
    logic                         TEXT NOT NULL,
    expected_telemetry_signature  TEXT NOT NULL,
    response_action               TEXT NOT NULL,
    status                        TEXT NOT NULL DEFAULT 'candidate',
    created_at                    TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_detection_rules_zone
    ON detection_rules(zone_id, status);

CREATE TABLE IF NOT EXISTS detection_results (
    result_id      TEXT PRIMARY KEY,
    session_id     TEXT NOT NULL,
    execution_id   TEXT NOT NULL,
    zone_id        TEXT NOT NULL,
    quadrant       TEXT NOT NULL,            -- PASS|PARTIAL|WEAK|FAIL
    prevention     TEXT NOT NULL,            -- blocked|succeeded
    observability  TEXT NOT NULL,            -- observed|silent|unknown
    rule_id        TEXT,
    evidence       TEXT NOT NULL DEFAULT '{}',
    created_at     TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_detection_results_zone
    ON detection_results(zone_id, created_at);
CREATE INDEX IF NOT EXISTS idx_detection_results_session
    ON detection_results(session_id);

CREATE TABLE IF NOT EXISTS detection_coverage (
    zone_id        TEXT PRIMARY KEY,
    coverage_score REAL NOT NULL DEFAULT 0.0,
    sample_count   INTEGER NOT NULL DEFAULT 0,
    updated_at     TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS control_validation_runs (
    run_id          TEXT PRIMARY KEY,
    kind            TEXT NOT NULL,           -- inline|full
    cases_total     INTEGER NOT NULL DEFAULT 0,
    cases_passed    INTEGER NOT NULL DEFAULT 0,
    regressions     TEXT NOT NULL DEFAULT '[]',
    victim_build_id TEXT NOT NULL DEFAULT 'mock',
    status          TEXT NOT NULL DEFAULT 'ok',  -- ok|errored
    created_at      TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_control_validation_kind
    ON control_validation_runs(kind, created_at);

CREATE TABLE IF NOT EXISTS report_cards (
    card_id      TEXT PRIMARY KEY,
    generated_at TEXT NOT NULL DEFAULT (datetime('now')),
    dimensions   TEXT NOT NULL DEFAULT '[]',
    summary      TEXT NOT NULL DEFAULT ''
);

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
    niche_descriptors TEXT NOT NULL DEFAULT '{}',
    updated_at        TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_archive_cells_grid
    ON idea_archive_cells(zone_id, interaction_style, response_movement);

--------------------------------------------------------------------------------
-- mutation_operator_stats — A2 operator success tracking
--------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS mutation_operator_stats (
    operator      TEXT PRIMARY KEY,
    uses          INTEGER NOT NULL DEFAULT 0,
    successes     INTEGER NOT NULL DEFAULT 0,
    avg_score     REAL NOT NULL DEFAULT 0.0,
    squared_score REAL NOT NULL DEFAULT 0.0,
    last_lift     REAL NOT NULL DEFAULT 0.0,
    updated_at    TEXT NOT NULL DEFAULT (datetime('now'))
);

--------------------------------------------------------------------------------
-- mutation_operator_stats_by_zone — per-zone operator breakdown (B6 §8)
--------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS mutation_operator_stats_by_zone (
    operator      TEXT NOT NULL,
    zone_id       TEXT NOT NULL,
    uses          INTEGER NOT NULL DEFAULT 0,
    successes     INTEGER NOT NULL DEFAULT 0,
    avg_score     REAL NOT NULL DEFAULT 0.0,
    squared_score REAL NOT NULL DEFAULT 0.0,
    last_lift     REAL NOT NULL DEFAULT 0.0,
    updated_at    TEXT NOT NULL DEFAULT (datetime('now')),
    PRIMARY KEY (operator, zone_id)
);

--------------------------------------------------------------------------------
-- mutation_attempts — one row per mutated execution (B6 §8)
--------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS mutation_attempts (
    attempt_id       TEXT PRIMARY KEY,
    cycle_id         INTEGER NOT NULL,
    zone_id          TEXT NOT NULL,
    operator         TEXT NOT NULL,
    parent_idea_id   TEXT NOT NULL,
    child_idea_id    TEXT NOT NULL,
    parent_score     REAL NOT NULL,
    child_score      REAL NOT NULL,
    lift             REAL NOT NULL,
    improved         INTEGER NOT NULL DEFAULT 0,
    child_verdict    TEXT NOT NULL,
    created_at       TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_mutation_attempts_op
    ON mutation_attempts(operator, zone_id, created_at);

--------------------------------------------------------------------------------
-- queue_transitions — audit trail of every status transition (data-integrity spec §8.1)
--------------------------------------------------------------------------------
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

--------------------------------------------------------------------------------
-- victim_snapshots / sandbox_runs — real-provisioner tables (migration 0006)
-- Reference copy, kept in sync with infra/migrations/0006_real_provisioner.sql.
--------------------------------------------------------------------------------
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

--------------------------------------------------------------------------------
-- trajectory_scores — per-turn harm-ladder trajectory (trajectory spec §8)
--------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS trajectory_scores (
    trajectory_id   TEXT PRIMARY KEY,
    lane_id         TEXT NOT NULL,
    idea_id         TEXT NOT NULL,
    zone_id         TEXT NOT NULL,
    max_stage       INTEGER NOT NULL DEFAULT 0,
    final_stage     INTEGER NOT NULL DEFAULT 0,
    erosion_slope   REAL NOT NULL DEFAULT 0.0,
    stalled_at_turn INTEGER NOT NULL DEFAULT -1,
    monotonic       INTEGER NOT NULL DEFAULT 1,   -- 0/1
    turn_scores     TEXT NOT NULL DEFAULT '[]',   -- JSON list of TurnScore
    created_at      TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_trajectory_scores_zone_idea
    ON trajectory_scores(zone_id, idea_id);

--------------------------------------------------------------------------------
-- near_misses — attacks that almost worked (trajectory spec §8)
--------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS near_misses (
    near_miss_id      TEXT PRIMARY KEY,
    idea_id           TEXT NOT NULL,
    lane_id           TEXT NOT NULL,
    zone_id           TEXT NOT NULL,
    max_stage         INTEGER NOT NULL DEFAULT 0,
    stalled_at_turn   INTEGER NOT NULL DEFAULT -1,
    erosion_excerpt   TEXT NOT NULL DEFAULT '',
    useful_components TEXT NOT NULL DEFAULT '[]', -- JSON list
    mutation_seeds    TEXT NOT NULL DEFAULT '[]', -- JSON list
    consumed          INTEGER NOT NULL DEFAULT 0, -- 0/1
    created_at        TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_near_misses_zone_consumed
    ON near_misses(zone_id, consumed);

--------------------------------------------------------------------------------
-- corpus-driven ideation — technique tagging + technique-coverage axis
-- (corpus-driven-ideation spec §8)
--------------------------------------------------------------------------------
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

--------------------------------------------------------------------------------
-- schema_meta — track schema version for migrations
--------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS schema_meta (
    key    TEXT PRIMARY KEY,
    value  TEXT NOT NULL
);

INSERT OR IGNORE INTO schema_meta(key, value) VALUES
    ('schema_version', '13'),
    ('taxonomy_corpus_version', 'atlas-5.4.0+owasp-2025'),
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
