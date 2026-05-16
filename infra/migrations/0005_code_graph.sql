-- Migration 0005 — code-graph tables (real-root-cause spec §7).
-- Forward-only, idempotent. Applied by infra/migrations.py on Database open.

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
