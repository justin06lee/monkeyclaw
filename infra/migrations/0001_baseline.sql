-- 0001_baseline.sql — no-op baseline.
-- Records that a DB already consistent with schema.sql (schema_version >= 2)
-- has migration 0001 applied. Every fresh schema.sql bootstrap and every
-- existing DB converge on the same migration ledger from here.
SELECT 1;
