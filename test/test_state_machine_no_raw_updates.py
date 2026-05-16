"""Constraint 2: after the data-integrity spec, no code outside
infra/state_machine.py issues a raw UPDATE ... SET <status column>. The one
status mutation path is the TransitionEngine."""

from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SCAN_DIRS = ["infra", "red_team", "blue_team"]
# state_machine.py owns the one status-mutation path; the migration runner and
# the versioned migration scripts in infra/migrations/ are the bootstrap path
# and run before the engine exists, so they are also exempt.
ALLOWED = {"infra/state_machine.py", "infra/migrations.py"}


def _is_allowed(rel: str) -> bool:
    return rel in ALLOWED or rel.startswith("infra/migrations/")

# Matches UPDATE <table> SET ... <status-ish column> = within one SET clause.
# The span is bounded to the SET clause itself: it may not cross a statement
# boundary (`;`), a string-literal boundary (quotes) or a paren — that keeps
# the match from leaking into an unrelated later statement in the same file.
_STATUS_COLS = r"(status|patch_status|blue_team_status|run_state)"
_PATTERN = re.compile(
    r"UPDATE\s+\w+\s+SET\s+[^;'\"()]*?\b" + _STATUS_COLS + r"\s*=",
    re.IGNORECASE | re.DOTALL,
)


def test_no_raw_status_updates_outside_state_machine() -> None:
    offenders: list[str] = []
    for d in SCAN_DIRS:
        for path in (ROOT / d).rglob("*.py"):
            rel = path.relative_to(ROOT).as_posix()
            if _is_allowed(rel):
                continue
            text = path.read_text()
            for m in _PATTERN.finditer(text):
                line = text[:m.start()].count("\n") + 1
                offenders.append(f"{rel}:{line}: {m.group(0)[:80]}")
    assert not offenders, (
        "raw status UPDATE outside the TransitionEngine:\n"
        + "\n".join(offenders)
    )
