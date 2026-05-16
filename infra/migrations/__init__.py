"""Ordered, forward-only schema migrations. Discovered by infra/migrations.py.

Versioned, forward-only SQLite migration runner.

Files live in infra/migrations/ named NNNN_short_description.sql or .py.
`.sql` files are wrapped in a transaction and executescript-ed; `.py` files
export `def migrate(conn: sqlite3.Connection) -> None`. Migrations run on
Database open; each applied migration is recorded in schema_meta as a row
keyed 'migration:NNNN'. Forward-only: an applied migration is never re-run.
"""

from __future__ import annotations

import importlib.util
import logging
import re
import sqlite3
from dataclasses import dataclass
from pathlib import Path

LOG = logging.getLogger("monkeyclaw.migrations")

MIGRATIONS_DIR = Path(__file__).resolve().parent
_NAME_RE = re.compile(r"^(\d{4})_[a-z0-9_]+\.(sql|py)$")


class MigrationError(RuntimeError):
    """A migration failed to apply, or the migration set is malformed."""


@dataclass(frozen=True)
class Migration:
    ordinal: int
    name: str          # full filename, e.g. "0003_queue_transitions.sql"
    path: Path
    kind: str          # "sql" | "py"


def discover(migrations_dir: Path = MIGRATIONS_DIR) -> list[Migration]:
    """Return migrations sorted by ordinal. Rejects malformed names,
    duplicate ordinals, and non-sequential ordinals (must start at 1 and
    increase by exactly 1)."""
    found: list[Migration] = []
    for path in sorted(migrations_dir.iterdir()):
        if path.name == "__init__.py" or path.name.startswith("_"):
            continue
        if path.suffix not in (".sql", ".py"):
            continue
        m = _NAME_RE.match(path.name)
        if not m:
            raise MigrationError(f"malformed migration filename: {path.name}")
        found.append(Migration(
            ordinal=int(m.group(1)), name=path.name, path=path, kind=m.group(2),
        ))
    found.sort(key=lambda mig: mig.ordinal)
    for i, mig in enumerate(found, start=1):
        if mig.ordinal != i:
            raise MigrationError(
                f"non-sequential migration ordinal: expected {i:04d}, "
                f"got {mig.name}"
            )
    return found


def applied_set(conn: sqlite3.Connection) -> set[int]:
    """Ordinals already recorded in schema_meta as 'migration:NNNN' rows."""
    rows = conn.execute(
        "SELECT key FROM schema_meta WHERE key LIKE 'migration:%'"
    ).fetchall()
    out: set[int] = set()
    for row in rows:
        try:
            out.add(int(str(row[0]).split(":", 1)[1]))
        except (IndexError, ValueError):
            continue
    return out


def _record_applied(conn: sqlite3.Connection, mig: Migration) -> None:
    conn.execute(
        "INSERT INTO schema_meta(key, value) VALUES(?, datetime('now')) "
        "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
        (f"migration:{mig.ordinal:04d}",),
    )
    conn.execute(
        "INSERT INTO schema_meta(key, value) VALUES('schema_version', ?) "
        "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
        (str(mig.ordinal),),
    )


def _apply_one(conn: sqlite3.Connection, mig: Migration) -> None:
    if mig.kind == "sql":
        sql = mig.path.read_text()
        # `executescript` implicitly commits any pending transaction first,
        # so wrap the migration body in its own BEGIN/COMMIT inside the
        # script text — that makes the whole migration atomic.
        try:
            conn.executescript(f"BEGIN;\n{sql}\nCOMMIT;")
        except sqlite3.Error as exc:
            try:
                conn.execute("ROLLBACK")
            except sqlite3.Error:
                pass
            raise MigrationError(f"{mig.name} failed: {exc}") from exc
    else:
        spec = importlib.util.spec_from_file_location(
            f"_migration_{mig.ordinal}", mig.path)
        if spec is None or spec.loader is None:
            raise MigrationError(f"cannot load {mig.name}")
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        migrate = getattr(module, "migrate", None)
        if migrate is None:
            raise MigrationError(f"{mig.name} has no migrate(conn) function")
        try:
            migrate(conn)
        except Exception as exc:  # noqa: BLE001
            raise MigrationError(f"{mig.name} failed: {exc}") from exc


def run_pending(conn: sqlite3.Connection,
                migrations_dir: Path = MIGRATIONS_DIR) -> list[int]:
    """Apply every discovered migration whose ordinal is not already in
    applied_set, in order. Records each only after its body completed.
    Returns the list of ordinals applied this call."""
    done = applied_set(conn)
    applied: list[int] = []
    for mig in discover(migrations_dir):
        if mig.ordinal in done:
            continue
        LOG.info("applying migration %s", mig.name)
        _apply_one(conn, mig)
        _record_applied(conn, mig)
        applied.append(mig.ordinal)
    return applied
