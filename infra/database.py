"""SQLite + sqlite-vec wrapper.

Owns: connection lifecycle, schema bootstrap, embedding model, vector ops.

The embedding model is sentence-transformers all-MiniLM-L6-v2 (384 dims). The
model is loaded lazily — the first call to `embed()` warms the cache. For
hot paths the embedding can be reused across calls.
"""

from __future__ import annotations

import logging
import sqlite3
import threading
from collections.abc import Iterable
from pathlib import Path

import numpy as np
import sqlite_vec

LOG = logging.getLogger("monkeyclaw.db")

EMBEDDING_DIM = 384
EMBEDDING_MODEL = "sentence-transformers/all-MiniLM-L6-v2"
CURRENT_SCHEMA_VERSION = 2
SCHEMA_PATH = Path(__file__).resolve().parent.parent / "interfaces" / "schema.sql"


def pack_vec(vec: Iterable[float]) -> bytes:
    """Pack a vector as little-endian float32 for sqlite-vec."""
    arr = np.asarray(list(vec), dtype=np.float32)
    if arr.ndim != 1 or arr.shape[0] != EMBEDDING_DIM:
        raise ValueError(
            f"embedding must be length {EMBEDDING_DIM}, got shape {arr.shape}"
        )
    return arr.tobytes()


def unpack_vec(b: bytes) -> np.ndarray:
    return np.frombuffer(b, dtype=np.float32)


class EmbeddingModel:
    """Lazy wrapper around sentence-transformers.

    A single shared model is used across the process. Calling code can pass
    pre-computed embeddings in MCP inputs to avoid re-encoding.
    """

    _lock = threading.Lock()
    _instance: EmbeddingModel | None = None

    @classmethod
    def shared(cls) -> EmbeddingModel:
        with cls._lock:
            if cls._instance is None:
                cls._instance = cls()
            return cls._instance

    def __init__(self, model_name: str = EMBEDDING_MODEL) -> None:
        self.model_name = model_name
        self._model = None  # lazy

    def _load(self):
        if self._model is None:
            from sentence_transformers import SentenceTransformer

            LOG.info("loading embedding model %s", self.model_name)
            self._model = SentenceTransformer(self.model_name)
        return self._model

    def encode(self, texts: list[str]) -> np.ndarray:
        model = self._load()
        emb = model.encode(texts, convert_to_numpy=True, normalize_embeddings=True)
        # normalize_embeddings=True so cosine == dot product
        return emb.astype(np.float32)

    def encode_one(self, text: str) -> np.ndarray:
        return self.encode([text])[0]


class Database:
    """Thin SQLite wrapper with sqlite-vec loaded.

    Connections are NOT thread-safe by default; the MCP server uses a single
    connection guarded by a lock. For higher concurrency, swap in a connection
    pool.
    """

    def __init__(self, db_path: str | Path, schema_path: Path = SCHEMA_PATH,
                 read_only: bool = False) -> None:
        self.path = Path(db_path)
        self.schema_path = schema_path
        self.read_only = read_only
        self._lock = threading.RLock()
        self._conn = self._open()

    def _open(self) -> sqlite3.Connection:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        # `check_same_thread=False` lets us guard with our own RLock and serve
        # both sync MCP calls and async orchestrator workers.
        conn = sqlite3.connect(
            self.path.as_posix(),
            check_same_thread=False,
            isolation_level=None,  # autocommit; we use explicit BEGIN where needed
        )
        conn.row_factory = sqlite3.Row
        conn.enable_load_extension(True)
        sqlite_vec.load(conn)
        conn.enable_load_extension(False)
        # Sensible pragmas
        conn.executescript(
            "PRAGMA journal_mode = WAL;\n"
            "PRAGMA synchronous = NORMAL;\n"
            "PRAGMA foreign_keys = ON;\n"
            "PRAGMA temp_store = MEMORY;\n"
        )
        if not self.read_only:
            self._apply_schema(conn)
            self._run_migrations(conn)
        return conn

    def _apply_schema(self, conn: sqlite3.Connection) -> None:
        sql = self.schema_path.read_text()
        conn.executescript(sql)

    def _run_migrations(self, conn: sqlite3.Connection) -> None:
        """Reconcile schema_version after the (idempotent) schema script runs.

        schema.sql uses CREATE TABLE IF NOT EXISTS, so re-running it on an old
        DB adds any missing tables. This step records that the DB is now at
        CURRENT_SCHEMA_VERSION so future migrations can branch on it.
        """
        row = conn.execute(
            "SELECT value FROM schema_meta WHERE key='schema_version'"
        ).fetchone()
        current = int(row[0]) if row else 0
        if current < CURRENT_SCHEMA_VERSION:
            LOG.info("migrating DB schema %d -> %d", current, CURRENT_SCHEMA_VERSION)
            conn.execute(
                "INSERT INTO schema_meta(key, value) VALUES('schema_version', ?) "
                "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                (str(CURRENT_SCHEMA_VERSION),),
            )

    # ------------------------------------------------------------------
    @property
    def conn(self) -> sqlite3.Connection:
        return self._conn

    def lock(self) -> threading.RLock:
        return self._lock

    def execute(self, sql: str, params: tuple = ()) -> sqlite3.Cursor:
        with self._lock:
            return self._conn.execute(sql, params)

    def executemany(self, sql: str, params_seq: list[tuple]) -> sqlite3.Cursor:
        with self._lock:
            return self._conn.executemany(sql, params_seq)

    def fetchone(self, sql: str, params: tuple = ()):
        with self._lock:
            return self._conn.execute(sql, params).fetchone()

    def fetchall(self, sql: str, params: tuple = ()):
        with self._lock:
            return self._conn.execute(sql, params).fetchall()

    def vacuum(self) -> None:
        with self._lock:
            self._conn.execute("VACUUM")

    def close(self) -> None:
        with self._lock:
            self._conn.close()

    # ------------------------------------------------------------------
    # Vector helpers
    # ------------------------------------------------------------------
    def upsert_vector(self, table: str, key_col: str, key: str, embedding) -> None:
        """Insert-or-replace an embedding in a vec0 virtual table."""
        blob = pack_vec(embedding)
        with self._lock:
            self._conn.execute(f"DELETE FROM {table} WHERE {key_col} = ?", (key,))
            self._conn.execute(
                f"INSERT INTO {table}({key_col}, embedding) VALUES (?, ?)", (key, blob),
            )

    def vector_search(self, table: str, key_col: str, embedding,
                       top_k: int, where_clause: str = "",
                       where_params: tuple = ()) -> list[tuple[str, float]]:
        """KNN search returning [(key, distance), ...]. Lower distance == closer."""
        blob = pack_vec(embedding)
        # sqlite-vec's MATCH operator runs KNN search.
        sql = (
            f"SELECT {key_col}, distance FROM {table} "
            f"WHERE embedding MATCH ? "
            f"{('AND ' + where_clause) if where_clause else ''} "
            f"ORDER BY distance LIMIT ?"
        )
        params = (blob, *where_params, top_k)
        with self._lock:
            rows = self._conn.execute(sql, params).fetchall()
        return [(r[0], r[1]) for r in rows]

    # ------------------------------------------------------------------
    # Backup / restore
    # ------------------------------------------------------------------
    def backup(self, dest: str | Path) -> None:
        dest = Path(dest)
        dest.parent.mkdir(parents=True, exist_ok=True)
        with self._lock:
            with sqlite3.connect(dest.as_posix()) as bck:
                self._conn.backup(bck)

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()
