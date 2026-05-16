"""PythonCodeGraph — the default CodeGraph backend (real-root-cause spec §6.3).

Reads `code_symbols` / `code_edges` from SQLite. `shortest_paths` is a bounded
BFS over the edge table. No Argyph dependency.
"""

from __future__ import annotations

import logging
from collections import deque

from infra.database import Database
from interfaces.code_graph import CodeEdge, CodeSymbol

LOG = logging.getLogger("monkeyclaw.blue.code_graph")

_MAX_PATHS = 3  # cap distinct shortest paths returned per (src, dst)


class PythonCodeGraph:
    """A SQLite-backed CodeGraph (satisfies the interfaces.code_graph Protocol)."""

    def __init__(self, db: Database) -> None:
        self.db = db

    # ------------------------------------------------------------------
    def available(self) -> bool:
        rows = self.db.fetchall("SELECT COUNT(*) AS n FROM code_symbols")
        return bool(rows) and rows[0]["n"] > 0

    # ------------------------------------------------------------------
    def find_symbols(self, name: str) -> list[CodeSymbol]:
        rows = self.db.fetchall(
            "SELECT * FROM code_symbols WHERE symbol_name = ?", (name,))
        return [self._row_to_symbol(r) for r in rows]

    def symbol_at(self, file: str, line: int) -> CodeSymbol | None:
        rows = self.db.fetchall(
            "SELECT * FROM code_symbols WHERE file_path = ? "
            "AND line_start <= ? AND line_end >= ? "
            "ORDER BY (line_end - line_start) ASC LIMIT 1",
            (file, line, line))
        return self._row_to_symbol(rows[0]) if rows else None

    def symbol_by_id(self, symbol_id: str) -> CodeSymbol | None:
        rows = self.db.fetchall(
            "SELECT * FROM code_symbols WHERE symbol_id = ?", (symbol_id,))
        return self._row_to_symbol(rows[0]) if rows else None

    # ------------------------------------------------------------------
    def callers(self, symbol_id: str) -> list[CodeEdge]:
        rows = self.db.fetchall(
            "SELECT * FROM code_edges WHERE dst_symbol_id = ?", (symbol_id,))
        return [self._row_to_edge(r) for r in rows]

    def callees(self, symbol_id: str) -> list[CodeEdge]:
        rows = self.db.fetchall(
            "SELECT * FROM code_edges WHERE src_symbol_id = ?", (symbol_id,))
        return [self._row_to_edge(r) for r in rows]

    # ------------------------------------------------------------------
    def shortest_paths(
        self, src: str, dst: str, max_hops: int,
    ) -> list[list[CodeEdge]]:
        """Bounded BFS — up to `_MAX_PATHS` shortest src->dst edge paths."""
        if src == dst:
            return [[]]
        found: list[list[CodeEdge]] = []
        # BFS over states (current symbol, path of edges, visited set).
        queue: deque[tuple[str, list[CodeEdge], frozenset[str]]] = deque()
        queue.append((src, [], frozenset({src})))
        best_len: int | None = None
        while queue:
            node, path, visited = queue.popleft()
            if best_len is not None and len(path) > best_len:
                break
            for edge in self.callees(node):
                target = edge.dst_symbol_id
                if target is None or target in visited:
                    continue
                new_path = [*path, edge]
                if target == dst:
                    if best_len is None:
                        best_len = len(new_path)
                    if len(new_path) == best_len:
                        found.append(new_path)
                        if len(found) >= _MAX_PATHS:
                            return found
                    continue
                if len(new_path) < max_hops:
                    queue.append((target, new_path, visited | {target}))
        return found

    # ------------------------------------------------------------------
    @staticmethod
    def _row_to_symbol(r) -> CodeSymbol:  # noqa: ANN001
        return CodeSymbol(
            symbol_id=r["symbol_id"], file_path=r["file_path"],
            symbol_name=r["symbol_name"], symbol_kind=r["symbol_kind"],
            line_start=r["line_start"], line_end=r["line_end"],
            language=r["language"],
        )

    @staticmethod
    def _row_to_edge(r) -> CodeEdge:  # noqa: ANN001
        return CodeEdge(
            src_symbol_id=r["src_symbol_id"], dst_symbol_id=r["dst_symbol_id"],
            dst_name=r["dst_name"], edge_kind=r["edge_kind"],
            resolved=bool(r["resolved"]),
        )


__all__ = ["PythonCodeGraph"]
