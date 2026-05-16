"""The code-graph contract — real-root-cause spec §6.1.

`PathTracer` is written against the `CodeGraph` Protocol so the symbol-graph
backend is swappable. `PythonCodeGraph` (blue_team/code_graph_sqlite.py) ships
first; an `ArgyphCodeGraph` may slot in later with no tracer change. No Argyph
runtime dependency is introduced by this module.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal, Protocol, runtime_checkable

SymbolKind = Literal["function", "method", "class"]
EdgeKind = Literal["call", "reference"]
GraphBackend = Literal["python", "argyph"]


@dataclass
class CodeSymbol:
    """One definition (function/method/class) extracted from a code chunk."""

    symbol_id: str
    file_path: str
    symbol_name: str
    symbol_kind: str  # SymbolKind
    line_start: int
    line_end: int
    language: str


@dataclass
class CodeEdge:
    """A directed reference from one symbol to another (resolved or not)."""

    src_symbol_id: str
    dst_symbol_id: str | None  # None when the reference is unresolved
    dst_name: str  # the referenced name — always present
    edge_kind: str  # EdgeKind
    resolved: bool


@dataclass
class PathNode:
    """One on-path symbol, with its measured rank signals."""

    symbol: CodeSymbol
    proximity: float  # 0..1 — closeness to the violation sink
    centrality: float  # 0..1 — fraction of anchor->sink paths crossing it
    evidence_touch: bool  # the symbol controls a path/syscall the attack hit
    rank_score: float  # 0..1 — the blended ranking score


@dataclass
class ExecutedPath:
    """The reconstructed executed path for one finding, ranked entry->violation."""

    nodes: list[PathNode]  # ranked, highest rank_score first
    anchors: list[CodeSymbol]
    sinks: list[CodeSymbol]
    backend: str  # GraphBackend
    degraded: bool  # true when the graph was unavailable / partial


@runtime_checkable
class CodeGraph(Protocol):
    """Read-only symbol/call graph the tracer walks."""

    def symbol_at(self, file: str, line: int) -> CodeSymbol | None:
        """The symbol whose line range contains `line` in `file`."""
        ...

    def symbol_by_id(self, symbol_id: str) -> CodeSymbol | None:
        """The symbol with the given id, or None."""
        ...

    def find_symbols(self, name: str) -> list[CodeSymbol]:
        """All symbols whose `symbol_name` equals `name`."""
        ...

    def callers(self, symbol_id: str) -> list[CodeEdge]:
        """Edges whose `dst_symbol_id` is `symbol_id`."""
        ...

    def callees(self, symbol_id: str) -> list[CodeEdge]:
        """Edges whose `src_symbol_id` is `symbol_id`."""
        ...

    def shortest_paths(
        self, src: str, dst: str, max_hops: int,
    ) -> list[list[CodeEdge]]:
        """Up to a few shortest edge-paths from symbol `src` to symbol `dst`."""
        ...

    def available(self) -> bool:
        """True iff the graph has at least one symbol."""
        ...


__all__ = [
    "CodeEdge",
    "CodeGraph",
    "CodeSymbol",
    "EdgeKind",
    "ExecutedPath",
    "GraphBackend",
    "PathNode",
    "SymbolKind",
]
