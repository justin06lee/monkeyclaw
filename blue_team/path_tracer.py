"""Path tracer — reconstructs the executed path (real-root-cause spec §6.4).

Four stages: anchor (evidence/logs -> entry symbols), seed (semantic search ->
sink symbols), walk (shortest paths anchor->sink over the graph), rank (path
proximity x graph centrality x evidence-touch). Degrades to semantic-search-only
when the graph is unavailable.
"""

from __future__ import annotations

import logging

from interfaces.code_graph import CodeGraph, CodeSymbol, ExecutedPath, PathNode
from interfaces.types import CheckResult, Message

LOG = logging.getLogger("monkeyclaw.blue.path_tracer")

# Evidence keys whose values name something the code controls (a path, a
# syscall, a destination) — used both to anchor and to award an evidence-touch.
_EVIDENCE_KEYS = (
    "system_writes", "writes_outside_allowed",
    "successful_outbound", "denylisted_blocked_syscalls",
)


class PathTracer:
    def __init__(
        self,
        *,
        graph: CodeGraph,
        mcp,  # noqa: ANN001 — MonkeyClawMCP or any object with search_codebase
        max_hops: int = 6,
        db=None,  # noqa: ANN001 — infra.database.Database, optional
    ) -> None:
        self.graph = graph
        self.mcp = mcp
        self.max_hops = max_hops
        self.db = db

    # ------------------------------------------------------------------
    def trace(
        self,
        *,
        zone_id: str,
        evidence: list[CheckResult],
        transcript: list[Message],
        victim_logs: list[str] | None = None,
        finding_id: str = "",
    ) -> ExecutedPath:
        sink_syms, _sink_chunks = self._seed_sinks(zone_id, evidence)
        if not self.graph.available():
            path = self._degraded(sink_syms)
        else:
            anchors = self._anchor(evidence, victim_logs or [])
            touch_tokens = self._evidence_tokens(evidence)
            try:
                path = self._walk_and_rank(anchors, sink_syms, touch_tokens)
            except Exception as e:  # noqa: BLE001
                LOG.warning("graph walk failed (%s) — degrading", e)
                path = self._degraded(sink_syms)
        self._persist(finding_id, zone_id, path)
        return path

    # ------------------------------------------------------------------
    def _seed_sinks(
        self, zone_id: str, evidence: list[CheckResult],
    ) -> tuple[list[CodeSymbol], list]:
        """Semantic search for the violation site -> sink symbols + raw chunks."""
        query = f"{zone_id} " + " ".join(
            c.check_name for c in evidence if c.triggered)
        try:
            chunks = self.mcp.search_codebase(query=query, top_k=5)
        except Exception as e:  # noqa: BLE001
            LOG.warning("search_codebase failed during sink seeding: %s", e)
            chunks = []
        sinks: list[CodeSymbol] = []
        for ch in chunks:
            sym = None
            if self.graph.available() and ch.function_name:
                matches = self.graph.find_symbols(ch.function_name)
                sym = matches[0] if matches else None
            if sym is None:
                sym = _symbol_from_chunk(ch)
            sinks.append(sym)
        return sinks, list(chunks)

    # ------------------------------------------------------------------
    def _anchor(
        self, evidence: list[CheckResult], victim_logs: list[str],
    ) -> list[CodeSymbol]:
        """Resolve triggered checks + log lines to entry symbols."""
        names: list[str] = []
        for c in evidence:
            if c.triggered:
                names.append(c.check_name)
        for line in victim_logs:
            names.extend(_identifier_tokens(line))
        anchors: list[CodeSymbol] = []
        seen: set[str] = set()
        for name in names:
            for sym in self.graph.find_symbols(name):
                if sym.symbol_id not in seen:
                    seen.add(sym.symbol_id)
                    anchors.append(sym)
        return anchors

    # ------------------------------------------------------------------
    def _walk_and_rank(
        self,
        anchors: list[CodeSymbol],
        sinks: list[CodeSymbol],
        touch_tokens: set[str],
    ) -> ExecutedPath:
        # Symbol-id -> CodeSymbol, grown as the walk discovers on-path symbols.
        by_id: dict[str, CodeSymbol] = {s.symbol_id: s for s in anchors + sinks}
        crossings: dict[str, int] = {}
        min_hop: dict[str, int] = {}

        for anchor in anchors:
            for sink in sinks:
                paths = self.graph.shortest_paths(
                    anchor.symbol_id, sink.symbol_id, self.max_hops)
                for path in paths:
                    chain = [anchor.symbol_id] + [
                        e.dst_symbol_id for e in path if e.dst_symbol_id]
                    for hop, sid in enumerate(chain):
                        if sid not in by_id:
                            resolved = self._symbol_by_id(sid)
                            if resolved is not None:
                                by_id[sid] = resolved
                        crossings[sid] = crossings.get(sid, 0) + 1
                        # distance from the sink end of the chain
                        dist = len(chain) - 1 - hop
                        min_hop[sid] = min(min_hop.get(sid, 999), dist)

        # If no path was found, fall back to anchors + sinks as bare nodes.
        if not crossings:
            sink_ids = {s.symbol_id for s in sinks}
            for s in anchors + sinks:
                crossings[s.symbol_id] = 1
                min_hop[s.symbol_id] = 0 if s.symbol_id in sink_ids else 1

        nodes = self._rank(by_id, crossings, min_hop, sinks, touch_tokens)
        return ExecutedPath(
            nodes=nodes, anchors=anchors, sinks=sinks,
            backend="python", degraded=False,
        )

    # ------------------------------------------------------------------
    def _rank(
        self,
        by_id: dict[str, CodeSymbol],
        crossings: dict[str, int],
        min_hop: dict[str, int],
        sinks: list[CodeSymbol],
        touch_tokens: set[str],
    ) -> list[PathNode]:
        sink_ids = {s.symbol_id for s in sinks}
        max_cross = max(crossings.values()) if crossings else 1
        nodes: list[PathNode] = []
        for sid, count in crossings.items():
            sym = by_id.get(sid)
            if sym is None:
                continue
            hop = min_hop.get(sid, 6)
            proximity = 1.0 if sid in sink_ids else max(0.0, 1.0 - hop / 6.0)
            centrality = count / max_cross if max_cross else 0.0
            touch = any(tok and tok in sym.symbol_name.lower()
                        for tok in touch_tokens) or sid in sink_ids
            rank = max(0.0, min(1.0,
                0.5 * proximity + 0.35 * centrality + (0.15 if touch else 0.0)))
            nodes.append(PathNode(
                symbol=sym, proximity=proximity, centrality=centrality,
                evidence_touch=touch, rank_score=rank,
            ))
        nodes.sort(key=lambda n: n.rank_score, reverse=True)
        return nodes

    # ------------------------------------------------------------------
    def _degraded(self, sinks: list[CodeSymbol]) -> ExecutedPath:
        """Semantic-search hits only, proximity-scored — today's behaviour."""
        nodes = [
            PathNode(symbol=s, proximity=1.0 - i * 0.1, centrality=0.0,
                     evidence_touch=False,
                     rank_score=max(0.0, 1.0 - i * 0.1))
            for i, s in enumerate(sinks)
        ]
        return ExecutedPath(
            nodes=nodes, anchors=[], sinks=sinks,
            backend="python", degraded=True,
        )

    # ------------------------------------------------------------------
    def _symbol_by_id(self, symbol_id: str) -> CodeSymbol | None:
        fn = getattr(self.graph, "symbol_by_id", None)
        if fn is None:
            return None
        try:
            return fn(symbol_id)
        except Exception:  # noqa: BLE001
            return None

    # ------------------------------------------------------------------
    def _persist(self, finding_id: str, zone_id: str, path: ExecutedPath) -> None:
        if self.db is None or not finding_id:
            return
        import json
        import uuid
        try:
            with self.db.lock():
                self.db.execute(
                    "INSERT INTO executed_paths(path_id, finding_id, zone_id, "
                    "anchor_symbols, sink_symbols, node_count, backend, "
                    "degraded, created_at) VALUES (?,?,?,?,?,?,?,?,datetime('now'))",
                    (f"EP-{uuid.uuid4().hex[:14]}", finding_id, zone_id,
                     json.dumps([s.symbol_id for s in path.anchors]),
                     json.dumps([s.symbol_id for s in path.sinks]),
                     len(path.nodes), path.backend, 1 if path.degraded else 0),
                )
        except Exception as e:  # noqa: BLE001
            LOG.warning("executed_paths persist failed: %s", e)

    # ------------------------------------------------------------------
    @staticmethod
    def _evidence_tokens(evidence: list[CheckResult]) -> set[str]:
        tokens: set[str] = set()
        for c in evidence:
            if not c.triggered:
                continue
            tokens.add(c.check_name.lower())
            for key in _EVIDENCE_KEYS:
                for v in (c.evidence or {}).get(key, []) or []:
                    if isinstance(v, dict):
                        for x in v.values():
                            tokens |= _identifier_tokens(str(x))
                    else:
                        tokens |= _identifier_tokens(str(v))
        return {t for t in tokens if t}


def _symbol_from_chunk(chunk) -> CodeSymbol:  # noqa: ANN001
    """Wrap a semantic-search chunk as a bare CodeSymbol (degraded path)."""
    start, _, end = (chunk.line_range or "L0-L0").lstrip("L").partition("-")
    try:
        ls, le = int(start or 0), int(end.lstrip("L") or 0)
    except ValueError:
        ls, le = 0, 0
    ident = chunk.function_name or chunk.file_path
    return CodeSymbol(
        symbol_id=f"CHUNK:{chunk.file_path}:{ident}",
        file_path=chunk.file_path,
        symbol_name=ident,
        symbol_kind="function",
        line_start=ls, line_end=le, language=chunk.language,
    )


def _identifier_tokens(text: str) -> set[str]:
    """Lowercase identifier-ish tokens from a free-text string."""
    out: set[str] = set()
    cur = ""
    for ch in text:
        if ch.isalnum() or ch == "_":
            cur += ch
        else:
            if len(cur) >= 3:
                out.add(cur.lower())
            cur = ""
    if len(cur) >= 3:
        out.add(cur.lower())
    return out


__all__ = ["PathTracer"]
