"""The second coverage axis — technique coverage per zone
(corpus-driven-ideation spec §6.4).

Of the ATLAS techniques + OWASP categories mapped to a zone, how many have
been exercised (an idea tagged with them was executed) and how many
confirmed (a finding tagged). Materialised in the technique_coverage table
so the map rebuilds from the DB.
"""

from __future__ import annotations

import logging

from interfaces.mcp_tools import MonkeyClawMCP
from interfaces.types import TechniqueCoverage, TechniqueRef

from red_team.taxonomy import Taxonomy

LOG = logging.getLogger("monkeyclaw.red.technique_coverage")


class TechniqueCoverageModel:
    """Maintains + queries the technique-coverage axis. Backed by the
    technique_coverage MCP table; rebuildable from idea/finding tags."""

    def __init__(self, mcp: MonkeyClawMCP, taxonomy: Taxonomy) -> None:
        self.mcp = mcp
        self.taxonomy = taxonomy

    # -- updates ----------------------------------------------------------
    def record_attempt(
        self, zone_id: str, technique_refs: list[TechniqueRef]
    ) -> None:
        """One judged attempt — every tag bumps attempts for its zone."""
        for ref in technique_refs:
            self.mcp.bump_technique_coverage(
                zone_id, ref.kind, ref.technique_id, attempts=1)

    def record_confirmation(
        self, zone_id: str, technique_refs: list[TechniqueRef]
    ) -> None:
        """One confirmed finding — every tag bumps confirmations."""
        for ref in technique_refs:
            self.mcp.bump_technique_coverage(
                zone_id, ref.kind, ref.technique_id, confirmations=1)

    # -- queries ----------------------------------------------------------
    def _mapped_ids(self, zone_id: str) -> list[tuple[str, str]]:
        out = [("atlas", t.technique_id)
               for t in self.taxonomy.techniques_for_zone(zone_id)]
        out += [("owasp", c.category_id)
                for c in self.taxonomy.owasp_for_zone(zone_id)]
        return out

    def coverage(self, zone_id: str) -> TechniqueCoverage:
        """exercised / confirmed counts + ratios for one zone."""
        mapped = self._mapped_ids(zone_id)
        total = len(mapped)
        rows = {(r["technique_kind"], r["technique_id"]): r
                for r in self.mcp.get_technique_coverage_rows(zone_id)}
        exercised = sum(1 for key in mapped
                        if rows.get(key, {}).get("attempts", 0) > 0)
        confirmed = sum(1 for key in mapped
                        if rows.get(key, {}).get("confirmations", 0) > 0)
        gaps = [tid for (kind, tid) in mapped
                if rows.get((kind, tid), {}).get("attempts", 0) == 0]
        return TechniqueCoverage(
            zone_id=zone_id, total=total, exercised=exercised,
            confirmed=confirmed,
            exercised_ratio=(exercised / total if total else 0.0),
            confirmed_ratio=(confirmed / total if total else 0.0),
            gap_technique_ids=gaps)

    def gaps(self, zone_id: str, top_n: int) -> list[TechniqueRef]:
        """The least-covered techniques for a zone — what Mode D consumes."""
        mapped = self._mapped_ids(zone_id)
        rows = {(r["technique_kind"], r["technique_id"]): r
                for r in self.mcp.get_technique_coverage_rows(zone_id)}
        ranked = sorted(
            mapped,
            key=lambda key: (rows.get(key, {}).get("attempts", 0),
                             key[1]))
        out: list[TechniqueRef] = []
        for kind, tid in ranked[:max(0, top_n)]:
            if kind == "atlas":
                tech = self.taxonomy.technique(tid)
                name = tech.name if tech else tid
            else:
                cat = next((c for c in self.taxonomy.owasp_for_zone(zone_id)
                            if c.category_id == tid), None)
                name = cat.name if cat else tid
            out.append(TechniqueRef(
                kind=kind, technique_id=tid, name=name,
                corpus_version=self.taxonomy.version, resolved_by="model"))
        return out

    def map(self) -> list[TechniqueCoverage]:
        """The whole-surface technique-coverage view."""
        return [self.coverage(z) for z in self.taxonomy.zone_ids()]


__all__ = ["TechniqueCoverageModel"]
