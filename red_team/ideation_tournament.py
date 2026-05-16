"""Head-to-head ideation judging + win-rate update — model-ideation-tournament
spec §5, §7.2, §8.

Counting confirmed findings conflates idea quality with execution and judging
luck. This module adds a cheaper, more direct signal that runs BEFORE
execution: a round-robin of pairwise comparisons of the idea SETS the entrant
models produced for one zone. A direct comparison is more reliable than two
absolute scores — the same principle the judge-ensemble spec uses for attack
ranking, applied one level earlier.

Never raises: a failed pairwise call drops that comparison; an empty idea set
is a forfeit, not a crash.
"""

from __future__ import annotations

import itertools
import logging
import uuid

from interfaces.llm import LLMClient, LLMMessage, extract_json
from interfaces.types import ModelZoneWinrate, TournamentRound

LOG = logging.getLogger("monkeyclaw.red.ideation_tournament")

_H2H_WEIGHT_DEFAULT = 0.6
_NEUTRAL_WINRATE = 0.5

_COMPARE_SYSTEM = """\
You are the IDEATION TOURNAMENT judge in a red-team exercise. You are given
two entrant models' idea sets (A and B) for the SAME attack-surface zone.
Answer ONE question: which entrant's idea set is the stronger basis for
attacking this zone — more genuinely distinct approaches, more zone-relevant
exploitation, fewer textbook repeats?

Output JSON only — no prose, no markdown fences:

{
  "winner": "A" | "B",
  "margin": 0.0 to 1.0,
  "reasoning": "one paragraph"
}
"""


def _idea_set_block(label: str, ideas: list[object]) -> str:
    lines = [f"# Entrant {label}"]
    for i, idea in enumerate(ideas):
        lines.append(
            f"  idea {i + 1}: {getattr(idea, 'title', '?')} | "
            f"approach: {getattr(idea, 'approach', '')} | "
            f"novelty: {getattr(idea, 'novelty_note', '')} | "
            f"tactics: {getattr(idea, 'tactic_tags', [])}"
        )
    return "\n".join(lines)


class IdeationTournamentJudge:
    """Round-robin pairwise judge of entrant idea sets + win-rate fold."""

    def __init__(self, llm: LLMClient, mcp: object | None = None,
                 h2h_weight: float = _H2H_WEIGHT_DEFAULT) -> None:
        self.llm = llm
        self.mcp = mcp
        self.h2h_weight = h2h_weight

    def _compare(self, zone_id: str, label_a: str, ideas_a: list[object],
                 label_b: str, ideas_b: list[object]) -> dict | None:
        """One pairwise comparison. Forfeit on empty set; None on LLM
        failure."""
        if not ideas_a and not ideas_b:
            return None
        if not ideas_b:
            return {"a": label_a, "b": label_b,
                    "winner": label_a, "margin": 1.0}
        if not ideas_a:
            return {"a": label_a, "b": label_b,
                    "winner": label_b, "margin": 1.0}
        user = (
            f"Zone: {zone_id}\n\n"
            f"{_idea_set_block('A', ideas_a)}\n\n"
            f"{_idea_set_block('B', ideas_b)}\n\n"
            f"Compare now. Output JSON only."
        )
        try:
            resp = self.llm.complete(
                messages=[LLMMessage(role="user", content=user)],
                system=_COMPARE_SYSTEM, max_tokens=600, temperature=0.2,
            )
        except Exception as e:  # noqa: BLE001 - a failed pair is dropped
            LOG.warning("ideation pairwise call failed (%s vs %s): %r",
                        label_a, label_b, e)
            return None
        try:
            data = extract_json(resp.text)
        except ValueError:
            LOG.warning("ideation pairwise unparseable: %r", resp.text[:200])
            return None
        if isinstance(data, list):
            data = data[0] if data else {}
        if not isinstance(data, dict):
            return None
        winner = str(data.get("winner", "")).upper()
        if winner not in ("A", "B"):
            return None
        margin = max(0.0, min(1.0, float(data.get("margin", 0.0) or 0.0)))
        win_label = label_a if winner == "A" else label_b
        return {"a": label_a, "b": label_b,
                "winner": win_label, "margin": margin}

    def judge_round(self, zone_id: str, cycle_id: int,
                    idea_sets: dict[str, list[object]]) -> TournamentRound:
        """Run the round-robin pairwise comparisons for one zone."""
        labels = sorted(idea_sets)
        pairwise: list[dict] = []
        for label_a, label_b in itertools.combinations(labels, 2):
            result = self._compare(zone_id, label_a, idea_sets[label_a],
                                   label_b, idea_sets[label_b])
            if result is not None:
                pairwise.append(result)
        wins: dict[str, int] = {label: 0 for label in labels}
        for p in pairwise:
            wins[p["winner"]] = wins.get(p["winner"], 0) + 1
        winner_label = max(wins, key=wins.get) if wins else ""
        rnd = TournamentRound(
            round_id=f"round-{uuid.uuid4().hex[:12]}",
            cycle_id=cycle_id, zone_id=zone_id,
            entrants=labels, pairwise=pairwise, winner_label=winner_label,
        )
        if self.mcp is not None:
            try:
                self.mcp.log_tournament_round(rnd)
            except Exception as e:  # noqa: BLE001 - persistence best-effort
                LOG.warning("failed to log tournament round: %r", e)
        return rnd

    def update_winrate(
        self,
        round: TournamentRound,
        execution_outcomes: dict[str, dict[str, int]],
        prior: dict[tuple[str, str], ModelZoneWinrate] | None = None,
    ) -> list[ModelZoneWinrate]:
        """Fold the round's head-to-head wins and the cycle's execution
        verdicts into the per-zone win-rate (spec §8). `prior` is the
        persisted state keyed (zone_id, model_label); each returned row is
        the accumulated, recomputed win-rate. Best-effort MCP persistence."""
        prior = prior or {}
        zone = round.zone_id
        # Tally this round's head-to-head wins / comparisons per entrant.
        h2h_w: dict[str, int] = {label: 0 for label in round.entrants}
        h2h_c: dict[str, int] = {label: 0 for label in round.entrants}
        for p in round.pairwise:
            for side in ("a", "b"):
                label = p.get(side)
                if label in h2h_c:
                    h2h_c[label] += 1
            if p.get("winner") in h2h_w:
                h2h_w[p["winner"]] += 1

        rows: list[ModelZoneWinrate] = []
        labels = set(round.entrants) | set(execution_outcomes)
        for label in sorted(labels):
            base = prior.get((zone, label))
            row = ModelZoneWinrate(
                zone_id=zone, model_label=label,
                role=base.role if base else "",
                h2h_wins=(base.h2h_wins if base else 0) + h2h_w.get(label, 0),
                h2h_comparisons=(base.h2h_comparisons if base else 0)
                + h2h_c.get(label, 0),
            )
            exec_out = execution_outcomes.get(label, {})
            row.confirmed = ((base.confirmed if base else 0)
                             + int(exec_out.get("confirmed", 0)))
            row.suspicious = ((base.suspicious if base else 0)
                              + int(exec_out.get("suspicious", 0)))
            row.ideas_executed = ((base.ideas_executed if base else 0)
                                  + int(exec_out.get("ideas_executed", 0)))
            row.winrate = self._combined_winrate(row)
            rows.append(row)
            if self.mcp is not None:
                try:
                    self.mcp.update_model_zone_winrate(row)
                except Exception as e:  # noqa: BLE001 - best-effort
                    LOG.warning("failed to persist win-rate: %r", e)
        return rows

    def _combined_winrate(self, row: ModelZoneWinrate) -> float:
        """The §8 win-rate. With no h2h and no execution evidence at all,
        the neutral prior (0.5) is preserved so routing stays optimistic."""
        if row.h2h_comparisons == 0 and row.ideas_executed == 0:
            return _NEUTRAL_WINRATE
        h2h_rate = row.h2h_wins / max(row.h2h_comparisons, 1)
        exec_rate = ((row.confirmed + 0.5 * row.suspicious)
                     / max(row.ideas_executed, 1))
        return (self.h2h_weight * h2h_rate
                + (1.0 - self.h2h_weight) * exec_rate)


__all__ = ["IdeationTournamentJudge"]
