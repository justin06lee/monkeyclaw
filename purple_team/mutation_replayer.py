"""Applies red-team mutation operators to a verified patch's minimal
transcript and replays each variant against the patched victim.

Consumes red_team.mutations read-only. The replay function is the same
PatchedReplayFactory output the verifier's gates use, so a variant is
replayed against exactly the patched surface the verifier proved.
"""

from __future__ import annotations

import logging
from collections.abc import Callable

from interfaces.types import LaneResult, Message, MutationVariant
from red_team.mutations import apply_operator

LOG = logging.getLogger("monkeyclaw.purple.mutation_replayer")

# Operators whose output is a multi-turn block that must be re-split into
# separate attacker Message turns before replay.
_MULTI_TURN_OPERATORS = frozenset(
    {"split_into_multi_turn", "reverse_component_order"})

ReplayFn = Callable[[list[Message]], LaneResult]


class MutationReplayer:
    """Produces MutationVariant records for a budget of operators."""

    def __init__(self, replay_fn: ReplayFn) -> None:
        self.replay_fn = replay_fn

    def _attacker_turns(self, package: object) -> list[Message]:
        transcript = getattr(package, "transcripts", {}).get("minimal", [])
        return [m for m in transcript if m.role == "attacker"]

    def _mutated_transcript(
        self, operator: str, package: object
    ) -> list[Message]:
        """Apply `operator` to each attacker turn of the minimal transcript,
        rebuilding the turn list. Multi-turn-producing operators are
        re-split on newlines into separate attacker turns."""
        transcript = list(
            getattr(package, "transcripts", {}).get("minimal", []))
        out: list[Message] = []
        for msg in transcript:
            if msg.role != "attacker":
                out.append(msg)
                continue
            mutated = apply_operator(operator, msg.content)
            if operator in _MULTI_TURN_OPERATORS:
                lines = [ln.strip() for ln in mutated.splitlines()
                         if ln.strip()]
                for ln in (lines or [mutated]):
                    out.append(Message(role="attacker", content=ln,
                                       timestamp=msg.timestamp))
            else:
                out.append(Message(role="attacker", content=mutated,
                                   timestamp=msg.timestamp))
        return out

    def replay_variants(
        self, patch: object, package: object, operators: list[str]
    ) -> list[MutationVariant]:
        """One MutationVariant per operator. An operator or replay that
        raises yields a variant with `replay_result=None` (scored
        `inconclusive` downstream) — one bad operator never aborts a round."""
        _ = patch  # the replay_fn already encloses the patched victim
        variants: list[MutationVariant] = []
        for i, operator in enumerate(operators):
            variant_id = f"V{i:02d}-{operator}"
            try:
                mutated = self._mutated_transcript(operator, package)
                replay = self.replay_fn(mutated)
            except Exception as e:  # noqa: BLE001
                LOG.warning("operator %s failed: %s — variant inconclusive",
                            operator, e)
                variants.append(MutationVariant(
                    variant_id=variant_id, operator=operator,
                    mutated_transcript=[], replay_result=None))
                continue
            variants.append(MutationVariant(
                variant_id=variant_id, operator=operator,
                mutated_transcript=mutated, replay_result=replay))
        return variants


__all__ = ["MutationReplayer", "ReplayFn"]
