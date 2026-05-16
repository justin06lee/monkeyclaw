"""Decides which mutation operators each generalization round runs.

Round 0 runs the full twelve-operator catalogue (cheap — deterministic
string ops plus one replay each). Later rounds run a focused budget: every
operator that bypassed in a prior round (re-test the re-patch closed it)
plus the zone-relevant operators. The zone -> operator affinity map is the
one piece of policy most likely to be tuned, so it lives here alone.
"""

from __future__ import annotations

from red_team.mutations import MUTATION_OPERATORS

# Zone -> the operators most likely to find a bypass in that zone.
_ZONE_AFFINITY: dict[str, tuple[str, ...]] = {
    "PROMPT-INJ": ("insert_untrusted_document",
                   "move_instruction_into_tool_output", "paraphrase"),
    "SKILL-SUPPLY": ("move_instruction_into_dependency_metadata",
                     "add_benign_framing"),
    "SKILL-INSTALL": ("move_instruction_into_dependency_metadata",
                      "insert_untrusted_document"),
    "SOCIAL-ENG": ("change_persona", "add_benign_framing", "paraphrase"),
    "SBX-NET": ("split_into_multi_turn", "concretize_final_request"),
    "SBX-FS": ("concretize_final_request", "split_into_multi_turn"),
    "AGENT-COMMS": ("move_instruction_into_tool_output",
                    "reverse_component_order"),
}
# A focused-round fallback for zones without an explicit affinity entry.
_DEFAULT_FOCUS: tuple[str, ...] = (
    "paraphrase", "add_benign_framing", "concretize_final_request")


def budget_for(
    round_index: int,
    zone_id: str,
    prior_bypass_operators: list[str],
) -> list[str]:
    """The operator list for a generalization round. Round 0 is exhaustive;
    later rounds run the prior-bypass operators plus the zone-relevant ones,
    deduplicated, in canonical catalogue order for determinism."""
    if round_index == 0:
        return list(MUTATION_OPERATORS)
    wanted = set(prior_bypass_operators)
    wanted |= set(_ZONE_AFFINITY.get(zone_id, _DEFAULT_FOCUS))
    # Drop anything not in the catalogue; keep canonical order.
    return [op for op in MUTATION_OPERATORS if op in wanted]


__all__ = ["budget_for"]
