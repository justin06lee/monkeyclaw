"""Cross-zone chaining: the committed capability-token vocabulary.

A capability token is a short controlled string naming what a ChainStep
yields (``produces``) or needs (``requires``). The composer uses them to
enforce the chain invariant: every token a step requires must be produced by
an earlier step. The vocabulary is deliberately coarse — it expresses
*dependency between steps*, not a full attack ontology.

Pure data + one function, stdlib only — the counterpart of MUTATION_OPERATORS
in red_team/mutations.py.
"""

from __future__ import annotations

CAPABILITY_TOKENS: tuple[str, ...] = (
    # Foothold — an instruction the attacker controls is now running.
    "foothold.instruction_executed",
    "foothold.context_poisoned",
    # Recon — the attacker has learned something exploitable.
    "recon.target_identified",
    "recon.path_discovered",
    # Access — the attacker reached a resource.
    "access.file_read",
    "access.tool_invoked",
    "access.permission_escalated",
    # Secret — sensitive data is in the attacker's hands.
    "secret.value_captured",
    "secret.credential_captured",
    # Egress — a channel out of the sandbox is usable.
    "egress.channel_open",
    "egress.data_exfiltrated",
    # Persistence — the attacker can survive a reset.
    "persistence.memory_written",
    "persistence.skill_installed",
    # Control — a policy/permission boundary has moved.
    "control.policy_modified",
    "control.routing_subverted",
)

_VALID_TOKENS = frozenset(CAPABILITY_TOKENS)


def validate_tokens(tokens: list[str]) -> None:
    """Raise ValueError if any token is not in the committed vocabulary."""
    for token in tokens:
        if token not in _VALID_TOKENS:
            raise ValueError(
                f"unknown capability token {token!r}; expected one of "
                f"{sorted(_VALID_TOKENS)}"
            )


__all__ = ["CAPABILITY_TOKENS", "validate_tokens"]
