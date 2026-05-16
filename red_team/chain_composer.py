"""Cross-zone chaining: turn ChainSkeletons into validated AttackChains.

For each skeleton step the composer binds a concrete primitive (a cycle
IdeaObject or an archive ArchiveEntry), assigns requires/produces capability
tokens from a per-zone default map, enforces the chain invariant (every
required token is produced by an earlier step — reordering when a valid order
exists, dropping the chain when not), and assigns a heuristic priority.
"""

from __future__ import annotations

import logging
import uuid

from interfaces.types import AttackChain, ChainSkeleton, ChainStep, IdeaObject

from red_team.archive import EliteArchive
from red_team.chain_tokens import validate_tokens

LOG = logging.getLogger("monkeyclaw.red.chain_composer")

# Per-zone default capability tokens — what a landed step in this zone yields
# (produces) and what it typically needs first (requires). Coarse by design.
_ZONE_TOKEN_MAP: dict[str, tuple[list[str], list[str]]] = {
    # zone: (produces, requires)
    "PROMPT-INJ": (["foothold.instruction_executed", "foothold.context_poisoned"], []),
    "SOCIAL-ENG": (["foothold.instruction_executed"], []),
    "PRV-LEAK": (["secret.value_captured"], ["foothold.instruction_executed"]),
    "PRV-ROUTE": (["control.routing_subverted"], ["foothold.instruction_executed"]),
    "SBX-FS": (["access.file_read", "secret.credential_captured"],
               ["foothold.instruction_executed"]),
    "SBX-NET": (["egress.channel_open", "egress.data_exfiltrated"],
                ["secret.value_captured"]),
    "SBX-PROC": (["access.tool_invoked"], ["foothold.instruction_executed"]),
    "SBX-IPC": (["access.tool_invoked"], ["foothold.instruction_executed"]),
    "PERM-MODEL": (["control.policy_modified", "access.permission_escalated"],
                   ["foothold.instruction_executed"]),
    "PERM-RUNTIME": (["access.permission_escalated"],
                     ["foothold.instruction_executed"]),
    "SKILL-INSTALL": (["persistence.skill_installed"],
                      ["foothold.instruction_executed"]),
    "SKILL-EXEC": (["access.tool_invoked"], ["foothold.instruction_executed"]),
    "SKILL-SUPPLY": (["persistence.skill_installed"], []),
    "MEM-STATE": (["persistence.memory_written"],
                  ["foothold.instruction_executed"]),
    "MEM-SHARED": (["persistence.memory_written"],
                   ["foothold.instruction_executed"]),
    "INF-ROUTE": (["control.routing_subverted"],
                  ["foothold.instruction_executed"]),
    "INF-LOCAL": (["recon.target_identified"], []),
    "AGENT-COMM": (["recon.path_discovered"], ["foothold.instruction_executed"]),
}
# A safe default for any zone not in the map: a recon step that needs nothing.
_DEFAULT_TOKENS: tuple[list[str], list[str]] = (["recon.target_identified"], [])


def _tokens_for_zone(zone: str) -> tuple[list[str], list[str]]:
    return _ZONE_TOKEN_MAP.get(zone, _DEFAULT_TOKENS)


def _resolve_primitive(
    ref: str,
    ideas_by_id: dict[str, IdeaObject],
    archive: EliteArchive,
) -> tuple[str, str] | None:
    """Return (approach, primitive_ref) for a skeleton step's reference.

    A plain ref is a cycle idea_id. An "ARCH:zone|style|movement" ref is an
    archive cell key. Returns None if the primitive cannot be resolved.
    """
    if ref.startswith("ARCH:"):
        try:
            zone, style, movement = ref[len("ARCH:"):].split("|")
        except ValueError:
            return None
        try:
            elite = archive.get_elite(zone, style, movement)
        except ValueError:
            return None
        if elite is None:
            return None
        return (elite.approach or elite.idea_title, ref)
    idea = ideas_by_id.get(ref)
    if idea is None:
        return None
    return (idea.approach, ref)


def _try_order(steps: list[ChainStep]) -> list[ChainStep] | None:
    """Greedy topological order — pick the next step whose requires are met.

    Returns a reordered list satisfying the invariant, or None if no order
    does. Chains are short (<= 7 steps) so the greedy pass is sufficient.
    """
    remaining = list(steps)
    ordered: list[ChainStep] = []
    available: set[str] = set()
    while remaining:
        pick = next(
            (s for s in remaining if set(s.requires) <= available), None)
        if pick is None:
            return None
        ordered.append(pick)
        available |= set(pick.produces)
        remaining.remove(pick)
    for idx, step in enumerate(ordered):
        step.step_index = idx
    return ordered


def _priority(chain: AttackChain, ideas_by_id: dict[str, IdeaObject]) -> float:
    """Heuristic chain priority: summed source-primitive priority, rewarded
    for distinct-zone breadth, lightly discounted for length."""
    base = 0.0
    for step in chain.steps:
        idea = ideas_by_id.get(step.primitive_ref)
        base += idea.priority_score if idea is not None else 0.5
    distinct_zones = len(set(chain.zones))
    return round(base * (1.0 + 0.3 * (distinct_zones - 1))
                 / (1.0 + 0.05 * len(chain.steps)), 4)


def compose(
    skeletons: list[ChainSkeleton],
    ideas_by_id: dict[str, IdeaObject],
    archive: EliteArchive,
    cycle_id: int,
) -> list[AttackChain]:
    """Compose validated AttackChains from ChainSkeletons.

    Never raises — a skeleton that cannot be resolved or ordered is dropped
    with a logged reason. Returned chains are sorted highest-priority first.
    """
    chains: list[AttackChain] = []
    priorities: dict[str, float] = {}
    for sk in skeletons:
        steps: list[ChainStep] = []
        ok = True
        for idx, (zone, objective, ref) in enumerate(sk.step_specs):
            resolved = _resolve_primitive(ref, ideas_by_id, archive)
            if resolved is None:
                LOG.warning("compose: skeleton %r — unresolvable primitive %r",
                            sk.title, ref)
                ok = False
                break
            approach, primitive_ref = resolved
            produces, requires = _tokens_for_zone(zone)
            try:
                validate_tokens(produces)
                validate_tokens(requires)
            except ValueError as e:
                LOG.warning("compose: skeleton %r — %s", sk.title, e)
                ok = False
                break
            steps.append(ChainStep(
                step_index=idx, zone_id=zone, objective=objective,
                primitive_ref=primitive_ref, approach=approach,
                requires=requires, produces=produces,
                success_signal=objective,
            ))
        if not ok or not steps:
            continue
        # Order the steps so every step's requires are produced earlier; a
        # skeleton whose steps cannot be ordered that way is dropped.
        ordered = _try_order(steps)
        if ordered is None:
            LOG.warning("compose: skeleton %r dropped — chain invariant "
                        "unsatisfiable", sk.title)
            continue
        steps = ordered
        # The first step in execution order has no earlier step to depend on,
        # so it cannot require anything — clear its requires.
        steps[0].requires = []
        chain = AttackChain(
            chain_id=f"CHAIN-{uuid.uuid4().hex[:10]}",
            cycle_id=cycle_id,
            title=sk.title,
            zones=[s.zone_id for s in steps],
            primary_zone=steps[-1].zone_id,
            steps=steps,
            builds_on=[s.primitive_ref for s in steps],
            estimated_turns=sk.estimated_turns,
            rationale=sk.rationale,
        )
        chains.append(chain)
        priorities[chain.chain_id] = _priority(chain, ideas_by_id)
    chains.sort(key=lambda c: priorities[c.chain_id], reverse=True)
    return chains


__all__ = ["compose"]
