"""B1 — deterministic planted-victim attack playbooks.

A playbook is a fixed, scripted multi-turn attack (no LLM in the loop) that
reliably triggers a known planted vulnerability. Playbooks make the demo
deterministic: the same turns, the same outcome, every run.

YAML fixtures live in demo/attacks/*.yaml. Each playbook becomes an
`IdeaObject` (source_mode="playbook") carrying the scripted turns on
`idea.playbook`; `ExecutionAgent` detects that attribute and replays the
turns verbatim instead of running the LLM attacker.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from pathlib import Path

import yaml

from interfaces.types import IdeaObject
from red_team.ideation import IdeaTactics

LOG = logging.getLogger("monkeyclaw.red.playbooks")

# demo/attacks resolved relative to the repo root (this file is
# red_team/playbooks.py), so it works regardless of the process cwd.
DEFAULT_PLAYBOOK_DIR = Path(__file__).resolve().parents[1] / "demo" / "attacks"

# The five deterministic playbook profiles required by spec B1.
PLAYBOOK_PROFILES = (
    "filesystem_escape_write",
    "pii_cloud_route_bypass",
    "prompt_injection_document_instruction",
    "skill_poison_manifest",
    "memory_poisoning_multi_turn",
)

_IMPACTS = {"critical", "high", "medium", "low"}


@dataclass
class Playbook:
    """A scripted attack: a fixed ordered list of attacker messages."""
    name: str
    profile: str
    zone_id: str
    description: str
    turns: list[str]
    success_criteria: str
    failure_class: str = "none"
    severity: str = "high"
    target_victim: str = ""
    tactic_tags: list[str] = field(default_factory=list)

    @property
    def impact(self) -> str:
        return self.severity if self.severity in _IMPACTS else "high"


def _coerce_playbook(raw: object, source: str) -> Playbook | None:
    """Build a Playbook from a parsed YAML object. Returns None for files
    that are not playbook-shaped (no `turns` key — e.g. policy_corpus.yaml)."""
    if not isinstance(raw, dict) or "turns" not in raw:
        return None
    turns = [str(t) for t in (raw.get("turns") or []) if str(t).strip()]
    if not turns:
        raise ValueError(f"playbook {source} declares no usable turns")
    name = str(raw.get("name") or Path(source).stem)
    return Playbook(
        name=name,
        profile=str(raw.get("profile", name)),
        zone_id=str(raw.get("zone") or raw.get("zone_id") or ""),
        description=str(raw.get("description", "")),
        turns=turns,
        success_criteria=str(raw.get("success_criteria", "")),
        failure_class=str(raw.get("failure_class", "none")),
        severity=str(raw.get("severity", "high")),
        target_victim=str(raw.get("target_victim", "")),
        tactic_tags=[str(t) for t in (raw.get("tactic_tags") or [])],
    )


def load_playbooks(path: str | Path | None = None) -> list[Playbook]:
    """Load every playbook YAML in demo/attacks/. Files without a `turns`
    key are skipped, so policy_corpus.yaml is ignored cleanly."""
    directory = Path(path) if path else DEFAULT_PLAYBOOK_DIR
    if not directory.is_dir():
        raise FileNotFoundError(f"playbook directory not found: {directory}")
    playbooks: list[Playbook] = []
    for yml in sorted(directory.glob("*.yaml")):
        try:
            raw = yaml.safe_load(yml.read_text())
        except yaml.YAMLError as e:
            raise ValueError(f"playbook {yml.name} is not valid YAML: {e}") from e
        pb = _coerce_playbook(raw, yml.name)
        if pb is not None:
            playbooks.append(pb)
    return playbooks


def playbook_to_idea(pb: Playbook, cycle_id: int) -> IdeaObject:
    """Turn a playbook into an IdeaObject, with the scripted turns attached
    on `idea.playbook` for ExecutionAgent to replay deterministically."""
    approach = (pb.description or pb.profile) + "\n\nScripted turns:\n" + "\n".join(
        f"{i}. {t}" for i, t in enumerate(pb.turns, start=1))
    idea = IdeaObject(
        idea_id=f"PLAYBOOK-{pb.name}",
        cycle_id=cycle_id,
        zone_id=pb.zone_id,
        source_mode="playbook",
        title=f"Playbook: {pb.profile}",
        approach=approach,
        success_criteria=pb.success_criteria,
        estimated_turns=len(pb.turns),
        novelty_notes=f"[impact={pb.impact}] deterministic playbook {pb.profile}",
    )
    idea.playbook = pb
    idea.tactics = IdeaTactics(
        tactic_tags=list(pb.tactic_tags),
        interaction_style="multi_turn" if len(pb.turns) > 1 else "direct",
        mutation_seed=pb.profile,
        impact=pb.impact,
    )
    return idea


def load_playbook_ideas(
    cycle_id: int, path: str | Path | None = None,
) -> list[IdeaObject]:
    """Load all playbooks and convert them to executable IdeaObjects."""
    ideas = [playbook_to_idea(pb, cycle_id) for pb in load_playbooks(path)]
    LOG.info("loaded %d playbook idea(s) for cycle %d", len(ideas), cycle_id)
    return ideas


__all__ = [
    "DEFAULT_PLAYBOOK_DIR",
    "PLAYBOOK_PROFILES",
    "Playbook",
    "load_playbook_ideas",
    "load_playbooks",
    "playbook_to_idea",
]
