"""Preloaded attack-skill corpus loader.

Research-grounded ideation priors. The YAML files in ``red_team/attack_skills/``
are the source of truth; this module parses and validates them into
``AttackSkill`` records. It is a pure module — no DB, no network, no side
effects — mirroring ``red_team/policy_corpus.py``.

Public API
----------
- ``AttackSkill``           -- dataclass mirroring one skill YAML file.
- ``load_attack_skills()``  -- parse + validate the whole corpus.
- ``skills_for_zone()``     -- filter the corpus by zone (keeps modifiers).
- ``content_hash()``        -- stable hash of a skill, for idempotent seeding.

Skills feed Mode D ("research_grounded") of the ideation engine. They are
distinct from B1 playbooks (deterministic replay) and the B7 policy corpus
(pass/fail policy fixtures): a skill is an open-ended *prior*, never replayed
verbatim and carrying no expected verdict.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from pathlib import Path

import yaml

from red_team.ideation import (
    INTERACTION_STYLES,
    OBSERVABLE_KINDS,
    TARGET_DEFENSES,
)
from red_team.policy_corpus import KNOWN_ZONES

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# red_team/attack_skills/ lives next to this module.
DEFAULT_SKILLS_DIR = Path(__file__).resolve().parent / "attack_skills"

KINDS: frozenset[str] = frozenset({"pattern", "modifier"})
PROVENANCES: frozenset[str] = frozenset({"research", "extrapolated"})
SEVERITIES: frozenset[str] = frozenset({"critical", "high", "medium", "low"})

# The 8 failure classes from the Securing Coding Agents PDF (§3.2).
FAILURE_CLASSES: frozenset[str] = frozenset(
    {
        "secrets_exposure",
        "command_execution",
        "mcp_tool_poisoning",
        "approval_fatigue",
        "settings_drift",
        "browser_desktop_expansion",
        "cloud_execution_drift",
        "audit_gaps",
    }
)

# Sentinel zone for cross-cutting modifier skills (e.g. declarative framing).
ALL_ZONES = "ALL"

# Fields that must be present in every skill YAML file.
_REQUIRED = (
    "skill_id",
    "name",
    "kind",
    "provenance",
    "sources",
    "zone_ids",
    "failure_class",
    "interaction_style",
    "target_defense",
    "severity_hint",
    "technique",
    "approach_template",
    "success_criteria_template",
)


# ---------------------------------------------------------------------------
# Dataclass
# ---------------------------------------------------------------------------


@dataclass
class AttackSkill:
    """One preloaded attack-skill record, mirroring a YAML file."""

    skill_id: str
    name: str
    kind: str  # pattern | modifier
    provenance: str  # research | extrapolated
    sources: list[str]
    zone_ids: list[str]  # 1+ KNOWN_ZONES, or ["ALL"] for modifiers
    failure_class: str
    interaction_style: str
    target_defense: str
    severity_hint: str
    technique: str
    approach_template: str
    success_criteria_template: str
    tactic_tags: list[str] = field(default_factory=list)
    estimated_turns: int = 5
    preconditions: str = ""
    example_payloads: list[str] = field(default_factory=list)
    variants: list[str] = field(default_factory=list)
    expected_observables: list[str] = field(default_factory=list)
    mutation_seeds: list[str] = field(default_factory=list)

    @property
    def is_modifier(self) -> bool:
        return self.kind == "modifier"

    def embedding_text(self) -> str:
        """The text embedded for zone-similarity retrieval."""
        return f"{self.name}\n{self.technique}\n{self.approach_template}"


# ---------------------------------------------------------------------------
# Loading + validation
# ---------------------------------------------------------------------------


def _as_str_list(value: object, field_name: str, skill_id: str) -> list[str]:
    """Coerce a YAML field into a list[str]; raise on the wrong shape."""
    if value is None:
        return []
    if not isinstance(value, list):
        raise ValueError(
            f"attack skill {skill_id!r}: {field_name!r} must be a list, "
            f"got {type(value).__name__}"
        )
    return [str(item) for item in value]


def _validate_skill(raw: dict, index: int) -> AttackSkill:
    """Build + validate a single skill record; raise ValueError on bad data."""
    if not isinstance(raw, dict):
        raise ValueError(f"attack skill #{index} is not a mapping: {raw!r}")

    for key in _REQUIRED:
        if key not in raw or raw[key] in (None, ""):
            raise ValueError(
                f"attack skill #{index} missing required field {key!r}"
            )

    skill_id = str(raw["skill_id"])

    kind = str(raw["kind"])
    if kind not in KINDS:
        raise ValueError(
            f"attack skill {skill_id!r} has invalid kind {kind!r}; "
            f"valid: {sorted(KINDS)}"
        )

    provenance = str(raw["provenance"])
    if provenance not in PROVENANCES:
        raise ValueError(
            f"attack skill {skill_id!r} has invalid provenance "
            f"{provenance!r}; valid: {sorted(PROVENANCES)}"
        )

    zone_ids = _as_str_list(raw["zone_ids"], "zone_ids", skill_id)
    if not zone_ids:
        raise ValueError(f"attack skill {skill_id!r} has empty zone_ids")
    if kind == "modifier":
        if zone_ids != [ALL_ZONES]:
            raise ValueError(
                f"attack skill {skill_id!r} is a modifier and must have "
                f"zone_ids: [{ALL_ZONES}]"
            )
    else:
        bad = [z for z in zone_ids if z not in KNOWN_ZONES]
        if bad:
            raise ValueError(
                f"attack skill {skill_id!r} references unknown zone(s) "
                f"{bad}; valid: {sorted(KNOWN_ZONES)}"
            )

    sources = _as_str_list(raw["sources"], "sources", skill_id)
    if provenance == "research" and not sources:
        raise ValueError(
            f"attack skill {skill_id!r} has provenance=research but no "
            f"sources; cite the research material or mark it extrapolated"
        )

    failure_class = str(raw["failure_class"])
    if failure_class not in FAILURE_CLASSES:
        raise ValueError(
            f"attack skill {skill_id!r} has invalid failure_class "
            f"{failure_class!r}; valid: {sorted(FAILURE_CLASSES)}"
        )

    style = str(raw["interaction_style"])
    if style not in INTERACTION_STYLES:
        raise ValueError(
            f"attack skill {skill_id!r} has invalid interaction_style "
            f"{style!r}; valid: {sorted(INTERACTION_STYLES)}"
        )

    defense = str(raw["target_defense"])
    if defense not in TARGET_DEFENSES:
        raise ValueError(
            f"attack skill {skill_id!r} has invalid target_defense "
            f"{defense!r}; valid: {sorted(TARGET_DEFENSES)}"
        )

    severity = str(raw["severity_hint"])
    if severity not in SEVERITIES:
        raise ValueError(
            f"attack skill {skill_id!r} has invalid severity_hint "
            f"{severity!r}; valid: {sorted(SEVERITIES)}"
        )

    observables = _as_str_list(
        raw.get("expected_observables"), "expected_observables", skill_id
    )
    bad_obs = [o for o in observables if o not in OBSERVABLE_KINDS]
    if bad_obs:
        raise ValueError(
            f"attack skill {skill_id!r} has unknown expected_observables "
            f"{bad_obs}; valid: {sorted(OBSERVABLE_KINDS)}"
        )

    try:
        estimated_turns = int(raw.get("estimated_turns", 5))
    except (TypeError, ValueError) as exc:
        raise ValueError(
            f"attack skill {skill_id!r} has non-integer estimated_turns"
        ) from exc

    return AttackSkill(
        skill_id=skill_id,
        name=str(raw["name"]),
        kind=kind,
        provenance=provenance,
        sources=sources,
        zone_ids=zone_ids,
        failure_class=failure_class,
        interaction_style=style,
        target_defense=defense,
        severity_hint=severity,
        technique=str(raw["technique"]),
        approach_template=str(raw["approach_template"]),
        success_criteria_template=str(raw["success_criteria_template"]),
        tactic_tags=_as_str_list(
            raw.get("tactic_tags"), "tactic_tags", skill_id
        ),
        estimated_turns=estimated_turns,
        preconditions=str(raw.get("preconditions", "")),
        example_payloads=_as_str_list(
            raw.get("example_payloads"), "example_payloads", skill_id
        ),
        variants=_as_str_list(raw.get("variants"), "variants", skill_id),
        expected_observables=observables,
        mutation_seeds=_as_str_list(
            raw.get("mutation_seeds"), "mutation_seeds", skill_id
        ),
    )


def load_attack_skills(path: str | Path | None = None) -> list[AttackSkill]:
    """Load + validate every ``*.yaml`` file under the attack-skills directory.

    ``path`` defaults to ``red_team/attack_skills/`` resolved relative to this
    module. Raises ``ValueError`` if the directory is missing, a file is
    malformed, any skill fails validation, or two skills share a ``skill_id``.
    Skills are returned sorted by ``skill_id`` for deterministic ordering.
    """
    skills_dir = Path(path) if path is not None else DEFAULT_SKILLS_DIR
    if not skills_dir.is_dir():
        raise ValueError(f"attack-skills directory not found: {skills_dir}")

    skills: list[AttackSkill] = []
    for index, yml in enumerate(sorted(skills_dir.glob("*.yaml"))):
        try:
            raw = yaml.safe_load(yml.read_text(encoding="utf-8"))
        except yaml.YAMLError as exc:
            raise ValueError(
                f"attack skill {yml.name} is not valid YAML: {exc}"
            ) from exc
        skills.append(_validate_skill(raw, index))

    if not skills:
        raise ValueError(f"no attack skills found in {skills_dir}")

    seen: set[str] = set()
    for skill in skills:
        if skill.skill_id in seen:
            raise ValueError(f"duplicate attack skill_id {skill.skill_id!r}")
        seen.add(skill.skill_id)

    return sorted(skills, key=lambda s: s.skill_id)


# ---------------------------------------------------------------------------
# Queries
# ---------------------------------------------------------------------------


def skills_for_zone(
    zone_id: str,
    skills: list[AttackSkill] | None = None,
    include_modifiers: bool = True,
) -> list[AttackSkill]:
    """Return the pattern skills mapped to ``zone_id``.

    Modifier skills (cross-cutting, ``zone_ids: [ALL]``) are appended when
    ``include_modifiers`` is set — Mode D always wants them as phrasing
    guidance regardless of the target zone.
    """
    if skills is None:
        skills = load_attack_skills()
    patterns = [
        s for s in skills if not s.is_modifier and zone_id in s.zone_ids
    ]
    if include_modifiers:
        patterns += [s for s in skills if s.is_modifier]
    return patterns


# ---------------------------------------------------------------------------
# Hashing — supports idempotent DB seeding
# ---------------------------------------------------------------------------


def content_hash(skill: AttackSkill) -> str:
    """Stable sha256 of a skill's content, independent of field order.

    Used by the seeder to skip unchanged rows and update edited ones.
    """
    payload = {
        "skill_id": skill.skill_id,
        "name": skill.name,
        "kind": skill.kind,
        "provenance": skill.provenance,
        "sources": skill.sources,
        "zone_ids": skill.zone_ids,
        "failure_class": skill.failure_class,
        "interaction_style": skill.interaction_style,
        "target_defense": skill.target_defense,
        "severity_hint": skill.severity_hint,
        "technique": skill.technique,
        "approach_template": skill.approach_template,
        "success_criteria_template": skill.success_criteria_template,
        "tactic_tags": skill.tactic_tags,
        "estimated_turns": skill.estimated_turns,
        "preconditions": skill.preconditions,
        "example_payloads": skill.example_payloads,
        "variants": skill.variants,
        "expected_observables": skill.expected_observables,
        "mutation_seeds": skill.mutation_seeds,
    }
    blob = json.dumps(payload, sort_keys=True, ensure_ascii=False)
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()


__all__ = [
    "ALL_ZONES",
    "AttackSkill",
    "DEFAULT_SKILLS_DIR",
    "FAILURE_CLASSES",
    "KINDS",
    "PROVENANCES",
    "SEVERITIES",
    "content_hash",
    "load_attack_skills",
    "skills_for_zone",
]
