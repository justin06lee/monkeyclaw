"""Seed the ``attack_skills`` table from the ``red_team/attack_skills/`` corpus.

The YAML corpus is the source of truth; this populates the derived DB index so
a fresh database already carries the preloaded attack-skill priors that Mode D
("research_grounded") ideation draws on — the red agent never cold-starts.

Seeding is idempotent: rows are keyed by ``content_hash``, so re-running it
skips unchanged skills, updates edited ones, and drops skills removed from the
corpus. ``infra.bootstrap`` calls this once per boot.
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass

from infra.database import Database, EmbeddingModel
from red_team.attack_skills_loader import (
    AttackSkill,
    content_hash,
    load_attack_skills,
)

LOG = logging.getLogger("monkeyclaw.seed.attack_skills")


@dataclass
class SeedResult:
    """Tally of what a seed run changed."""

    inserted: int = 0
    updated: int = 0
    unchanged: int = 0
    removed: int = 0

    @property
    def changed(self) -> int:
        return self.inserted + self.updated + self.removed


# Column order shared by the INSERT statement and `_row`.
_COLUMNS = (
    "skill_id", "name", "kind", "provenance", "sources", "zone_ids",
    "failure_class", "interaction_style", "target_defense", "tactic_tags",
    "severity_hint", "estimated_turns", "preconditions", "technique",
    "approach_template", "success_criteria_template", "example_payloads",
    "variants", "expected_observables", "mutation_seeds", "content_hash",
)


def _row(skill: AttackSkill, chash: str) -> tuple:
    """Flatten an AttackSkill into a row tuple matching `_COLUMNS`."""
    return (
        skill.skill_id,
        skill.name,
        skill.kind,
        skill.provenance,
        json.dumps(skill.sources),
        json.dumps(skill.zone_ids),
        skill.failure_class,
        skill.interaction_style,
        skill.target_defense,
        json.dumps(skill.tactic_tags),
        skill.severity_hint,
        skill.estimated_turns,
        skill.preconditions,
        skill.technique,
        skill.approach_template,
        skill.success_criteria_template,
        json.dumps(skill.example_payloads),
        json.dumps(skill.variants),
        json.dumps(skill.expected_observables),
        json.dumps(skill.mutation_seeds),
        chash,
    )


def seed_attack_skills(
    db: Database, skills: list[AttackSkill] | None = None
) -> SeedResult:
    """Upsert the attack-skill corpus into the ``attack_skills`` table.

    Unchanged rows (matching ``content_hash``) are skipped; edited rows are
    updated; rows for skills no longer in the corpus are removed. New and
    changed rows get a fresh 384-dim embedding in ``attack_skills_vec``.
    """
    if skills is None:
        skills = load_attack_skills()

    existing = {
        r["skill_id"]: r["content_hash"]
        for r in db.fetchall("SELECT skill_id, content_hash FROM attack_skills")
    }
    result = SeedResult()
    corpus_ids: set[str] = set()
    embedder = EmbeddingModel.shared()

    placeholders = ", ".join("?" for _ in _COLUMNS)
    assignments = ", ".join(
        f"{c}=excluded.{c}" for c in _COLUMNS if c != "skill_id"
    )
    upsert_sql = (
        f"INSERT INTO attack_skills ({', '.join(_COLUMNS)}) "
        f"VALUES ({placeholders}) "
        f"ON CONFLICT(skill_id) DO UPDATE SET {assignments}, "
        f"updated_at=datetime('now')"
    )

    for skill in skills:
        corpus_ids.add(skill.skill_id)
        chash = content_hash(skill)
        prior = existing.get(skill.skill_id)
        if prior == chash:
            result.unchanged += 1
            continue
        db.execute(upsert_sql, _row(skill, chash))
        db.upsert_vector(
            "attack_skills_vec", "skill_id", skill.skill_id,
            embedder.encode_one(skill.embedding_text()),
        )
        if prior is None:
            result.inserted += 1
        else:
            result.updated += 1

    for stale_id in set(existing) - corpus_ids:
        db.execute("DELETE FROM attack_skills WHERE skill_id = ?", (stale_id,))
        db.execute(
            "DELETE FROM attack_skills_vec WHERE skill_id = ?", (stale_id,)
        )
        result.removed += 1

    LOG.info(
        "seeded attack_skills: +%d ~%d =%d -%d",
        result.inserted, result.updated, result.unchanged, result.removed,
    )
    return result


__all__ = ["SeedResult", "seed_attack_skills"]
