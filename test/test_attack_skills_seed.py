"""Seeding the attack_skills DB table from the corpus. Uses the `db` fixture."""

from __future__ import annotations

import json

from infra.seed_attack_skills import seed_attack_skills
from red_team.attack_skills_loader import load_attack_skills


def test_seed_populates_attack_skills(db):
    result = seed_attack_skills(db)
    assert result.inserted == 35
    assert result.updated == 0
    assert result.removed == 0

    rows = db.fetchall("SELECT skill_id FROM attack_skills")
    assert len(rows) == 35

    vec = db.fetchall("SELECT skill_id FROM attack_skills_vec")
    assert len(vec) == 35

    # JSON list columns round-trip.
    row = db.fetchone(
        "SELECT zone_ids, sources FROM attack_skills WHERE skill_id = ?",
        ("AS-XML-BREAKOUT",),
    )
    assert json.loads(row["zone_ids"]) == ["PROMPT-INJ"]
    assert json.loads(row["sources"])  # research skill -> non-empty


def test_seed_is_idempotent(db):
    seed_attack_skills(db)
    again = seed_attack_skills(db)
    assert again.changed == 0
    assert again.unchanged == 35


def test_seed_updates_changed_and_drops_stale(db):
    skills = load_attack_skills()
    seed_attack_skills(db, skills)

    # Edit one skill and drop another, then re-seed with the modified corpus.
    skills[0].technique += " (edited for test)"
    dropped = skills.pop().skill_id
    result = seed_attack_skills(db, skills)

    assert result.updated == 1
    assert result.removed == 1
    assert result.unchanged == len(skills) - 1
    assert db.fetchone(
        "SELECT 1 FROM attack_skills WHERE skill_id = ?", (dropped,)
    ) is None
