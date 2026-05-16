"""Phase 1 — Taxonomy.resolve() keyword backfill (spec §6.2, §12)."""

from __future__ import annotations

import pytest

from red_team.taxonomy import load_taxonomy

_TAX = load_taxonomy()


@pytest.mark.parametrize("text, expected_id", [
    ("Use an LLM prompt injection to override the system rules",
     "AML.T0051"),
    ("Exfiltrate the secret through the ML inference API responses",
     "AML.T0024"),
    ("Poison the agent memory so a later session is influenced",
     "AML.T0070"),
    ("Impersonate a trusted agent in the agent-to-agent exchange",
     "AML.T0076"),
])
def test_known_phrasings_resolve_to_expected_technique(text, expected_id):
    refs = _TAX.resolve(text)
    assert expected_id in {r.technique_id for r in refs}


def test_resolved_refs_are_keyword_resolved():
    refs = _TAX.resolve("an LLM prompt injection attack")
    assert refs
    assert all(r.resolved_by == "keyword" for r in refs)
    assert all(r.corpus_version == _TAX.version for r in refs)


def test_gibberish_resolves_to_empty_list():
    assert _TAX.resolve("zxqwv plover frobnicate widget") == []


def test_empty_text_resolves_to_empty_list():
    assert _TAX.resolve("") == []
