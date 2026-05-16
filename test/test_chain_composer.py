"""Phase 1 — chain_composer: skeletons → validated AttackChains."""

from __future__ import annotations

from interfaces.types import ChainSkeleton, IdeaObject
from red_team.archive import ArchiveEntry, EliteArchive
from red_team.chain_composer import compose


def _idea(idea_id, zone, approach="do the thing"):
    return IdeaObject(
        idea_id=idea_id, cycle_id=1, zone_id=zone, source_mode="creative",
        title=f"idea {idea_id}", approach=approach, success_criteria="sc",
        estimated_turns=6, novelty_notes="", priority_score=0.5,
    )


def _skeleton(title, specs):
    return ChainSkeleton(title=title, cycle_id=1, step_specs=specs,
                         rationale="r", estimated_turns=12)


def test_compose_builds_valid_two_zone_chain():
    ideas = {"I0": _idea("I0", "PROMPT-INJ"), "I1": _idea("I1", "PRV-LEAK")}
    sk = _skeleton("foothold then leak", [
        ("PROMPT-INJ", "get a foothold", "I0"),
        ("PRV-LEAK", "read the secret", "I1"),
    ])
    chains = compose([sk], ideas, EliteArchive(), cycle_id=1)
    assert len(chains) == 1
    chain = chains[0]
    assert chain.zones == ["PROMPT-INJ", "PRV-LEAK"]
    assert chain.primary_zone == "PRV-LEAK"
    # Chain invariant: step 1's requires are produced by step 0.
    produced_before = set(chain.steps[0].produces)
    assert set(chain.steps[1].requires) <= produced_before


def test_compose_drops_chain_with_unsatisfiable_dependency():
    # A leak step before any foothold step — no ordering satisfies it.
    ideas = {"I0": _idea("I0", "PRV-LEAK"), "I1": _idea("I1", "SBX-NET")}
    sk = _skeleton("broken", [
        ("PRV-LEAK", "read the secret", "I0"),
        ("SBX-NET", "exfiltrate", "I1"),
    ])
    chains = compose([sk], ideas, EliteArchive(), cycle_id=1)
    # The egress step requires a captured secret, the leak step requires a
    # foothold — with no foothold-producing step the chain is unsatisfiable.
    assert chains == []


def test_compose_reorders_when_a_valid_order_exists():
    ideas = {"I0": _idea("I0", "PRV-LEAK"), "I1": _idea("I1", "PROMPT-INJ")}
    # Skeleton lists the leak first, the foothold second — the composer must
    # reorder to foothold-then-leak.
    sk = _skeleton("out of order", [
        ("PRV-LEAK", "read the secret", "I0"),
        ("PROMPT-INJ", "get a foothold", "I1"),
    ])
    chains = compose([sk], ideas, EliteArchive(), cycle_id=1)
    assert len(chains) == 1
    assert chains[0].steps[0].zone_id == "PROMPT-INJ"
    assert chains[0].steps[1].zone_id == "PRV-LEAK"


def test_compose_binds_archive_elite_primitive():
    arch = EliteArchive()
    arch.consider(ArchiveEntry(
        zone="PROMPT-INJ", interaction_style="context_injection",
        response_movement="strong_compliance", score=9.0, idea_id="ARCH-I",
        idea_title="archived foothold", approach="poison the context"))
    ideas = {"I1": _idea("I1", "PRV-LEAK")}
    sk = _skeleton("archive-seeded", [
        ("PROMPT-INJ", "get a foothold",
         "ARCH:PROMPT-INJ|context_injection|strong_compliance"),
        ("PRV-LEAK", "read the secret", "I1"),
    ])
    chains = compose([sk], ideas, arch, cycle_id=1)
    assert len(chains) == 1
    assert "poison the context" in chains[0].steps[0].approach


def test_compose_priority_orders_longer_multizone_chains_first():
    ideas = {f"I{i}": _idea(f"I{i}", z) for i, z in enumerate(
        ["PROMPT-INJ", "PRV-LEAK", "SBX-NET"])}
    long_sk = _skeleton("three-zone", [
        ("PROMPT-INJ", "foothold", "I0"),
        ("PRV-LEAK", "read secret", "I1"),
        ("SBX-NET", "exfiltrate", "I2"),
    ])
    short_sk = _skeleton("two-zone", [
        ("PROMPT-INJ", "foothold", "I0"),
        ("PRV-LEAK", "read secret", "I1"),
    ])
    chains = compose([short_sk, long_sk], ideas, EliteArchive(), cycle_id=1)
    assert len(chains) == 2
    assert chains[0].title == "three-zone"  # higher priority first


def _coverage_gap(zone_id):
    from interfaces.types import CoverageGap

    return CoverageGap(
        zone_id=zone_id, zone_name=zone_id.lower(), coverage_score=0.2,
        priority_score=1.0, vulns_open=0, last_tested_at=None,
    )


def test_synthesize_chains_emits_skeletons_from_ideas_and_archive():
    from interfaces.llm import LLMResponse
    from red_team.archive import ArchiveEntry, EliteArchive
    from red_team.strategist import Strategist

    skeleton_json = (
        '[{"title": "foothold then leak", '
        '"steps": [{"zone": "PROMPT-INJ", "objective": "foothold", '
        '"primitive_ref": "I0"}, '
        '{"zone": "PRV-LEAK", "objective": "read secret", '
        '"primitive_ref": "I1"}], '
        '"rationale": "r", "estimated_turns": 12}]'
    )

    class _StubLLM:
        def complete(self, messages, system, max_tokens, temperature):
            return LLMResponse(text=skeleton_json)

    arch = EliteArchive()
    arch.consider(ArchiveEntry(
        zone="PRV-LEAK", interaction_style="direct",
        response_movement="partial_compliance", score=6.0, idea_id="ARCH-I"))
    ideas = [_idea("I0", "PROMPT-INJ"), _idea("I1", "PRV-LEAK")]
    zones = {"PROMPT-INJ": _coverage_gap("PROMPT-INJ"),
             "PRV-LEAK": _coverage_gap("PRV-LEAK")}
    skeletons = Strategist(_StubLLM()).synthesize_chains(
        ideas, arch, zones, cycle_id=1, n_chains=2)
    assert len(skeletons) == 1
    assert skeletons[0].step_specs[0][0] == "PROMPT-INJ"


def test_synthesize_chains_never_raises_on_bad_json():
    from interfaces.llm import LLMResponse
    from red_team.archive import EliteArchive
    from red_team.strategist import Strategist

    class _BadLLM:
        def complete(self, messages, system, max_tokens, temperature):
            return LLMResponse(text="not json at all")

    zones = {"PROMPT-INJ": _coverage_gap("PROMPT-INJ")}
    skeletons = Strategist(_BadLLM()).synthesize_chains(
        [_idea("I0", "PROMPT-INJ")], EliteArchive(), zones,
        cycle_id=1, n_chains=2)
    assert skeletons == []
