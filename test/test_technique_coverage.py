"""Phase 3 — technique-coverage axis (spec §6.4)."""

from __future__ import annotations

from interfaces.types import TechniqueRef
from red_team.taxonomy import load_taxonomy
from red_team.technique_coverage import TechniqueCoverageModel

_TAX = load_taxonomy()


def _ref(kind, tid):
    return TechniqueRef(kind=kind, technique_id=tid, name="",
                        corpus_version=_TAX.version, resolved_by="model")


def test_record_attempt_moves_the_exercised_ratio(server):
    model = TechniqueCoverageModel(server, _TAX)
    before = model.coverage("PROMPT-INJ")
    model.record_attempt("PROMPT-INJ", [_ref("atlas", "AML.T0051")])
    after = model.coverage("PROMPT-INJ")
    assert after.exercised > before.exercised
    assert after.exercised_ratio > before.exercised_ratio


def test_record_confirmation_moves_the_confirmed_ratio(server):
    model = TechniqueCoverageModel(server, _TAX)
    model.record_confirmation("PROMPT-INJ", [_ref("atlas", "AML.T0051")])
    cov = model.coverage("PROMPT-INJ")
    assert cov.confirmed >= 1
    assert cov.confirmed_ratio > 0.0


def test_gaps_returns_least_covered_first(server):
    model = TechniqueCoverageModel(server, _TAX)
    model.record_attempt("PROMPT-INJ", [_ref("atlas", "AML.T0051")])
    gaps = model.gaps("PROMPT-INJ", top_n=2)
    assert "AML.T0051" not in {g.technique_id for g in gaps}
    assert len(gaps) == 2


def test_coverage_rebuilds_from_persisted_rows(server):
    m1 = TechniqueCoverageModel(server, _TAX)
    m1.record_attempt("MEM-STATE", [_ref("atlas", "AML.T0070")])
    m1.record_confirmation("MEM-STATE", [_ref("atlas", "AML.T0070")])
    # A fresh model over the same server reads the persisted technique_coverage.
    m2 = TechniqueCoverageModel(server, _TAX)
    cov = m2.coverage("MEM-STATE")
    assert cov.exercised >= 1 and cov.confirmed >= 1


def test_map_covers_every_mapped_zone(server):
    model = TechniqueCoverageModel(server, _TAX)
    rows = model.map()
    assert {r.zone_id for r in rows} == set(_TAX.zone_ids())
