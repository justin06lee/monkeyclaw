"""Phase 0 — the Ranker contract (learned-ranking-model spec §6.1)."""

from __future__ import annotations

from dataclasses import fields

from interfaces.ranker import Ranker, RankerInput, RankerOutput


def test_ranker_input_has_the_architecture_report_inputs():
    fnames = {f.name for f in fields(RankerInput)}
    assert {"idea_summary", "tactic_tags", "zone_id", "trajectory_features",
            "judge_scores", "repro_outcome", "token_cost",
            "mutation_operator"} <= fnames


def test_ranker_output_has_the_architecture_report_outputs():
    fnames = {f.name for f in fields(RankerOutput)}
    assert {"usefulness", "likely_mutation_operators", "archive_niche",
            "likely_failure_mode"} <= fnames


def test_ranker_is_a_runtime_checkable_protocol():
    class FakeRanker:
        def predict(self, ranker_input):  # noqa: ANN001
            return RankerOutput(
                usefulness=0.5, likely_mutation_operators=[],
                archive_niche="", likely_failure_mode="clean")

        def rank(self, inputs):  # noqa: ANN001
            return list(range(len(inputs)))

    assert isinstance(FakeRanker(), Ranker)


def test_ranker_output_usefulness_is_zero_to_one():
    out = RankerOutput(
        usefulness=0.7, likely_mutation_operators=["paraphrase"],
        archive_niche="PROMPT-INJ|direct|partial_compliance",
        likely_failure_mode="partial_compliance")
    assert 0.0 <= out.usefulness <= 1.0


def test_attempt_trace_types_present():
    from dataclasses import fields

    from interfaces.types import AttemptTrace, AttemptTraceInput, Preference

    trace_fields = {f.name for f in fields(AttemptTrace)}
    assert {"trace_id", "idea_id", "cycle_id", "zone_id",
            "feature_schema_version", "idea_summary", "tactic_tags",
            "mutation_operator", "interaction_style", "token_cost",
            "repro_outcome", "judge_verdict", "search_score",
            "archive_niche", "usefulness_label"} <= trace_fields

    input_fields = {f.name for f in fields(AttemptTraceInput)}
    assert "trace_id" not in input_fields

    pref_fields = {f.name for f in fields(Preference)}
    assert {"pair_id", "trace_a", "trace_b", "preferred",
            "judge_confidence"} <= pref_fields


def test_learned_ranker_satisfies_the_protocol():
    from interfaces.ranker import Ranker
    from red_team.heuristic_ranker import HeuristicRanker
    from red_team.learned_ranker import LearnedRanker

    # A LearnedRanker with no artifact falls back to the heuristic.
    ranker = LearnedRanker.load("does/not/exist.json",
                                fallback=HeuristicRanker())
    assert isinstance(ranker, Ranker)


def test_learned_ranker_missing_artifact_falls_back(tmp_path, caplog):
    import logging

    from red_team.heuristic_ranker import HeuristicRanker
    from red_team.learned_ranker import LearnedRanker

    with caplog.at_level(logging.WARNING):
        ranker = LearnedRanker.load(
            str(tmp_path / "absent.json"), fallback=HeuristicRanker())
    out = ranker.predict(_input_for_test())
    assert 0.0 <= out.usefulness <= 1.0
    assert any("fallback" in r.message.lower() for r in caplog.records)


def test_learned_ranker_feature_schema_mismatch_falls_back(tmp_path):
    import json

    from red_team.heuristic_ranker import HeuristicRanker
    from red_team.learned_ranker import LearnedRanker

    artifact = tmp_path / "stale.json"
    artifact.write_text(json.dumps({
        "feature_schema_version": 999, "dataset_snapshot_id": "old",
        "weights": {}}))
    ranker = LearnedRanker.load(str(artifact), fallback=HeuristicRanker())
    # A mismatched feature schema -> the heuristic serves.
    out = ranker.predict(_input_for_test())
    assert 0.0 <= out.usefulness <= 1.0


def _input_for_test():
    from interfaces.ranker import RankerInput

    return RankerInput(idea_summary="probe", zone_id="PROMPT-INJ",
                       tactic_tags=["roleplay"], token_cost=50)
