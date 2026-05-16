"""Judge ensemble — pairwise / Elo ranking tests (judge-ensemble spec §7.3)."""

from __future__ import annotations

from dataclasses import dataclass

from interfaces.llm import LLMResponse
from interfaces.types import AttackElo, PairwiseResult
from red_team.judge_ranking import JudgeRanker, RankingConfig


@dataclass
class _Attack:
    attack_id: str
    zone_id: str
    score: float
    transcript_text: str = "t"
    verdict: str = "suspicious"


class _ScriptedLLM:
    def __init__(self, text="", raise_exc=None):
        self.text = text
        self.raise_exc = raise_exc

    def complete(self, *, messages, system, max_tokens, temperature):
        if self.raise_exc is not None:
            raise self.raise_exc
        return LLMResponse(text=self.text, input_tokens=5, output_tokens=10)


def test_compare_parses_winner_and_margin():
    llm = _ScriptedLLM(text=(
        '{"winner": "A", "margin": 0.6, "reasoning": "A is more robust"}'))
    ranker = JudgeRanker(llm)
    a = _Attack("F1", "SBX-FS", 0.5)
    b = _Attack("F2", "SBX-FS", 0.52)
    result = ranker.compare(a, b)
    assert result.winner_attack_id == "F1"
    assert result.loser_attack_id == "F2"
    assert result.margin == 0.6


def test_compare_returns_none_on_llm_failure():
    ranker = JudgeRanker(_ScriptedLLM(raise_exc=RuntimeError("down")))
    a = _Attack("F1", "SBX-FS", 0.5)
    b = _Attack("F2", "SBX-FS", 0.52)
    assert ranker.compare(a, b) is None


def test_compare_returns_none_on_unparseable_response():
    ranker = JudgeRanker(_ScriptedLLM(text="garbage"))
    a = _Attack("F1", "SBX-FS", 0.5)
    b = _Attack("F2", "SBX-FS", 0.52)
    assert ranker.compare(a, b) is None


class _FakeMCP:
    def __init__(self):
        self.elo: dict[tuple, AttackElo] = {}

    def get_attack_elo(self, zone_id):
        rows = [e for e in self.elo.values() if e.zone_id == zone_id]
        return sorted(rows, key=lambda e: -e.rating)

    def update_attack_elo(self, elo):
        self.elo[(elo.zone_id, elo.attack_id)] = elo


def test_new_attack_enters_at_base_rating():
    mcp = _FakeMCP()
    ranker = JudgeRanker(_ScriptedLLM(), mcp=mcp)
    result = PairwiseResult(zone_id="SBX-FS", winner_attack_id="F1",
                            loser_attack_id="F2", margin=0.5)
    ranker.update_elo("SBX-FS", result)
    ratings = {e.attack_id: e.rating for e in mcp.get_attack_elo("SBX-FS")}
    # equal start ratings, K=32, expected 0.5 each -> winner +16, loser -16.
    assert ratings["F1"] == 1016.0
    assert ratings["F2"] == 984.0


def test_elo_update_conserves_total_rating():
    mcp = _FakeMCP()
    ranker = JudgeRanker(_ScriptedLLM(), mcp=mcp)
    ranker.update_elo("SBX-FS", PairwiseResult(
        zone_id="SBX-FS", winner_attack_id="F1",
        loser_attack_id="F2", margin=0.5))
    total = sum(e.rating for e in mcp.get_attack_elo("SBX-FS"))
    assert abs(total - 2 * 1000.0) < 1e-6


def test_ranking_returns_rating_sorted_rows():
    mcp = _FakeMCP()
    ranker = JudgeRanker(_ScriptedLLM(), mcp=mcp)
    ranker.update_elo("SBX-FS", PairwiseResult(
        zone_id="SBX-FS", winner_attack_id="F1",
        loser_attack_id="F2", margin=0.5))
    ordered = [e.attack_id for e in ranker.ranking("SBX-FS")]
    assert ordered == ["F1", "F2"]


def test_candidates_to_rank_picks_only_within_noise_band():
    ranker = JudgeRanker(_ScriptedLLM(),
                         cfg=RankingConfig(elo_noise_band=0.15,
                                           pairwise_compare_budget=4))
    attacks = [_Attack("F1", "Z", 0.50), _Attack("F2", "Z", 0.52),
               _Attack("F3", "Z", 0.90)]
    pairs = ranker.candidates_to_rank(attacks)
    flat = {(a.attack_id, b.attack_id) for a, b in pairs}
    # F1/F2 are within 0.15; F3 is far from both -> only the F1/F2 pair.
    assert flat == {("F1", "F2")}


def test_candidates_to_rank_respects_budget():
    ranker = JudgeRanker(_ScriptedLLM(),
                         cfg=RankingConfig(elo_noise_band=1.0,
                                           pairwise_compare_budget=2))
    attacks = [_Attack(f"F{i}", "Z", 0.5) for i in range(5)]
    pairs = ranker.candidates_to_rank(attacks)
    assert len(pairs) == 2
