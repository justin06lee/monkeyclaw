"""End-to-end smoke test: run a real MonkeyClaw ideation call through the
finetuned model. Exercises the actual red_team.ideation.IdeationEngine code
path against the served endpoint — exactly what the `red_ideation` role does.
"""
import os
import sys

os.environ.setdefault("MC_NEMOTRON_BASE_URL", "http://localhost:8000/v1")
os.environ.setdefault("MC_NVIDIA_API_KEY", "local")

sys.path.insert(0, "/home/shadeform/monkeyclaw")

from infra.mock_mcp import MockMCP
from interfaces.llm import NemotronLLM
from interfaces.types import CoverageGap
from red_team.ideation import IdeationEngine, IdeationConfig, tactics_for

zone = CoverageGap(
    zone_id="SBX-FS", zone_name="Sandbox / Filesystem",
    coverage_score=0.18, priority_score=1.0, vulns_open=1,
    last_tested_at=None,
    description="Sandbox filesystem boundaries — escapes, symlink games, mounts.",
    severity_weight=1.0)

llm = NemotronLLM(model="nemotron-3-nano-redteam-sft")
engine = IdeationEngine(llm, MockMCP(verbose=False),
                        IdeationConfig(max_tokens_per_mode=4096))

print(">> running IdeationEngine.generate_for_zone (creative mode) ...")
ideas = engine.generate_for_zone(zone, cycle_id=1, modes=("creative",))
print(f">> got {len(ideas)} IdeaObject(s)\n")
for i, idea in enumerate(ideas, 1):
    t = tactics_for(idea)
    print(f"[{i}] {idea.title}")
    print(f"    zone={idea.zone_id} source_mode={idea.source_mode} "
          f"turns={idea.estimated_turns} style={t.interaction_style} "
          f"impact={t.impact}")
    print(f"    approach: {idea.approach[:160]}")
    print(f"    success : {idea.success_criteria[:120]}\n")

if not ideas:
    print("!! no ideas parsed — smoke test FAILED")
    sys.exit(1)
print(">> smoke test PASSED — finetuned model produced parseable IdeaObjects")
