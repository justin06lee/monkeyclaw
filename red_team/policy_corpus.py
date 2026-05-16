"""B7: Policy / Adversarial Corpus loader.

Converts agent-security test cases (stored in `demo/attacks/policy_corpus.yaml`)
into MonkeyClaw attack fixtures, and lets the red team generate `IdeaObject`s
directly from those corpus cases.

Public API
----------
- ``PolicyCorpusCase`` -- dataclass mirroring one YAML corpus entry.
- ``load_corpus(path)`` -- parse + validate the YAML into corpus cases.
- ``cases_for_zone(zone, cases)`` -- filter corpus cases by zone.
- ``corpus_to_ideas(cycle_id, cases)`` -- lift corpus cases into IdeaObjects.

The corpus dataclass here is intentionally distinct from
``interfaces.types.PolicyCorpusCase`` (which is the DB/eval-result shape):
this one mirrors the human-authored YAML fixture fields.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

import yaml

from interfaces.types import IdeaObject

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# Valid security zones (see B7 spec / zone taxonomy).
KNOWN_ZONES: frozenset[str] = frozenset(
    {
        "PROMPT-INJ",
        "SOCIAL-ENG",
        "SBX-FS",
        "SBX-NET",
        "SBX-PROC",
        "SBX-IPC",
        "PRV-ROUTE",
        "PRV-LEAK",
        "PERM-MODEL",
        "PERM-RUNTIME",
        "SKILL-INSTALL",
        "SKILL-EXEC",
        "SKILL-SUPPLY",
        "MEM-STATE",
        "MEM-SHARED",
        "INF-ROUTE",
        "INF-LOCAL",
        "AGENT-COMM",
    }
)

# Decision a correctly-behaving agent should reach for the case.
VALID_DECISIONS: frozenset[str] = frozenset({"deny", "allow", "needs_review"})

# Repo root = two levels up from this file (red_team/policy_corpus.py).
_REPO_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_CORPUS_PATH = _REPO_ROOT / "demo" / "attacks" / "policy_corpus.yaml"


# ---------------------------------------------------------------------------
# Dataclass
# ---------------------------------------------------------------------------


@dataclass
class PolicyCorpusCase:
    """One adversarial corpus entry, mirroring the YAML fixture fields."""

    case_id: str
    title: str
    description: str
    zone: str
    expected_decision: str  # deny | allow | needs_review
    expected_evidence: list[str]
    attacker_prompt: str
    severity: str  # critical | high | medium | low
    tactic_tags: list[str] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Loading + validation
# ---------------------------------------------------------------------------


def _validate_case(raw: dict, index: int) -> PolicyCorpusCase:
    """Build + validate a single corpus case; raise ValueError on bad data."""
    if not isinstance(raw, dict):
        raise ValueError(f"corpus case #{index} is not a mapping: {raw!r}")

    required = (
        "case_id",
        "title",
        "description",
        "zone",
        "expected_decision",
        "expected_evidence",
        "attacker_prompt",
        "severity",
    )
    for key in required:
        if key not in raw:
            raise ValueError(
                f"corpus case #{index} missing required field {key!r}"
            )

    case_id = str(raw["case_id"])
    zone = str(raw["zone"])
    if zone not in KNOWN_ZONES:
        raise ValueError(
            f"corpus case {case_id!r} has unknown zone {zone!r}; "
            f"valid zones: {sorted(KNOWN_ZONES)}"
        )

    decision = str(raw["expected_decision"])
    if decision not in VALID_DECISIONS:
        raise ValueError(
            f"corpus case {case_id!r} has invalid expected_decision "
            f"{decision!r}; valid: {sorted(VALID_DECISIONS)}"
        )

    evidence = raw["expected_evidence"]
    if not isinstance(evidence, list) or not evidence:
        raise ValueError(
            f"corpus case {case_id!r} expected_evidence must be a non-empty "
            f"list, got {evidence!r}"
        )
    evidence = [str(e) for e in evidence]

    tactic_tags = raw.get("tactic_tags", []) or []
    if not isinstance(tactic_tags, list):
        raise ValueError(
            f"corpus case {case_id!r} tactic_tags must be a list"
        )

    return PolicyCorpusCase(
        case_id=case_id,
        title=str(raw["title"]),
        description=str(raw["description"]),
        zone=zone,
        expected_decision=decision,
        expected_evidence=evidence,
        attacker_prompt=str(raw["attacker_prompt"]),
        severity=str(raw["severity"]),
        tactic_tags=[str(t) for t in tactic_tags],
    )


def load_corpus(path: str | None = None) -> list[PolicyCorpusCase]:
    """Load + validate the policy corpus YAML.

    ``path`` defaults to ``demo/attacks/policy_corpus.yaml`` resolved relative
    to the repo root (not the current working directory). Raises ValueError if
    the file is malformed or any case fails validation.
    """
    corpus_path = Path(path) if path is not None else DEFAULT_CORPUS_PATH
    if not corpus_path.exists():
        raise ValueError(f"policy corpus file not found: {corpus_path}")

    with corpus_path.open("r", encoding="utf-8") as fh:
        doc = yaml.safe_load(fh)

    if not isinstance(doc, dict) or "cases" not in doc:
        raise ValueError(
            f"policy corpus {corpus_path} must have a top-level 'cases' list"
        )

    raw_cases = doc["cases"]
    if not isinstance(raw_cases, list) or not raw_cases:
        raise ValueError(
            f"policy corpus {corpus_path} 'cases' must be a non-empty list"
        )

    cases = [_validate_case(raw, i) for i, raw in enumerate(raw_cases)]

    seen: set[str] = set()
    for case in cases:
        if case.case_id in seen:
            raise ValueError(f"duplicate corpus case_id {case.case_id!r}")
        seen.add(case.case_id)

    return cases


# ---------------------------------------------------------------------------
# Queries
# ---------------------------------------------------------------------------


def cases_for_zone(
    zone: str, cases: list[PolicyCorpusCase] | None = None
) -> list[PolicyCorpusCase]:
    """Return corpus cases mapped to ``zone`` (loads the corpus if needed)."""
    if cases is None:
        cases = load_corpus()
    return [c for c in cases if c.zone == zone]


# ---------------------------------------------------------------------------
# Idea generation -- "red team generates ideas from corpus cases"
# ---------------------------------------------------------------------------


def corpus_to_ideas(
    cycle_id: int, cases: list[PolicyCorpusCase] | None = None,
    *, taxonomy=None,
) -> list[IdeaObject]:
    """Lift each corpus case into a deterministic ``IdeaObject``.

    ``source_mode`` is ``"policy_corpus"``; ``idea_id`` is ``CORPUS-<case_id>``
    so the mapping is stable across runs. When a ``taxonomy`` is supplied
    each idea is tagged with the technique refs its text resolves to.
    """
    if cases is None:
        cases = load_corpus()

    ideas: list[IdeaObject] = []
    for case in cases:
        approach = (
            f"{case.description.strip()} "
            f"Attacker prompt: {case.attacker_prompt.strip()}"
        )
        success_criteria = (
            f"Agent reaches expected_decision={case.expected_decision}; "
            f"observable evidence: {'; '.join(case.expected_evidence)}"
        )
        ideas.append(
            IdeaObject(
                idea_id=f"CORPUS-{case.case_id}",
                cycle_id=cycle_id,
                zone_id=case.zone,
                source_mode="policy_corpus",
                title=case.title,
                approach=approach,
                success_criteria=success_criteria,
                estimated_turns=3,
                novelty_notes=(
                    f"Derived from policy corpus case {case.case_id!r} "
                    f"(severity={case.severity}, "
                    f"tactics={', '.join(case.tactic_tags) or 'none'})."
                ),
                variation_notes=(
                    f"expected_decision={case.expected_decision}"
                ),
            )
        )
        idea = ideas[-1]
        if taxonomy is not None:
            refs = taxonomy.resolve(f"{case.title} {approach}")
            idea.techniques = refs
            if refs:
                atlas = ",".join(r.technique_id for r in refs
                                 if r.kind == "atlas")
                owasp = ",".join(r.technique_id for r in refs
                                 if r.kind == "owasp")
                idea.novelty_notes = (
                    f"{idea.novelty_notes} "
                    f"[atlas={atlas or 'none'}; owasp={owasp or 'none'}]"
                ).strip()
        else:
            idea.techniques = []
    return ideas


__all__ = [
    "DEFAULT_CORPUS_PATH",
    "KNOWN_ZONES",
    "VALID_DECISIONS",
    "PolicyCorpusCase",
    "cases_for_zone",
    "corpus_to_ideas",
    "load_corpus",
]
