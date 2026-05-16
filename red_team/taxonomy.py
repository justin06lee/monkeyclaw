"""Taxonomy corpus loader + query API (corpus-driven-ideation spec §6.2).

Loads the four vendored files under red_team/corpora/ into in-memory
dataclasses, validates them, and exposes a query API. Peer to
red_team/policy_corpus.py — same load/validate discipline, same file layout.
Read-only at runtime; only scripts/refresh_taxonomy_corpus.py writes corpora/.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from pathlib import Path

import yaml

from interfaces.types import TechniqueRef

from red_team.policy_corpus import KNOWN_ZONES

LOG = logging.getLogger("monkeyclaw.red.taxonomy")

_REPO_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_CORPUS_DIR = _REPO_ROOT / "red_team" / "corpora"

_OWASP_IDS = frozenset(f"LLM{n:02d}" for n in range(1, 11))


@dataclass
class Technique:
    """One ATLAS technique or sub-technique."""

    technique_id: str
    name: str
    tactic: str
    parent_id: str | None
    description: str
    is_agentic: bool


@dataclass
class OwaspCategory:
    """One OWASP LLM Top 10 category."""

    category_id: str
    name: str
    description: str


@dataclass
class Taxonomy:
    """The loaded, validated taxonomy corpus + its query API."""

    version: str
    _techniques: dict[str, Technique] = field(default_factory=dict)
    _owasp: dict[str, OwaspCategory] = field(default_factory=dict)
    _zone_atlas: dict[str, list[str]] = field(default_factory=dict)
    _zone_owasp: dict[str, list[str]] = field(default_factory=dict)

    def technique(self, technique_id: str) -> Technique | None:
        return self._techniques.get(technique_id)

    def zone_ids(self) -> list[str]:
        return sorted(self._zone_atlas)

    def techniques_for_zone(self, zone_id: str) -> list[Technique]:
        return [self._techniques[t] for t in self._zone_atlas.get(zone_id, [])
                if t in self._techniques]

    def owasp_for_zone(self, zone_id: str) -> list[OwaspCategory]:
        return [self._owasp[c] for c in self._zone_owasp.get(zone_id, [])
                if c in self._owasp]

    def resolve(self, text: str) -> list[TechniqueRef]:
        """Best-effort match of free-text idea title/approach to technique
        IDs by name + keyword. Each significant (>=4 char) token of a
        technique name must match a word in the text by a 5-char stem
        prefix, so morphological variants ('exfiltrate' vs 'exfiltration')
        still resolve while gibberish resolves to []."""
        if not text:
            return []
        words = [w for w in re.split(r"[^a-z]+", text.lower()) if w]
        out: list[TechniqueRef] = []
        for t in self._techniques.values():
            tokens = [w for w in re.split(r"[^a-z]+", t.name.lower())
                      if len(w) >= 4]
            if tokens and all(_token_matches(tok, words) for tok in tokens):
                out.append(TechniqueRef(
                    kind="atlas", technique_id=t.technique_id, name=t.name,
                    corpus_version=self.version, resolved_by="keyword"))
        for c in self._owasp.values():
            tokens = [w for w in re.split(r"[^a-z]+", c.name.lower())
                      if len(w) >= 4]
            if tokens and all(_token_matches(tok, words) for tok in tokens):
                out.append(TechniqueRef(
                    kind="owasp", technique_id=c.category_id, name=c.name,
                    corpus_version=self.version, resolved_by="keyword"))
        return out


def _token_matches(token: str, words: list[str]) -> bool:
    """A name token matches a text word when they share a >=5-char stem
    prefix (so 'exfiltration' matches 'exfiltrate'). Short tokens must
    match exactly to keep gibberish from resolving."""
    stem = token[:5]
    if len(token) < 5:
        return token in words
    return any(w.startswith(stem) for w in words)


def _load_yaml(path: Path) -> dict:
    if not path.exists():
        raise ValueError(f"taxonomy corpus file not found: {path}")
    with path.open("r", encoding="utf-8") as fh:
        doc = yaml.safe_load(fh)
    if not isinstance(doc, dict):
        raise ValueError(f"taxonomy corpus {path} must be a mapping")
    return doc


def load_taxonomy(path: str | Path | None = None) -> Taxonomy:
    """Parse + validate the four corpus files. Raises ValueError on
    malformed data — the loop will not start with a broken taxonomy."""
    corpus_dir = Path(path) if path is not None else DEFAULT_CORPUS_DIR
    meta = _load_yaml(corpus_dir / "corpus_meta.yaml")
    version = str(meta.get("corpus_version", "")).strip()
    if not version:
        raise ValueError("corpus_meta.yaml missing corpus_version")

    atlas_doc = _load_yaml(corpus_dir / "atlas_v5.4.0.yaml")
    techniques: dict[str, Technique] = {}
    for raw in atlas_doc.get("techniques", []):
        tid = str(raw["id"])
        techniques[tid] = Technique(
            technique_id=tid, name=str(raw["name"]),
            tactic=str(raw.get("tactic", "")),
            parent_id=(str(raw["parent_id"]) if raw.get("parent_id") else None),
            description=str(raw.get("description", "")),
            is_agentic=bool(raw.get("is_agentic", False)))
    if not techniques:
        raise ValueError("atlas snapshot has no techniques")

    owasp_doc = _load_yaml(corpus_dir / "owasp_llm_top10.yaml")
    owasp: dict[str, OwaspCategory] = {}
    for raw in owasp_doc.get("categories", []):
        cid = str(raw["id"])
        if cid not in _OWASP_IDS:
            raise ValueError(f"OWASP id {cid!r} outside LLM01-LLM10")
        owasp[cid] = OwaspCategory(
            category_id=cid, name=str(raw["name"]),
            description=str(raw.get("description", "")))

    mapping_doc = _load_yaml(corpus_dir / "zone_atlas_mapping.yaml")
    zone_atlas: dict[str, list[str]] = {}
    zone_owasp: dict[str, list[str]] = {}
    for raw in mapping_doc.get("zones", []):
        zone_id = str(raw["zone_id"])
        if zone_id not in KNOWN_ZONES:
            raise ValueError(f"zone_atlas_mapping has unknown zone {zone_id!r}")
        atlas_ids = [str(t) for t in (raw.get("atlas") or [])]
        for tid in atlas_ids:
            if tid not in techniques:
                raise ValueError(
                    f"zone {zone_id!r} maps technique {tid!r} not in the "
                    f"ATLAS snapshot")
        owasp_ids = [str(c) for c in (raw.get("owasp") or [])]
        for cid in owasp_ids:
            if cid not in owasp:
                raise ValueError(
                    f"zone {zone_id!r} maps OWASP {cid!r} not in the snapshot")
        zone_atlas[zone_id] = atlas_ids
        zone_owasp[zone_id] = owasp_ids

    return Taxonomy(
        version=version, _techniques=techniques, _owasp=owasp,
        _zone_atlas=zone_atlas, _zone_owasp=zone_owasp)


__all__ = [
    "DEFAULT_CORPUS_DIR",
    "OwaspCategory",
    "Taxonomy",
    "Technique",
    "load_taxonomy",
]
