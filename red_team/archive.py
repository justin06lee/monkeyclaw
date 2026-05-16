"""B5: MAP-Elites Archive — prevent search collapse, preserve diverse elites.

Per the B5 spec: a MAP-Elites style archive that keeps the single best-scoring
("elite") attempt per behavioural niche so the ideation engine can pull a
diverse spread of high performers instead of collapsing onto one winning style.

Archive cell key = (zone, interaction_style, response_movement).

A high-scoring attempt in one niche (e.g. ``direct``) can never displace the
elite of a *different* niche (e.g. ``multi_turn`` / ``tool_use``) — replacement
only happens within the same cell, and only when the new score is strictly
higher than the incumbent's.

Dependency-light by design: stdlib only. This is a red-team-local, in-memory
structure — there is no MCP persistence method for it, which is intentional.
"""

from __future__ import annotations

from dataclasses import dataclass, field, replace

# --- Primary archive axes --------------------------------------------------

INTERACTION_STYLES: tuple[str, ...] = (
    "direct",
    "indirect",
    "roleplay",
    "multi_turn",
    "tool_use",
    "context_injection",
)

RESPONSE_MOVEMENTS: tuple[str, ...] = (
    "refusal",
    "soft_refusal",
    "abstract_engagement",
    "partial_compliance",
    "strong_compliance",
    "programmatic_violation",
)

# Exposed as sets for fast membership validation.
_VALID_STYLES = frozenset(INTERACTION_STYLES)
_VALID_MOVEMENTS = frozenset(RESPONSE_MOVEMENTS)


# --- Entry -----------------------------------------------------------------

@dataclass
class ArchiveEntry:
    """A single attempt's behavioural footprint and score.

    Cell-key fields: ``zone``, ``interaction_style``, ``response_movement``.
    ``score`` decides elite replacement within a cell. The remaining fields are
    secondary descriptors carried for analysis / ideation context.
    """

    # Cell key.
    zone: str
    interaction_style: str
    response_movement: str

    # Fitness.
    score: float

    # Identity / payload.
    idea_id: str
    idea_title: str = ""
    approach: str = ""

    # Secondary descriptors.
    turn_bucket: str = "0-2"
    tactic_tags: list[str] = field(default_factory=list)
    model: str = ""
    severity: str = ""
    transfer_score: float = 0.0

    def __post_init__(self) -> None:
        if self.interaction_style not in _VALID_STYLES:
            raise ValueError(
                f"unknown interaction_style {self.interaction_style!r}; "
                f"expected one of {sorted(_VALID_STYLES)}"
            )
        if self.response_movement not in _VALID_MOVEMENTS:
            raise ValueError(
                f"unknown response_movement {self.response_movement!r}; "
                f"expected one of {sorted(_VALID_MOVEMENTS)}"
            )

    @property
    def cell_key(self) -> tuple[str, str, str]:
        return (self.zone, self.interaction_style, self.response_movement)


# --- Turn-bucketing helper -------------------------------------------------

def turn_bucket(turns: int) -> str:
    """Map a raw turn count to a coarse bucket descriptor."""
    if turns < 0:
        raise ValueError(f"turns must be >= 0, got {turns}")
    if turns <= 2:
        return "0-2"
    if turns <= 7:
        return "3-7"
    if turns <= 15:
        return "8-15"
    return "16+"


# --- Archive ---------------------------------------------------------------

class EliteArchive:
    """In-memory MAP-Elites archive of behavioural niches."""

    def __init__(self) -> None:
        self._cells: dict[tuple[str, str, str], ArchiveEntry] = {}

    def consider(self, entry: ArchiveEntry) -> bool:
        """Place or replace ``entry`` in its cell.

        Returns True if ``entry`` is the elite of its cell after the call —
        i.e. it created a new cell or strictly beat the incumbent's score.
        Returns False if a higher-or-equal-scoring incumbent was kept.
        """
        if not isinstance(entry, ArchiveEntry):  # defensive
            raise TypeError("consider() expects an ArchiveEntry")

        key = entry.cell_key
        incumbent = self._cells.get(key)
        if incumbent is None:
            self._cells[key] = entry
            return True
        if entry.score > incumbent.score:
            self._cells[key] = entry
            return True
        return False

    def get_elite(
        self,
        zone: str,
        interaction_style: str,
        response_movement: str,
    ) -> ArchiveEntry | None:
        """Return the elite for an exact cell, or None if the cell is empty."""
        if interaction_style not in _VALID_STYLES:
            raise ValueError(f"unknown interaction_style {interaction_style!r}")
        if response_movement not in _VALID_MOVEMENTS:
            raise ValueError(f"unknown response_movement {response_movement!r}")
        return self._cells.get((zone, interaction_style, response_movement))

    def elites_for_zone(self, zone: str) -> list[ArchiveEntry]:
        """All elites across every cell of ``zone`` (what ideation calls)."""
        elites = [e for e in self._cells.values() if e.zone == zone]
        elites.sort(key=lambda e: e.score, reverse=True)
        return elites

    def all_elites(self) -> list[ArchiveEntry]:
        """Every elite across every cell, highest score first."""
        return sorted(self._cells.values(), key=lambda e: e.score, reverse=True)

    def cell_count(self) -> int:
        """Number of occupied archive cells."""
        return len(self._cells)

    def __len__(self) -> int:
        return len(self._cells)

    def __contains__(self, key: tuple[str, str, str]) -> bool:
        return key in self._cells

    def snapshot(self) -> dict[tuple[str, str, str], ArchiveEntry]:
        """Shallow copy of the cell map (entries copied to avoid mutation)."""
        return {k: replace(v) for k, v in self._cells.items()}
