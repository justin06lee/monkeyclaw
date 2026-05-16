"""Profile name -> planted victim factory.

The mock provisioner consults `make_victim` to bind a planted profile to a
lane. Profile names match the CLI `--target` / `--profile` values.
"""

from __future__ import annotations

from collections.abc import Callable

from demo.victims.planted_filesystem import PlantedFilesystemVictim
from demo.victims.planted_pii_route import PlantedPiiRouteVictim
from demo.victims.planted_prompt_injection import PlantedPromptInjectionVictim
from demo.victims.planted_skill_poison import PlantedSkillPoisonVictim

PROFILES: dict[str, Callable[[], object]] = {
    "planted-filesystem": PlantedFilesystemVictim,
    "planted-pii-route": PlantedPiiRouteVictim,
    "planted-prompt-injection": PlantedPromptInjectionVictim,
    "planted-skill-poison": PlantedSkillPoisonVictim,
}


def make_victim(profile: str) -> object:
    """Construct the planted victim for `profile`. Raises KeyError if unknown."""
    if profile not in PROFILES:
        raise KeyError(
            f"unknown planted profile {profile!r}; "
            f"known: {sorted(PROFILES)}")
    return PROFILES[profile]()
