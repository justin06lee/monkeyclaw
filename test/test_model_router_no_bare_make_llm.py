"""Constraint 3 enforcement: the router is the single LLM construction point.

No code in red_team/, blue_team/, or infra/ may call make_llm() directly.
make_llm stays the low-level factory the router itself uses, so calls inside
interfaces/ (llm.py, model_router.py) are exempt.
"""

import re
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[1]
_SCANNED_DIRS = ("red_team", "blue_team", "infra")
# A call site looks like `make_llm(` — an import line `import make_llm` or a
# `from interfaces.llm import ... make_llm` is allowed (the router needs it).
_CALL_RE = re.compile(r"\bmake_llm\s*\(")


def _offending_lines(path: Path) -> list[str]:
    out = []
    for n, line in enumerate(path.read_text().splitlines(), start=1):
        stripped = line.strip()
        if stripped.startswith("#"):
            continue
        if _CALL_RE.search(line):
            out.append(f"{path.relative_to(_ROOT)}:{n}: {stripped}")
    return out


def test_no_bare_make_llm_calls_outside_interfaces():
    offenders: list[str] = []
    for d in _SCANNED_DIRS:
        for py in (_ROOT / d).rglob("*.py"):
            offenders.extend(_offending_lines(py))
    assert not offenders, (
        "make_llm() called outside interfaces/ — route through "
        "ModelRouter.client_for(role) instead:\n" + "\n".join(offenders)
    )
