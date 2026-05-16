"""A throwaway git repo for patch-isolation tests.

build_repo() writes a single-file repo, commits it, and returns
(repo_path, base_ref). The repo is the stand-in for a NemoClaw checkout —
the patch-isolation tests apply diffs into worktrees off it without needing
a real NemoClaw or any credentials.
"""

from __future__ import annotations

import subprocess
from pathlib import Path

from interfaces.types import PatchCandidate

# A clean-apply diff against the file build_repo() writes.
GOOD_DIFF = (
    "--- a/control.py\n"
    "+++ b/control.py\n"
    "@@ -1,2 +1,2 @@\n"
    " # nemoclaw control plane\n"
    "-ALLOWED_PATHS = ['/work', '/']\n"
    "+ALLOWED_PATHS = ['/work']\n"
)
# A diff whose context will not match -> a rejected hunk.
CONFLICTING_DIFF = (
    "--- a/control.py\n"
    "+++ b/control.py\n"
    "@@ -1,2 +1,2 @@\n"
    " # totally different first line\n"
    "-ALLOWED_PATHS = ['/nope']\n"
    "+ALLOWED_PATHS = []\n"
)


def build_repo(root: Path) -> tuple[str, str]:
    """Create a committed single-file repo; return (repo_path, base_ref)."""
    root.mkdir(parents=True, exist_ok=True)
    (root / "control.py").write_text(
        "# nemoclaw control plane\n"
        "ALLOWED_PATHS = ['/work', '/']\n")
    for cmd in (
        ["git", "init", "-q"],
        ["git", "config", "user.email", "test@monkeyclaw"],
        ["git", "config", "user.name", "monkeyclaw-test"],
        ["git", "add", "."],
        ["git", "commit", "-q", "-m", "base"],
    ):
        subprocess.run(cmd, cwd=root, check=True, capture_output=True)
    rev = subprocess.run(
        ["git", "rev-parse", "HEAD"], cwd=root, check=True,
        capture_output=True, text=True)
    return str(root), rev.stdout.strip()


def make_patch(patch_id: str, diff: str) -> PatchCandidate:
    """Build a valid PatchCandidate carrying `diff` — the patch-isolation
    tests only exercise patch_id and diff, so the rest is filler."""
    return PatchCandidate(
        patch_id=patch_id, vuln_ids=["MC-2026-0001"], zone_id="SBX-FS",
        approach="canon", invasiveness="low", diff=diff,
        explanation="x", side_effects="x", status="proposed")
