# Patch Isolation Runbook

Operator guide for the real disposable-worktree patch verification path
(`blue_team/patch_isolation.py`). See the design spec
`docs/superpowers/specs/2026-05-15-real-patch-isolation-design.md`.

## What it does

`PatchIsolation` makes "all six gates passed" mean the gates passed against a
victim with the candidate diff actually applied — not against the unpatched
mock replay surface. For each candidate patch it:

1. `git worktree add` a fresh checkout at a pinned base commit, under a unique
   `mc-patch-*` temp directory.
2. `git apply --check` then `git apply` the candidate diff into that worktree.
3. Rebuilds the victim from the patched worktree via the rebuildable
   provisioner (`VictimConfig.nemoclaw_repo_path`).
4. Hands `PatchVerifier` a `ReplayFn` bound to that patched victim.
5. Tears down the victim and worktree in a `finally` — even on a crash.

When no rebuildable victim is configured, isolation degrades to the existing
mock replay and stamps `VerifyOutcome.isolation_mode="mock"`, so a verdict is
never silently overclaimed. **Mock is the default and a first-class fallback.**

## Configuration

`blue_team.patch_isolation` in `configs/monkeyclaw.yaml`:

| Key | Default | Meaning |
|-----|---------|---------|
| `enabled` | `false` | Master switch. Off → mock fallback. |
| `nemoclaw_repo_path` | `null` | Path to the NemoClaw git checkout the worktrees branch from. Required for the live path. |
| `base_ref` | `"HEAD"` | Commit/ref the worktree is created at. |
| `build_timeout_s` | `900` | Timeout for `git worktree add` (and the build). |
| `worktree_root` | `"/tmp"` | Directory the `mc-patch-*` worktrees are created under. |

The live path activates only when `enabled: true` **and**
`nemoclaw_repo_path` is set. Otherwise the pipeline logs a startup warning and
runs verification on the mock surface.

## Dependency

The live path depends on the real-nemoclaw-provisioner spec for the
rebuildable victim: the provisioner must accept `VictimConfig.nemoclaw_repo_path`
and build a victim from the patched worktree. With `MockProvisioner` the
build degrades to `build_status="build_failed"` / mock replay.

## Reading the dashboard

The patch panel shows an `isolation_mode` badge per patch, sourced from the
latest `patch_builds` row for that patch:

- **`live`** — the verdict was proven against a real patched build.
- **`mock`** — the verdict ran on the mock replay surface (default when no
  build row exists or isolation is disabled).

## Janitor sweep

On `Pipeline` startup, when isolation is enabled, `sweep_orphaned_worktrees`
removes every `mc-patch-*` directory under `worktree_root` left behind by a
prior crash. There is no background scheduler — the sweep runs once at
startup. A leftover directory is reclaimed whether its `patch_builds` row is
untorn or absent; the disk sweep is the source of truth, the row is advisory.

## Audit table

`patch_builds` (migration 0013) records one row per attempted isolation
build: `build_status` (`built` / `apply_failed` / `build_failed` / `mock`),
`diff_applied`, `rejected_hunks`, `isolation_mode`, `torn_down`, and timing.
Inspect with:

```
uv run python -c "from infra.database import Database; d=Database('data/monkeyclaw.db'); print(len(d.fetchall('SELECT * FROM patch_builds')))"
```

## Caveats (spec §14)

- **base_ref pinning** — `base_ref` is an explicit config value. It must match
  the commit the running victim was built from; otherwise the patched build
  and the live victim diverge. Until the companion provisioner spec reports
  the victim's build commit, keeping `base_ref` aligned is the operator's
  responsibility.
- **build determinism** — not solved here; a follow-up item.
- **diff path rooting** — the single-repo victim uses `a/`…`b/` prefixes that
  `git apply` handles by default; `-p<n>` is left as a future config knob.

Cross-reference spec §13 for the phased delivery plan.
