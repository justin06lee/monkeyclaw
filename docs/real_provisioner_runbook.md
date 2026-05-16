# Real NemoClaw Provisioner — Operator Runbook

Bringing up MonkeyClaw against a live NemoClaw victim instead of the default
mock. See the design spec `docs/superpowers/specs/2026-05-15-real-nemoclaw-provisioner-design.md`
(§13 phased delivery, §14 open questions) for background.

## Mock stays the default

With zero credentials and no `nemoclaw` CLI on PATH, MonkeyClaw runs the
`MockProvisioner` end to end. `bootstrap.boot()` probes the local build once;
when `cli_present` is False it logs a loud warning and falls back to mock.
Nothing about the live path is required for the demo cycle.

## The `MC_LIVE_NEMOCLAW` marker

Live-only smoke checks are gated behind the `MC_LIVE_NEMOCLAW=1` env marker
and the `-m live` pytest marker. On CI / a host without the CLI they report
`deselected`, which is the expected CI behaviour:

```
MC_LIVE_NEMOCLAW=1 uv run pytest test/test_provisioning_lifecycle.py -q -m live
```

## NemoClaw build requirements

The provisioner probes the local build at construction and freezes a
`SandboxCapabilities`:

- `cli_present`  — `nemoclaw` resolves on PATH.
- `snapshots`    — `nemoclaw <sandbox> snapshot create` succeeds.
- `ephemeral`    — implied by `snapshots`; per-lane disposable clones need
  working snapshots.
- `recover`      — `nemoclaw <sandbox> recover --dry-run` succeeds.
- `container_fsdiff` — `nemoclaw <sandbox> inspect --container` yields a
  container id.

`snapshot create` / `snapshot restore` MUST succeed for **ephemeral
snapshot-isolated** victims. Without them the provisioner degrades to
**recover-only** mode.

## Recover-only degradation

When `snapshots` is False the provisioner restarts the gateway + agent but
does NOT reset the filesystem. Consequences:

- Filesystem changes from a prior lane **bleed** into the next.
- Every `LaneResult.deterministic` is stamped `False`.
- `sandbox_runs.mode` is `recover_only`.

Reproductions taken under `deterministic=False` are not guaranteed
replayable. Treat them as advisory until a snapshot-capable build is
available.

## Config keys (`nemoclaw:` block in `configs/monkeyclaw.yaml`)

- `baseline_snapshot` — the immutable clean image name. Distinct from
  `clean_snapshot`, the per-lane restore target. Defaults to the same name.
- `work_area_dir` — disposable per-lane clone location. `teardown_victim`
  discards everything under here.
- `patch_build_timeout_s` — upper bound on a per-candidate patch rebuild.

## Reading capabilities from the bootstrap log

`bootstrap.boot()` logs at INFO:

```
monkeyclaw.provisioning.caps INFO probed sandbox capabilities for monkey-victim: SandboxCapabilities(...)
```

and at WARNING when degrading to mock. Inspect this line to confirm whether
the live path is ephemeral, recover-only, or absent.

## Patch verification

`provision_victim(VictimConfig(patch_diff=...))` builds a patched victim via
`PatchBuilder`: clone the NemoClaw checkout into a disposable work area,
apply the diff, rebuild, snapshot. With no snapshot support, a `patch_diff`
raises `ProvisioningError` — never a silent unpatched victim.

## Known follow-up

A crashed-before-teardown reaper for stale `work_area_dir` clones is a noted
follow-up, consistent with the data-integrity stale-claim sweep.
