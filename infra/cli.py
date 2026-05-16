"""MonkeyClaw CLI — the single demo entrypoint.

    monkeyclaw run --cycles 5 --target monkey-victim   run N red-team cycles
    monkeyclaw run --perpetual --target monkey-victim  run indefinitely
    monkeyclaw status                                  coverage + findings summary
    monkeyclaw findings                                list confirmed/suspicious vulns
    monkeyclaw repro <vuln_id>                         run the repro pipeline on a finding
    monkeyclaw dashboard [--port 8787]                 start the live web dashboard

Wired as the `monkeyclaw` script entry point in pyproject.toml.
"""

from __future__ import annotations

import argparse
import os
import sys
import time

from infra.config import load_config

# ---------------------------------------------------------------------------
# run — red/blue cycles via the orchestrator
# ---------------------------------------------------------------------------


def _cmd_run(args: argparse.Namespace) -> int:
    # --target plumbs through the layered config's env-override mechanism.
    os.environ["MC_NEMOCLAW__SANDBOX_NAME"] = args.target
    from infra import orchestrator

    argv = [
        "--red", "red_team.pipeline:Pipeline",
        "--blue", "blue_team.pipeline:Pipeline",
    ]
    if args.mock:
        argv.append("--use-mock-provisioner")
    if not args.perpetual:
        argv += ["--max-cycles", str(args.cycles)]
    mode = "perpetual" if args.perpetual else f"{args.cycles} cycle(s)"
    print(f"MonkeyClaw — running {mode} against '{args.target}'\n")
    return orchestrator.main(argv)


# ---------------------------------------------------------------------------
# status / findings — read the persistent knowledge base
# ---------------------------------------------------------------------------


def _open_db():
    from infra.database import Database

    cfg = load_config()
    return Database(cfg.storage.db_path), cfg


def _cmd_status(args: argparse.Namespace) -> int:
    db, cfg = _open_db()
    try:
        zones = db.fetchall(
            "SELECT zone_id, name, coverage_score, vulns_open, vulns_found "
            "FROM surface_zones ORDER BY coverage_score ASC"
        )
        findings = db.fetchall("SELECT verdict, severity FROM findings")
        cycles = db.fetchone("SELECT COUNT(*) AS n FROM cycle_log")
        tests = db.fetchone(
            "SELECT COUNT(*) AS n FROM regression_tests WHERE deprecated = 0"
        )
    except Exception as e:  # noqa: BLE001
        print(f"could not read knowledge base ({cfg.storage.db_path}): {e}")
        return 1
    confirmed = sum(1 for f in findings if f["verdict"] == "confirmed")
    suspicious = sum(1 for f in findings if f["verdict"] == "suspicious")
    cov = (sum(z["coverage_score"] for z in zones) / len(zones)) if zones else 0.0

    print("=== MonkeyClaw status ===")
    print(f"  cycles completed : {cycles['n'] if cycles else 0}")
    print(f"  findings         : {confirmed} confirmed, {suspicious} suspicious, "
          f"{len(findings)} total")
    print(f"  regression tests : {tests['n'] if tests else 0}")
    print(f"  mean coverage    : {cov:.0%}  ({len(zones)} zones)")
    print("\n  attack surface (lowest coverage first):")
    for z in zones[:12]:
        bar = "#" * int(z["coverage_score"] * 20)
        print(f"    {z['zone_id']:14} {z['coverage_score']:.2f} "
              f"|{bar:<20}|  open={z['vulns_open']} found={z['vulns_found']}")
    db.close()
    return 0


def _cmd_findings(args: argparse.Namespace) -> int:
    db, _ = _open_db()
    try:
        rows = db.fetchall(
            "SELECT finding_id, zone_id, verdict, severity, failure_class, "
            "idea_summary, created_at FROM findings "
            "WHERE verdict IN ('confirmed', 'suspicious') "
            "ORDER BY CASE severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 "
            "WHEN 'medium' THEN 2 ELSE 3 END, created_at DESC"
        )
    except Exception as e:  # noqa: BLE001
        print(f"could not read findings: {e}")
        return 1
    if not rows:
        print("no confirmed or suspicious findings yet — run `monkeyclaw run` first.")
        return 0
    print(f"=== {len(rows)} finding(s) ===")
    for r in rows:
        print(f"\n  [{r['severity'].upper()}] {r['finding_id']}  "
              f"({r['verdict']}, {r['zone_id']}, {r['failure_class']})")
        print(f"    {r['idea_summary'][:140]}")
        print(f"    {r['created_at']}")
    db.close()
    return 0


# ---------------------------------------------------------------------------
# repro — run the blue repro pipeline on one finding
# ---------------------------------------------------------------------------


def _cmd_repro(args: argparse.Namespace) -> int:
    from infra.bootstrap import boot
    from infra.mcp_server import _finding_row_to_record

    rt = boot(use_mock_provisioner=args.mock)
    try:
        row = rt.db.fetchone(
            "SELECT * FROM findings WHERE finding_id = ?", (args.vuln_id,)
        )
        if row is None:
            print(f"no finding with id {args.vuln_id!r}. "
                  f"Use `monkeyclaw findings` to list them.")
            return 1
        finding = _finding_row_to_record(row)
        from blue_team.pipeline import Pipeline as BluePipeline

        blue = BluePipeline(rt)
        print(f"running repro pipeline on {finding.finding_id} "
              f"(zone {finding.zone_id}, severity {finding.severity}) ...")
        blue._process_one_finding(finding)
        print("repro pipeline complete — see `monkeyclaw status` for the package.")
        return 0
    finally:
        rt.shutdown()


# ---------------------------------------------------------------------------
# probe — talk directly to the victim
# ---------------------------------------------------------------------------


def _build_provisioner(target: str):
    from infra.provisioning_nemoclaw import NemoClawProvisioner

    nc = load_config().nemoclaw
    return NemoClawProvisioner(
        cli_binary=nc.cli_binary,
        sandbox_name=target,
        sandbox_namespace=nc.sandbox_namespace,
        clean_snapshot=nc.clean_snapshot,
        gateway_endpoint=nc.gateway_endpoint,
        gateway_container=nc.gateway_container,
        snapshot_restore_timeout_s=nc.snapshot_restore_timeout_s,
        recover_timeout_s=nc.recover_timeout_s,
    ), nc


def _cmd_probe(args: argparse.Namespace) -> int:
    """Direct line to the victim — send messages and see its replies.

    Use it to try things by hand: prompt-engineering experiments, PII
    exfiltration attempts, jailbreak phrasings. The victim's session
    persists between turns, so a sequence of probes is one conversation.
    """
    from interfaces.provisioning import VictimConfig
    from interfaces.victim_client import VictimClient

    prov, nc = _build_provisioner(args.target)
    if args.reset:
        print(f"provisioning a fresh '{args.target}' (snapshot restore + recover) ...")
        inst = prov.provision_victim(VictimConfig(
            nemoclaw_version=nc.version,
            policy_path=nc.default_policy_path,
            agent_type="coding_assistant",
            agent_config_path=nc.default_agent_config_path,
        ))
    else:
        inst = prov.connect_existing()
    token = inst.metadata["gateway_token"]
    print(f"connected to victim '{args.target}' @ {inst.chat_endpoint}")

    def _send(client: VictimClient, msg: str) -> None:
        t0 = time.time()
        try:
            reply, _ = client.send(msg)
        except Exception as e:  # noqa: BLE001
            print(f"  [transport error: {e}]\n")
            return
        print(f"victim> {reply}   ({time.time() - t0:.0f}s)\n")

    with VictimClient(inst.chat_endpoint, auth_token=token) as client:
        if args.message:
            print(f"\nyou> {args.message}")
            _send(client, args.message)
            return 0
        print("interactive probe — type a message; 'exit' or Ctrl-D to quit.\n")
        while True:
            try:
                msg = input("you> ").strip()
            except EOFError:
                print()
                break
            if msg in ("exit", "quit"):
                break
            if not msg:
                continue
            _send(client, msg)
    return 0


# ---------------------------------------------------------------------------
# blue-team — demo mode: triage -> patch -> test, output only
# ---------------------------------------------------------------------------


def _indent(text: str, pad: str = "      ") -> str:
    return "\n".join(pad + ln for ln in (text or "").splitlines())


def _cmd_blueteam(args: argparse.Namespace) -> int:
    from infra.bootstrap import boot

    # The blue triage/patch/test stages never provision a victim (only the
    # verifier does, which demo mode skips) — boot with the mock provisioner.
    rt = boot(use_mock_provisioner=True)
    try:
        packages = list(rt.mcp.get_blue_team_queue())
        if args.vuln_id:
            packages = [p for p in packages if args.vuln_id in (p.vuln_id, p.finding_id)]
        if not packages:
            print("no repro packages ready for the blue team. "
                  "Run `monkeyclaw repro <finding_id>` first.")
            return 0
        from blue_team.pipeline import Pipeline as BluePipeline

        blue = BluePipeline(rt)
        tasks = blue.triage.triage(packages)
        print("=== BLUE TEAM (demo mode — output only, nothing applied) ===")
        print(f"triaged {len(packages)} package(s) -> {len(tasks)} fix task(s)\n")
        for task in tasks:
            print(f"--- task {task.task_id}  severity={task.severity}  "
                  f"vulns={','.join(task.vuln_ids)}")
            candidates = blue.patch_generator.generate_for_task(task)
            print(f"  {len(candidates)} patch candidate(s):")
            for c in candidates:
                print(f"\n  [{c.patch_id}] {c.approach}  (invasiveness: {c.invasiveness})")
                print(f"    {c.explanation}")
                if c.diff.strip():
                    print("    diff:")
                    print(_indent(c.diff[:1200]))
            if candidates and task.packages:
                pair = blue.test_generator.generate(task.packages[0], candidates[0])
                print(f"\n  regression test [{pair.vuln_id}]:")
                print(_indent(pair.positive_test.test_script[:900]))
            print()
        print("(demo mode — patches were NOT applied or verified against NemoClaw)")
        return 0
    finally:
        rt.shutdown()


# ---------------------------------------------------------------------------
# demo — one-shot preset: a single mock cycle against a planted profile
# ---------------------------------------------------------------------------


def _cmd_demo(args: argparse.Namespace) -> int:
    """Run the canned demo: one mock cycle against a planted victim profile.

    This is a thin preset over `run` — `demo --profile X` does exactly what
    `run --cycles 1 --target X --mock` does, then prints the resulting
    findings so the demo is self-contained.
    """
    from demo.victims.registry import PROFILES

    if args.profile not in PROFILES:
        print(f"unknown planted profile {args.profile!r}; "
              f"known: {', '.join(sorted(PROFILES))}")
        return 1

    print(f"=== MonkeyClaw demo — planted profile '{args.profile}' ===\n")

    # Reuse the run path verbatim: build a Namespace matching `run`'s args.
    run_args = argparse.Namespace(
        cycles=1, perpetual=False, target=args.profile, mock=True,
    )
    rc = _cmd_run(run_args)
    if rc != 0:
        print(f"\ndemo cycle failed (run exited {rc}).")
        return rc

    # Print the findings the cycle produced, the way `findings` does.
    print("\n--- findings from this demo ---")
    _cmd_findings(args)
    return 0


# ---------------------------------------------------------------------------
# test — self-checks (notification delivery)
# ---------------------------------------------------------------------------


def _cmd_test(args: argparse.Namespace) -> int:
    if args.kind != "notification":
        print(f"unknown test: {args.kind!r}")
        return 1
    from infra.notifications import AlertDispatcher

    cfg = load_config()
    n = cfg.notifications
    if not n.telegram_bot_token:
        print("no Telegram bot token — set MC_TELEGRAM_BOT_TOKEN.")
        return 1
    if not n.telegram_chat_id:
        print("no Telegram chat id — set MC_TELEGRAM_CHAT_ID.")
        return 1
    disp = AlertDispatcher(n)
    try:
        # Call the telegram path directly so a failure surfaces here rather
        # than being swallowed as a warning inside the multiplexed send().
        disp._send_telegram(f"[TEST] {args.message}")
        print(f"notification delivered to chat {n.telegram_chat_id}: "
              f"{args.message!r}")
        return 0
    except Exception as e:  # noqa: BLE001
        print(f"telegram delivery FAILED: {e}")
        return 1
    finally:
        disp.close()


# ---------------------------------------------------------------------------
# dashboard
# ---------------------------------------------------------------------------


def _cmd_dashboard(args: argparse.Namespace) -> int:
    try:
        from infra.dashboard import serve
    except ImportError as e:  # pragma: no cover
        print(f"dashboard module unavailable: {e}")
        return 1
    cfg = load_config()
    serve(db_path=cfg.storage.db_path, port=args.port)
    return 0


# ---------------------------------------------------------------------------
# arg parsing
# ---------------------------------------------------------------------------


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="monkeyclaw",
        description="Autonomous red-team / blue-team security agent for NemoClaw.",
    )
    sub = p.add_subparsers(dest="command", required=True)

    run = sub.add_parser("run", help="run red-team cycles against a target sandbox")
    run.add_argument("--cycles", type=int, default=1, help="number of cycles (default 1)")
    run.add_argument("--perpetual", action="store_true", help="run indefinitely")
    run.add_argument("--target", default="monkey-victim", help="target sandbox name")
    run.add_argument("--mock", action="store_true",
                     help="use the in-memory mock provisioner (no live sandbox)")
    run.set_defaults(func=_cmd_run)

    st = sub.add_parser("status", help="print coverage + findings summary")
    st.set_defaults(func=_cmd_status)

    fd = sub.add_parser("findings", help="list confirmed/suspicious findings")
    fd.set_defaults(func=_cmd_findings)

    rp = sub.add_parser("repro", help="run the repro pipeline on a finding")
    rp.add_argument("vuln_id", help="finding_id to reproduce")
    rp.add_argument("--mock", action="store_true", help="use the mock provisioner")
    rp.set_defaults(func=_cmd_repro)

    pr = sub.add_parser("probe",
                        help="talk directly to the victim (interactive or one-shot)")
    pr.add_argument("--target", default="monkey-victim", help="target sandbox name")
    pr.add_argument("-m", "--message", default=None,
                    help="one-shot: send this message and exit")
    pr.add_argument("--reset", action="store_true",
                    help="snapshot-restore + recover the victim first (clean slate)")
    pr.set_defaults(func=_cmd_probe)

    bt = sub.add_parser("blue-team",
                        help="demo: triage -> patch -> test for queued repros")
    bt.add_argument("vuln_id", nargs="?", default=None,
                    help="optional: limit to one vuln_id / finding_id")
    bt.add_argument("--mock", action="store_true",
                    help="use the mock provisioner (default for demo mode)")
    bt.set_defaults(func=_cmd_blueteam)

    dm = sub.add_parser("demo",
                        help="one-shot demo: a mock cycle against a planted profile")
    dm.add_argument("--profile", default="planted-filesystem",
                    help="planted victim profile (default planted-filesystem)")
    dm.set_defaults(func=_cmd_demo)

    ts = sub.add_parser("test", help="self-checks (e.g. notification delivery)")
    ts.add_argument("kind", choices=["notification"], help="what to test")
    ts.add_argument("message", nargs="?", default="MonkeyClaw test notification",
                    help="message body for the test")
    ts.set_defaults(func=_cmd_test)

    db = sub.add_parser("dashboard", help="start the live web dashboard")
    db.add_argument("--port", type=int, default=8787, help="HTTP port (default 8787)")
    db.set_defaults(func=_cmd_dashboard)

    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return args.func(args)
    except KeyboardInterrupt:
        print("\ninterrupted.")
        return 130


if __name__ == "__main__":
    sys.exit(main())
