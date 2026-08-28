#!/usr/bin/env python3
"""Chainwatch - which commit made this contract vulnerable, and is it live.

    python chainwatch.py --repo <path-or-url> [--address 0x...] [--limit 50]

Walks a Solidity repository's commit history, runs every shipped regression
rule over each (parent, commit) pair, attributes each fire to a contract and
function, checks whether the regression survives to HEAD, and - when an address
is given - whether the affected code is what is deployed on-chain.

The report ALWAYS prints coverage before findings. "0 findings" from a scan
that could only analyse 3 of 40 commit pairs is not a clean bill of health, and
this tool refuses to let that distinction be lost (finding HIST-L1).

Read-only on the target repository and on chain, always (CHARTER rule 5).
"""

from __future__ import annotations

import argparse
import json
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))

from src.scan import RULE_ORDER, RULE_TITLES, ScanOptions, scan  # noqa: E402
from src import verdict as V  # noqa: E402
from src import liveness as L  # noqa: E402
from src import exposure as E  # noqa: E402
from src import deepen as DEEPEN  # noqa: E402
from src.history import clone_public  # noqa: E402


# Anything git can clone from. `file://` is included so the clone path itself
# is testable without a network round trip.
CLONE_SCHEMES = ("http://", "https://", "git@", "ssh://", "git://", "file://")


def clone(url: str, dest: Path) -> Path:
    """Full-history anonymous clone, through the ONE implementation in
    history.py. Depth is NOT truncated: trajectory is the product, and a
    shallow clone has no trajectory."""
    try:
        return clone_public(url, dest, on_progress=print)
    except RuntimeError as exc:
        sys.exit(str(exc))


def _print_progress(ev: dict) -> None:
    kind = ev.get("kind")
    if kind == "pair":
        print(f"  [{ev['index']}/{ev['total']}] {ev['prev']}..{ev['cur']}  "
              f"{ev.get('subject','')[:60]}")
    elif kind == "skip":
        print(f"      SKIPPED: {ev.get('reason')}")
    elif kind == "finding":
        where = (f"{ev.get('contract')}.{ev['function']}" if ev.get("function")
                 else str(ev.get("contract")))
        print(f"      {ev['verdict']:<9} rule {ev['rule']:<3} {ev['file']}::{where}")
    elif kind == "env":
        # The longest silent phase of a scan. Without this a large monorepo
        # install looks like a hang for minutes (measured on balancer-v3, a
        # Yarn Berry workspace: zero output until it finished).
        print(f"  ... {ev.get('message')}", flush=True)
    elif kind == "warn":
        print(f"  ! {ev.get('message')}")
    elif kind == "liveness":
        print(f"  checking on-chain liveness for {ev.get('address')}")


def _wrap(text: str, width: int = 74) -> list[str]:
    import textwrap

    return textwrap.wrap(text, width=width)


def _print_sizing(sz: dict) -> None:
    """Time measured, and what it does or does NOT support projecting.

    The refusal text is rendered at the SAME weight as the SCAN-L1 banner, and
    for the same reason: a range that is withheld reads as a bug unless the user
    is told, in the report itself, that the withholding is deliberate and why.
    The `refusal` string already carries the age->bias->13x argument (SIZE-L1);
    this function's whole job is to make sure it reaches a user's eyes rather
    than living only in LIMITATIONS.md and the JSON.
    """
    obs = sz.get("observed")
    if not obs:
        return
    print("\nSIZING (measured, not predicted)")
    print(f"  observed          : {obs['pairs']} pair(s), {obs['comparisons']} "
          f"comparison(s) ({obs['comparisons_ok']} ok) in {obs['seconds']}s")
    spread = sz.get("per_comparison_seconds")
    if spread:
        print(f"  per comparison    : {spread['low']}-{spread['high']}s "
              f"(spread across {spread['basis_n']} pair(s))")
    coverage = sz.get("coverage_pct")
    if coverage:
        print(f"  coverage spread   : {coverage['low']}-{coverage['high']}% "
              f"(across {coverage['basis_n']} pair(s))")

    proj = sz.get("projection")
    if proj:
        print(f"  remaining ({proj['basis_n']} obs) : {proj['low']}-{proj['high']}s "
              f"for the rest of the run")
        for line in _wrap(sz.get("caveat", "")):
            print(f"      {line}")
    elif sz.get("refusal"):
        # Banner-weight: this is a deliberate refusal, not a missing number.
        print("\n" + "!" * 78)
        print("NO TIME ESTIMATE - AND THIS IS WHY (not a bug, not missing data)")
        for line in _wrap(sz["refusal"]):
            print("  " + line)
        print("!" * 78)


def print_report(rep: dict) -> None:
    s, cov = rep["summary"], rep["coverage"]
    print()
    print("=" * 78)
    print(f"CHAINWATCH REPORT   {rep['repo']}")
    print(f"HEAD {rep.get('head')}")
    print("=" * 78)

    # SCOPE, then coverage, then findings. Each answers a question the next is
    # meaningless without: what was looked at, how much of that could be
    # analysed, and only then what was found.
    scope = rep.get("scope") or {}
    if scope:
        roots = ", ".join((r + "/") if r else "(repository root)"
                          for r in (scope.get("roots") or [])) or "(nothing)"
        print(f"\nSCOPE     {roots}   [{scope.get('mode', 'auto')}]")
        if scope.get("reason"):
            for line in _wrap(scope["reason"]):
                print(f"          {line}")

    # Coverage FIRST. A finding count without it is not interpretable.
    print("\nCOVERAGE (read this before the findings)")
    print(f"  commit pairs analyzed : {cov['pairs_analyzed']}/{cov['pairs_total']}"
          f"  ({cov['pairs_analyzed_pct']}%)")
    print(f"  file comparisons ok   : {cov['files_ok']}/{cov['files_total']}"
          f"  ({cov['files_ok_pct']}%)")
    if cov.get("files_partial"):
        print(f"  partially analysed    : {cov['files_partial']} "
              f"(some rules ran, some failed)")
    # COV-ACCT1: the honest denominator. Coverage is earned per rule, and a
    # file-level count hides nine clean rule runs behind one failure.
    if cov.get("rule_invocations_total"):
        print(f"  rule checks completed : {cov['rule_invocations_ok']}"
              f"/{cov['rule_invocations_answerable']}"
              f"  ({cov['rule_coverage_pct']}% of answerable)")
        if cov.get("rule_invocations_unsupported"):
            print(f"  not applicable here   : "
                  f"{cov['rule_invocations_unsupported']} rule check(s) "
                  f"(rule needs a compiler feature this source's version lacks)")
    if cov["pairs_skipped"]:
        print(f"  pairs skipped         : {cov['pairs_skipped']}")
        reasons: dict[str, int] = {}
        for sk in cov["skips"]:
            reasons[sk["reason"]] = reasons.get(sk["reason"], 0) + 1
        for reason, n in sorted(reasons.items(), key=lambda kv: -kv[1]):
            print(f"      {n:>4}  {reason}")
    if cov["files_error"]:
        print(f"  file comparisons lost : {cov['files_error']} "
              f"(rule errors, see --json for detail)")
    if cov.get("files_skipped"):
        print(f"  never attempted       : {cov['files_skipped']} "
              f"(toolchain missing, not analysed at all)")
        reasons: dict[str, int] = {}
        for fs in cov.get("file_skips", []):
            reasons[fs["reason"]] = reasons.get(fs["reason"], 0) + 1
        for reason, n in sorted(reasons.items(), key=lambda kv: -kv[1]):
            print(f"      {n:>4}  {reason}")
    if cov["pairs_analyzed"] < cov["pairs_total"]:
        print("  NOTE: this scan did not see the whole history. A quiet result "
              "over unanalyzed\n        commits means UNMEASURED, not SAFE.")

    _print_sizing(rep.get("sizing") or {})

    print(f"\nSUMMARY   {s['findings']} finding(s): "
          f"{s['confirmed']} CONFIRMED, {s['candidates']} CANDIDATE "
          f"in {s['seconds']}s")
    if rep["by_rule"]:
        for rid in RULE_ORDER:
            if rid in rep["by_rule"]:
                print(f"    rule {rid:<3} {RULE_TITLES[rid]:<42} {rep['by_rule'][rid]}")

    if rep.get("nothing_compared"):
        print("\n" + "!" * 78)
        print("NOT A RESULT ABOUT THIS CODE")
        for line in _wrap(rep["nothing_compared"]):
            print("  " + line)
        print("!" * 78)

    exposure = rep.get("exposure") or []
    if exposure:
        print("\nEXPOSURE PROBE (capability 13 - live, not a finding, not a verdict)")
        print("  Is a one-shot init/critical-config function still unconsumed on the")
        print("  deployed contract right now? Answered by a real read-only eth_call,")
        print("  never a guess - see src/exposure.py.")
        for e in exposure:
            print(f"    {e['status']:<8} {e['contract']}.{e['function']}"
                  f"  {e['signature']}")
            print(f"             {e['reason']}")
            if e["status"] == E.OPEN:
                print("             >>> exploitable right now, verified, not inferred")

    if not rep["findings"]:
        print("\nNo regression matched any shipped rule over the analyzed pairs.")
        return

    order = {V.CONFIRMED: 0, V.CANDIDATE: 1, V.DISCARDED: 2}
    for i, f in enumerate(sorted(rep["findings"],
                                 key=lambda x: (order.get(x["verdict"], 9), x["rule_id"])), 1):
        print("\n" + "-" * 78)
        loc = f"{f['contract']}.{f['function']}" if f["function"] else f["contract"]
        print(f"#{i}  {f['verdict']}   rule {f['rule_id']} - "
              f"{RULE_TITLES.get(f['rule_id'], '')}")
        print(f"    {f['file']}:{f['line']}   {loc}")
        print(f"    {f['detail']}")
        print(f"\n    TRAJECTORY")
        print(f"      introduced : {(f['commit'] or '')[:12]}  {f.get('date','')}"
              f"  {f.get('author','')}")
        print(f"      parent     : {(f['parent'] or '')[:12]}")
        print(f"      lines      : {f.get('line_range')}")
        surv = f["survives_to_head"]
        print(f"      at HEAD    : "
              + ("still present" if surv is True else
                 f"repaired later (quiet at {f.get('fixed_at')})" if surv is False
                 else "undetermined"))
        if f.get("liveness"):
            print(f"      on-chain   : {f['liveness']} - {f['liveness_reason']}")
            if f["liveness"] == V.LIVE:
                # Never print LIVE unqualified - see liveness.LIVE_CAVEAT.
                print(f"                   {L.LIVE_CAVEAT}")
        xp = f.get("exploit_proof")
        if xp and xp["status"] != "NOT_APPLICABLE":
            print(f"\n    EXPLOITABILITY PROOF (capability 14 - read-only eth_call, "
                  f"never a transaction)")
            print(f"      {xp['status']:<8} {xp['reason']}")
        if f["downgrade_reasons"]:
            print("\n    WHY NOT CONFIRMED")
            for r in f["downgrade_reasons"]:
                print(f"      - {r}")
        # DEEPEN-1: naming the gap is only half an answer; say what closes it.
        steps = DEEPEN.next_steps(f)
        if steps:
            print("\n    WHAT WOULD SETTLE IT")
            for s in steps:
                print(f"      [{s['status']}] {s['gap']}: {s['why']}")
                for line in _wrap(s["action"], width=66):
                    print(f"          {line}")


def main() -> int:
    ap = argparse.ArgumentParser(description="Chainwatch trajectory scanner")
    ap.add_argument("--repo", help="local path or clone URL (omit only with --from-json)")
    ap.add_argument("--address", help="deployed address for the liveness gate")
    ap.add_argument("--rpc-url", help="override RPC_URL from .env")
    ap.add_argument("--pairs", default="",
                    help="explicit prev:cur commit pairs (comma-separated) "
                         "instead of walking recent history. What makes a "
                         "demo or a re-check reproducible rather than "
                         "dependent on wherever the branch tip happens to be.")
    ap.add_argument("--limit", type=int, default=50,
                    help="how many .sol-touching commits to walk (default 50)")
    ap.add_argument("--root", default="", help="restrict to a subdirectory, e.g. contracts")
    ap.add_argument("--rules", default="",
                    help=f"comma-separated subset of {','.join(RULE_ORDER)}")
    ap.add_argument("--no-head-check", action="store_true",
                    help="skip the survives-to-HEAD re-run (faster, weaker evidence)")
    ap.add_argument("--check-exposure", action="store_true",
                    help="capability 13: for files this scan already flagged, also "
                         "check via a real read-only eth_call whether a one-shot "
                         "init/critical-config function is still unconsumed on the "
                         "deployed contract right now. Needs --address. Separate "
                         "from findings/verdicts - printed as its own section.")
    ap.add_argument("--check-exploit-proof", action="store_true",
                    help="capability 14: for every CONFIRMED finding on rule 1, 3a, "
                         "3b or 10 (the rules where 'callable without authorization' "
                         "IS the regression), a real read-only eth_call proving the "
                         "exact regressed function is callable by an unprivileged "
                         "address right now. Needs --address. Never a real "
                         "transaction - see src/exploit_proof.py.")
    ap.add_argument("--json", help="write the full report here")
    ap.add_argument("--quiet", action="store_true", help="suppress progress lines")
    ap.add_argument("--generate-reports", action="store_true",
                    help="after the scan, have the Gemini agent draft a dossier for "
                         "each finding (capability 12). Needs GEMINI_API_KEY.")
    ap.add_argument("--from-json",
                    help="skip scanning and load a previously written report JSON; "
                         "pair with --generate-reports to draft from an earlier scan")
    ap.add_argument("--reports-dir", default="reports",
                    help="where generated dossiers are written (default: reports/)")
    ap.add_argument("--rpm", type=int, default=None,
                    help="model requests per minute budget (default 12, sized for the "
                         "Gemini free tier's 15). Raising it is a config change only.")
    ap.add_argument("--nextgen", metavar="FILE:CONTRACT:FUNCTION",
                    help="EXPERIMENTAL (src/nextgen/, additive, flag-gated): run the "
                         "execution-grounded proof pipeline over ONE (parent:commit) "
                         "pair given by --pairs, on the named target. Reconstructs "
                         "each side's dependency environment, discovers + diffs "
                         "security invariants, builds the attack-path graph, checks "
                         "compensating controls, and - with --address - verifies "
                         "bytecode provenance, liveness, and reproduces the violation "
                         "(local fork, or a read-only eth_call for a pre-0.6 pragma). "
                         "Prints a CONFIRMED / UNKNOWN / REJECTED research report. "
                         "The classic pipeline above is untouched.")
    ap.add_argument("--nextgen-rule", default="", metavar="ID",
                    help="rule id hint for --nextgen (1, 3a, 3b, 10) - sets the "
                         "report's Type label and the pre-0.6 exploit-probe rule.")
    ap.add_argument("--twin", metavar="ADDRESS",
                    help="EXPERIMENTAL (src/nextgen/twin/, additive, flag-gated): "
                         "the Counterfactual Protocol Twin - reason from REAL "
                         "on-chain behaviour instead of git history. Collects "
                         "real transactions for ADDRESS over --blocks, "
                         "fingerprints per-function behaviour, mines candidate "
                         "boundaries (authorization, conservation, accounting, "
                         "replay protection, ...), generates and replays "
                         "counterfactual mutations on an isolated local Anvil "
                         "fork (never broadcast), checks for a violation, "
                         "minimises it, then validates with an independent "
                         "Skeptic sweep + blinded reproduction before allowing "
                         "CONFIRMED. Needs --blocks and a Foundry toolchain "
                         "(native forge/anvil, or WSL). Uses --rpc-url / "
                         "RPC_URL exactly like the classic pipeline's liveness "
                         "check.")
    ap.add_argument("--blocks", metavar="LO:HI",
                    help="block range for --twin, e.g. 21000000:21005000")
    args = ap.parse_args()

    if args.twin:
        return _run_twin(args)

    if args.nextgen:
        return _run_nextgen(args)

    # --from-json: report generation over a completed scan, no repo walk.
    if args.from_json:
        rep = json.loads(Path(args.from_json).read_text(encoding="utf-8"))
        print_report(rep)
        if args.generate_reports:
            _generate_reports(rep, args)
        return 0

    if not args.repo:
        ap.error("--repo is required (or use --from-json to read a finished scan)")

    repo = args.repo
    if repo.startswith(CLONE_SCHEMES):
        repo = clone(repo, Path(tempfile.gettempdir()) / "chainwatch-clones")
    repo = Path(repo).resolve()
    if not (repo / ".git").exists():
        sys.exit(f"{repo} is not a git working tree")

    opts = ScanOptions(
        repo=repo,
        limit=args.limit,
        root_dir=args.root,
        address=args.address,
        rpc_url=args.rpc_url,
        check_head_survival=not args.no_head_check,
        rules=[r.strip() for r in args.rules.split(",") if r.strip()] or None,
        explicit_pairs=[tuple(x.split(":", 1))
                        for x in args.pairs.split(",")
                        if ":" in x] or None,
        check_exposure=args.check_exposure,
        check_exploit_proof=args.check_exploit_proof,
    )
    rep = scan(opts, on_event=None if args.quiet else _print_progress)
    print_report(rep)
    if args.json:
        Path(args.json).write_text(json.dumps(rep, indent=2), encoding="utf-8")
        print(f"\nfull report written to {args.json}")
    if args.generate_reports:
        _generate_reports(rep, args)
    return 0


def _run_nextgen(args) -> int:
    """`--nextgen FILE:CONTRACT:FUNCTION` over one --pairs prev:cur pair.

    Additive and flag-gated: this touches nothing in the classic pipeline. See
    NEXTGEN.md.
    """
    if not args.repo:
        sys.exit("--nextgen needs --repo")
    parts = args.nextgen.split(":")
    if len(parts) < 3:
        sys.exit("--nextgen wants FILE:CONTRACT:FUNCTION "
                 "(e.g. contracts/NFT.sol:NFT:init)")
    file, contract, function = parts[0], parts[1], ":".join(parts[2:])
    pairs = [tuple(x.split(":", 1)) for x in args.pairs.split(",") if ":" in x]
    if len(pairs) != 1:
        sys.exit("--nextgen wants exactly one --pairs prev:cur pair")
    parent, commit = pairs[0]

    repo = args.repo
    if repo.startswith(CLONE_SCHEMES):
        repo = clone(repo, Path(tempfile.gettempdir()) / "chainwatch-clones")
    repo = str(Path(repo).resolve())

    rpc = args.rpc_url
    if rpc is None and args.address:
        try:
            from dotenv import load_dotenv
            load_dotenv()
        except Exception:  # noqa: BLE001
            pass
        import os
        rpc = os.environ.get("RPC_URL")

    from src.nextgen import pipeline as PL
    print(f"nextgen pipeline: {contract}.{function}  "
          f"{parent[:12]}..{commit[:12]}"
          + (f"  @ {args.address}" if args.address else "  (repo-only)"))
    res = PL.run_from_repo(
        repo=repo, parent=parent, commit=commit, file=file,
        contract=contract, function=function, rule_id=args.nextgen_rule,
        address=args.address or "", rpc_url=rpc)

    print("\n" + res.report_text)
    print(f"\nproof score: {res.proof_score.total}  "
          f"(permits_confirmed={res.proof_score.permits_confirmed})")
    notes = res.sub_reports.get("repo_notes") or {}
    if notes:
        print("\nrun notes:")
        for k, v in notes.items():
            print(f"  {k}: {v}")
    errs = {k: v for k, v in res.sub_reports.items() if k.endswith("_error")}
    if errs:
        print("\nnon-fatal step errors:")
        for k, v in errs.items():
            print(f"  {k}: {v}")
    if args.json:
        Path(args.json).write_text(json.dumps(res.as_dict(), indent=2, default=str),
                                   encoding="utf-8")
        print(f"\nfull result written to {args.json}")
    return 0 if res.verdict in ("CONFIRMED", "UNKNOWN") else 1


def _run_twin(args) -> int:
    """`--twin ADDRESS --blocks LO:HI`. Trace-driven; needs no --repo. See
    NEXTGEN.md - Counterfactual Protocol Twin."""
    if not args.blocks or ":" not in args.blocks:
        sys.exit("--twin needs --blocks LO:HI (e.g. --blocks 21000000:21005000)")
    lo_s, hi_s = args.blocks.split(":", 1)
    try:
        lo, hi = int(lo_s), int(hi_s)
    except ValueError:
        sys.exit(f"--blocks wants two integers, got {args.blocks!r}")
    if hi <= lo:
        sys.exit(f"--blocks: HI ({hi}) must be greater than LO ({lo})")

    rpc = args.rpc_url
    if rpc is None:
        try:
            from dotenv import load_dotenv
            load_dotenv()
        except Exception:  # noqa: BLE001
            pass
        import os
        rpc = os.environ.get("RPC_URL")
    if not rpc:
        sys.exit("--twin needs an RPC endpoint: pass --rpc-url or set RPC_URL in .env")

    from src.nextgen.twin.twin import CounterfactualTwin

    def _progress(msg: str) -> None:
        if not args.quiet:
            print(f"  ... {msg}")

    print(f"counterfactual twin: {args.twin}  blocks [{lo}, {hi}]")
    tw = CounterfactualTwin(args.twin, rpc, lo, hi, on_event=_progress)
    res = tw.run()
    print("\n" + res.render_text())
    if args.json:
        Path(args.json).write_text(json.dumps(res.as_dict(), indent=2, default=str),
                                   encoding="utf-8")
        print(f"\nfull result written to {args.json}")
    return 0 if res.verdict in ("CONFIRMED", "UNKNOWN") else 1


def _generate_reports(rep: dict, args) -> None:
    """Capability 12 over a finished scan. Same gate as everywhere else."""
    from agent import FindingStore
    from agent import runner as R

    findings = rep.get("findings") or []
    if not findings:
        print("\nNo findings to report on.")
        return
    if not R.api_key_present():
        print("\nGEMINI_API_KEY is not configured, so no dossiers were drafted.")
        print("The scan above is complete and unaffected: the deterministic engine")
        print("never calls a model. Set GEMINI_API_KEY in .env to enable this step.")
        return

    store = FindingStore(rep)
    out_dir = Path(args.reports_dir)
    rpm = args.rpm or R.DEFAULT_RPM
    print(f"\n{'=' * 78}\nGENERATING DOSSIERS  ({len(findings)} finding(s), "
          f"model {R.DEFAULT_MODEL}, {rpm} model-requests/min budget)\n{'=' * 78}")

    def on_event(ev):
        kind = ev.get("kind")
        if kind == "tool":
            print(f"    tool: {ev['tool']}")
        elif kind == "throttle":
            print(f"    pacing {ev['seconds']}s to stay inside the rate limit…")
        elif kind == "retry":
            print(f"    {ev['reason']}; the server asked for {ev['seconds']}s, waiting…")
        elif kind == "error":
            print(f"    ERROR: {ev['message']}")

    results = R.generate_all_sync(store, out_dir, rpm=rpm, on_event=on_event)
    print()
    for res in results:
        f = store.get(res["finding_id"]) or {}
        who = (f"{f.get('contract')}.{f['function']}" if f.get("function")
               else str(f.get("contract")))
        if res["status"] == "success":
            print(f"  OK       {who:<34} verified, {res['path']}")
        else:
            print(f"  FAILED   {who:<34} {res.get('error_message', '')[:80]}")
            for v in res.get("violations", [])[:5]:
                print(f"             rejected [{v['kind']}] {v['span']!r}")
    ok = sum(1 for r in results if r["status"] == "success")
    print(f"\n  {ok}/{len(results)} dossiers written and re-verified against the "
          f"finding record.")


if __name__ == "__main__":
    sys.exit(main())
