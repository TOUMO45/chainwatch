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
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))

from src.scan import RULE_ORDER, RULE_TITLES, ScanOptions, scan  # noqa: E402
from src import verdict as V  # noqa: E402
from src import liveness as L  # noqa: E402


# Anything git can clone from. `file://` is included so the clone path itself
# is testable without a network round trip.
CLONE_SCHEMES = ("http://", "https://", "git@", "ssh://", "git://", "file://")


def clone(url: str, dest: Path) -> Path:
    """Full-history read-only clone. Depth is NOT truncated: trajectory is the
    product, and a shallow clone has no trajectory."""
    dest.mkdir(parents=True, exist_ok=True)
    name = url.rstrip("/").split("/")[-1].removesuffix(".git")
    target = dest / name
    if (target / ".git").exists():
        return target
    print(f"cloning {url} -> {target} (full history, read-only)")
    proc = subprocess.run(["git", "clone", url, str(target)],
                          capture_output=True, text=True)
    if proc.returncode != 0:
        sys.exit(f"clone failed:\n{proc.stderr[:600]}")
    return target


def _print_progress(ev: dict) -> None:
    kind = ev.get("kind")
    if kind == "pair":
        print(f"  [{ev['index']}/{ev['total']}] {ev['prev']}..{ev['cur']}  "
              f"{ev.get('subject','')[:60]}")
    elif kind == "skip":
        print(f"      SKIPPED: {ev.get('reason')}")
    elif kind == "finding":
        print(f"      {ev['verdict']:<9} rule {ev['rule']:<3} {ev['file']}"
              f"::{ev.get('contract')}.{ev.get('function')}")
    elif kind == "warn":
        print(f"  ! {ev.get('message')}")
    elif kind == "liveness":
        print(f"  checking on-chain liveness for {ev.get('address')}")


def print_report(rep: dict) -> None:
    s, cov = rep["summary"], rep["coverage"]
    print()
    print("=" * 78)
    print(f"CHAINWATCH REPORT   {rep['repo']}")
    print(f"HEAD {rep.get('head')}")
    print("=" * 78)

    # Coverage FIRST. A finding count without it is not interpretable.
    print("\nCOVERAGE (read this before the findings)")
    print(f"  commit pairs analyzed : {cov['pairs_analyzed']}/{cov['pairs_total']}"
          f"  ({cov['pairs_analyzed_pct']}%)")
    print(f"  file comparisons ok   : {cov['files_ok']}/{cov['files_total']}"
          f"  ({cov['files_ok_pct']}%)")
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
    if cov["pairs_analyzed"] < cov["pairs_total"]:
        print("  NOTE: this scan did not see the whole history. A quiet result "
              "over unanalyzed\n        commits means UNMEASURED, not SAFE.")

    print(f"\nSUMMARY   {s['findings']} finding(s): "
          f"{s['confirmed']} CONFIRMED, {s['candidates']} CANDIDATE "
          f"in {s['seconds']}s")
    if rep["by_rule"]:
        for rid in RULE_ORDER:
            if rid in rep["by_rule"]:
                print(f"    rule {rid:<3} {RULE_TITLES[rid]:<42} {rep['by_rule'][rid]}")

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
        if f["downgrade_reasons"]:
            print("\n    WHY NOT CONFIRMED")
            for r in f["downgrade_reasons"]:
                print(f"      - {r}")


def main() -> int:
    ap = argparse.ArgumentParser(description="Chainwatch trajectory scanner")
    ap.add_argument("--repo", required=True, help="local path or clone URL")
    ap.add_argument("--address", help="deployed address for the liveness gate")
    ap.add_argument("--rpc-url", help="override RPC_URL from .env")
    ap.add_argument("--limit", type=int, default=50,
                    help="how many .sol-touching commits to walk (default 50)")
    ap.add_argument("--root", default="", help="restrict to a subdirectory, e.g. contracts")
    ap.add_argument("--rules", default="",
                    help=f"comma-separated subset of {','.join(RULE_ORDER)}")
    ap.add_argument("--no-head-check", action="store_true",
                    help="skip the survives-to-HEAD re-run (faster, weaker evidence)")
    ap.add_argument("--json", help="write the full report here")
    ap.add_argument("--quiet", action="store_true", help="suppress progress lines")
    args = ap.parse_args()

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
    )
    rep = scan(opts, on_event=None if args.quiet else _print_progress)
    print_report(rep)
    if args.json:
        Path(args.json).write_text(json.dumps(rep, indent=2), encoding="utf-8")
        print(f"\nfull report written to {args.json}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
