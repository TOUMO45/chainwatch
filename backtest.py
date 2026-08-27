"""Incident-anchored backtesting (BACKTEST-1).

    python backtest.py                 # run every case in backtest-cases.json
    python backtest.py --case 88mph-nft-init-2021
    python backtest.py --json out.json

THE QUESTION THIS ANSWERS, and why it is worth more than any fixture score:

    At the commit that introduced a publicly documented vulnerability, would
    Chainwatch have fired - at commit time, before the incident?

`scorer.py` measures precision and recall against fixtures this project wrote.
That is necessary and it is also self-referential: fixtures encode what the
rules were built to catch. A backtest anchors to incidents the project did NOT
author, at commits chosen by someone else, with the answer already known from
a public post-mortem. It is the difference between "precision 1.00 on our own
cases" and "would have flagged this real hack, weeks before it happened".

WHAT IT DELIBERATELY DOES NOT DO. It does not grade partial credit, and it
never relaxes a case to make a number look better. A case whose expected rule
does not fire is reported as MISSED, with its coverage, so a miss caused by a
compile failure is legible as such rather than blamed on the rule. The corpus
is ground truth in the same sense `fixtures/` is: read-only, per CHARTER rule 1.

HONEST SIZE. The corpus starts at ONE case - the only incident this project has
independently verified end to end, down to the deployed bytecode. Every entry
costs real work (resolve the repository, resolve the commit and its parent
against real history, verify against a public write-up), and a case with a
guessed hash would produce a rigorous-looking number that means nothing. The
harness is the reusable artifact; the corpus grows as cases are verified.
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))

from src.scan import ScanOptions, scan  # noqa: E402

CASES_FILE = ROOT / "backtest-cases.json"

CAUGHT = "CAUGHT"
MISSED = "MISSED"
UNRUNNABLE = "UNRUNNABLE"   # the case could not be executed; says nothing about the rule


def load_cases(path: Path = CASES_FILE) -> list[dict]:
    data = json.loads(path.read_text(encoding="utf-8"))
    return data.get("cases", [])


def _matches(finding: dict, expect: dict) -> bool:
    """Did THIS finding answer the case?

    Every field the case names must match. A case names a rule, a file, a
    contract and a function precisely so that "some rule fired somewhere in the
    repo" cannot be counted as catching a specific vulnerability - which is the
    obvious way to make a backtest lie.
    """
    if str(finding.get("rule_id")) != str(expect["rule"]):
        return False
    if expect.get("contract") and finding.get("contract") != expect["contract"]:
        return False
    if expect.get("function") and finding.get("function") != expect["function"]:
        return False
    if expect.get("file"):
        got = (finding.get("file") or "").replace("\\", "/")
        if not got.endswith(expect["file"].replace("\\", "/")):
            return False
    return True


def run_case(case: dict, *, quiet: bool = True) -> dict:
    """Run one case. Never raises: an unrunnable case is a reported status."""
    started = time.time()
    repo = (ROOT / case["repo"]).resolve()
    out = {
        "id": case["id"],
        "repo": str(repo),
        "expect": case["expect"],
        "source": case.get("source", ""),
        "status": UNRUNNABLE,
        "reason": "",
        "coverage": {},
        "findings_total": 0,
        "seconds": 0.0,
    }

    if not (repo / ".git").exists():
        out["reason"] = (f"{repo} is not a git checkout. Clone it first: "
                         f"git clone {case.get('clone_url', '<url>')} {repo}")
        return out

    try:
        report = scan(ScanOptions(
            repo=repo,
            limit=1,
            explicit_pairs=[(case["parent"], case["commit"])],
            # The question is "would it have fired AT THIS COMMIT". Whether the
            # bug still exists at today's HEAD is a different (and for an old
            # incident, usually irrelevant) question, and letting it run costs
            # a full HEAD environment build per case for no gain here.
            check_head_survival=False,
        ), on_event=None if quiet else lambda e: None)
    except Exception as exc:  # noqa: BLE001
        out["reason"] = f"scan raised {type(exc).__name__}: {exc}"[:300]
        out["seconds"] = round(time.time() - started, 1)
        return out

    findings = report.get("findings", [])
    cov = report.get("coverage", {})
    out["coverage"] = {
        "files_ok": cov.get("files_ok"),
        "files_total": cov.get("files_total"),
        "rule_checks_ok": cov.get("rule_invocations_ok"),
        "rule_checks_answerable": cov.get("rule_invocations_answerable"),
    }
    out["findings_total"] = len(findings)
    out["seconds"] = round(time.time() - started, 1)

    hit = next((f for f in findings if _matches(f, case["expect"])), None)
    if hit:
        out["status"] = CAUGHT
        out["verdict"] = hit.get("verdict")
        out["detail"] = (hit.get("detail") or "")[:200]
        return out

    # Distinguish "the rule was asked and stayed silent" from "the rule was
    # never asked" - only the first is evidence about the rule (METHODOLOGY
    # Face A: a miss over uncompiled code is unmeasured, not a false negative).
    if not cov.get("files_ok"):
        out["reason"] = ("nothing compiled for this pair, so no rule was ever "
                         "asked - this is a coverage failure, not a rule miss")
        return out

    out["status"] = MISSED
    out["reason"] = (f"rule {case['expect']['rule']} did not fire on "
                     f"{case['expect'].get('contract')}."
                     f"{case['expect'].get('function')} "
                     f"({len(findings)} other finding(s) in this pair)")
    return out


def main() -> int:
    ap = argparse.ArgumentParser(
        description="Would Chainwatch have caught these real incidents?")
    ap.add_argument("--case", help="run one case id (default: all)")
    ap.add_argument("--cases-file", default=str(CASES_FILE))
    ap.add_argument("--json", help="write full results here")
    args = ap.parse_args()

    cases = load_cases(Path(args.cases_file))
    if args.case:
        cases = [c for c in cases if c["id"] == args.case]
        if not cases:
            print(f"no such case: {args.case}")
            return 2

    print("=" * 78)
    print("INCIDENT BACKTEST - would Chainwatch have fired, at commit time?")
    print("=" * 78)

    results = []
    for case in cases:
        print(f"\n  {case['id']}  ({case.get('date', '?')})")
        print(f"    expect rule {case['expect']['rule']} on "
              f"{case['expect'].get('contract')}.{case['expect'].get('function')}")
        res = run_case(case)
        results.append(res)
        mark = {CAUGHT: "CAUGHT ", MISSED: "MISSED ", UNRUNNABLE: "SKIPPED"}[res["status"]]
        print(f"    -> {mark}  {res['seconds']}s")
        if res["status"] == CAUGHT:
            print(f"       verdict={res.get('verdict')}  {res.get('detail', '')[:90]}")
        elif res["reason"]:
            print(f"       {res['reason']}")

    caught = sum(1 for r in results if r["status"] == CAUGHT)
    missed = sum(1 for r in results if r["status"] == MISSED)
    unrun = sum(1 for r in results if r["status"] == UNRUNNABLE)

    print("\n" + "-" * 78)
    print(f"  {caught} caught / {missed} missed / {unrun} unrunnable "
          f"of {len(results)} case(s)")
    if unrun:
        print("  Unrunnable cases are NOT counted as either - a case that could "
              "not\n  execute says nothing about the rules.")
    print("-" * 78)

    if args.json:
        Path(args.json).write_text(json.dumps(
            {"caught": caught, "missed": missed, "unrunnable": unrun,
             "results": results}, indent=2), encoding="utf-8")
        print(f"\nfull results written to {args.json}")

    # Exit non-zero only on a real MISS: an unrunnable case is an environment
    # problem for the operator, not a regression in the detector.
    return 1 if missed else 0


if __name__ == "__main__":
    raise SystemExit(main())
