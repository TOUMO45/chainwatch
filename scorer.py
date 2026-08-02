#!/usr/bin/env python3
"""Chainwatch scorer harness.

Scores every registered detection rule against the frozen fixture set in
fixtures/manifest.json and reports per-rule precision and recall.

Ship gates (RULES.md, per-rule calibration requirement):
  - precision = 1.00 on the fixture set (zero false positives)
  - recall   >= 0.70

Exit code is non-zero if any registered rule misses either gate.

--empty-detector runs the harness with every rule disabled. Once rules are
registered, this run MUST fail (0 detections -> recall 0.00), proving the
scorer is capable of failing. With zero rules registered it reports 0/N
detections and passes vacuously.
"""

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
FIXTURES = ROOT / "fixtures"
MANIFEST = FIXTURES / "manifest.json"

# Solidity dependency sets a fixture directory may be built against. This is
# build configuration (which remapping solc gets), never detection logic.
REMAP_SETS = {
    "oz4": [
        "@openzeppelin/contracts/=node_modules/@openzeppelin/contracts/",
        "@openzeppelin/contracts-upgradeable/=node_modules/@openzeppelin/contracts-upgradeable/",
    ],
    "oz5": [
        "@openzeppelin/contracts/=realworld-test/oz5/node_modules/@openzeppelin/contracts/",
        "@openzeppelin/contracts-upgradeable/=realworld-test/oz5/node_modules/@openzeppelin/contracts-upgradeable/",
    ],
}

PRECISION_GATE = 1.00
RECALL_GATE = 0.70

# Registry: rule_id -> callable(before_path: Path, after_path: Path, meta: dict) -> bool
# The callable returns True iff the rule FIRES (claims a regression) on the case.
# Rules register themselves via src/rules/register_all().
REGISTERED_RULES: dict[str, object] = {}

from src.rules import register_all  # noqa: E402

register_all(REGISTERED_RULES)


def load_cases(fixtures_dir: Path = FIXTURES) -> list[dict]:
    with open(fixtures_dir / "manifest.json", encoding="utf-8") as fh:
        cases = json.load(fh)
    for case in cases:
        case_dir = fixtures_dir / case["path"]
        before = case_dir / "before.sol"
        after = case_dir / "after.sol"
        if not before.is_file() or not after.is_file():
            sys.exit(f"FATAL: fixture files missing for case {case['id']} in {case_dir}")
        case["_before"] = before
        case["_after"] = after
    return cases


def _apply_build_config(remaps_key: str, solc: str | None) -> None:
    """Point the analysis at one OpenZeppelin tree / solc version. Build config
    only - which imports resolve and which compiler runs, never detection logic.
    Allows a single fixture directory to mix OZ 4 and OZ 5 cases, each declaring
    its own `remaps`/`solc` in the manifest."""
    import os

    import src.rules._shared as _shared
    import src.rules._storage as _storage

    _shared.REMAPS = list(REMAP_SETS[remaps_key])
    _storage.REMAPPINGS = list(REMAP_SETS[remaps_key])
    if solc:
        os.environ["SOLC_VERSION"] = solc


def score(rules: dict, cases: list[dict], default_remaps: str = "oz4") -> tuple[dict, int]:
    """Run every rule against every case. Returns (per-rule stats, total detections)."""
    stats = {
        rule_id: {"tp": 0, "fp": 0, "fn": 0, "unsupported": 0, "detections": []}
        for rule_id in rules
    }
    total_detections = 0
    for case in cases:
        # Per-case build config overrides the run default, so one directory can
        # hold both OZ 4 and OZ 5 cases (e.g. fixtures-ext).
        if case.get("remaps") or case.get("solc"):
            _apply_build_config(case.get("remaps", default_remaps), case.get("solc"))
        is_positive = case["label"] == "positive"
        for rule_id, rule_fn in rules.items():
            # A rule id may be a whole rule ("3") or a sub-rule ("3a"); a case
            # is an expected positive for the rule that owns it.
            owns_case = rule_id in (str(case["rule"]), str(case.get("sub_rule")))
            expected_fire = owns_case and is_positive
            # A case may be flagged in the manifest as covering a rule mode that
            # is not built yet. It is still run and still shown, but a miss is
            # reported as KNOWN-UNSUPPORTED rather than counted as a failure.
            unsupported = owns_case and bool(case.get("known_unsupported"))
            # A case may DECLARE, via manifest `also_fires`, that a NON-owning
            # rule is EXPECTED to fire on it - a legitimate cross-rule detection
            # (e.g. N1-05 is Rule 1's negative but the same diff as P3a-01, so
            # Rule 3a rightly fires). Such a declared fire is counted as neither
            # TP nor FP. A fire by any rule that is neither the owner nor listed
            # in also_fires is STILL a false positive - this exception narrows
            # nothing else.
            declared_cross = not owns_case and rule_id in {
                str(r) for r in case.get("also_fires", [])
            }
            fired = bool(rule_fn(case["_before"], case["_after"], case))
            if fired:
                total_detections += 1
                stats[rule_id]["detections"].append(case["id"])
            if expected_fire and unsupported:
                if fired:
                    stats[rule_id]["tp"] += 1
                else:
                    stats[rule_id]["unsupported"] += 1
                    print(
                        f"  [{rule_id}] {case['id']:<11} expected=FIRE  got=quiet "
                        f"KNOWN-UNSUPPORTED ({case['known_unsupported']})"
                    )
                    continue
            elif expected_fire:
                if fired:
                    stats[rule_id]["tp"] += 1
                else:
                    stats[rule_id]["fn"] += 1
            elif fired and declared_cross:
                # Declared, expected cross-rule detection (manifest `also_fires`):
                # counted as neither TP nor FP for this rule.
                pass
            elif fired:
                # Fired on a negative case, or on a case belonging to another
                # rule with no also_fires declaration: false positive.
                stats[rule_id]["fp"] += 1
            if fired and declared_cross:
                ok, note = True, "  EXPECTED (also_fires cross-rule)"
            else:
                ok, note = fired == expected_fire, ""
            print(
                f"  [{rule_id}] {case['id']:<7} expected={'FIRE' if expected_fire else 'quiet':<5} "
                f"got={'FIRE' if fired else 'quiet':<5} {'OK' if ok else '** WRONG **'}{note}"
            )
    return stats, total_detections


def main() -> int:
    parser = argparse.ArgumentParser(description="Chainwatch fixture scorer")
    parser.add_argument(
        "--empty-detector",
        action="store_true",
        help="disable every rule; control run proving the scorer can fail",
    )
    parser.add_argument(
        "--all", action="store_true", help="score all registered rules (default)"
    )
    parser.add_argument(
        "--fixtures", default="fixtures",
        help="fixture directory to score (default: fixtures, the frozen OZ 4 set)",
    )
    parser.add_argument(
        "--remaps", choices=sorted(REMAP_SETS), default="oz4",
        help="solc remapping set the fixtures are built against (build config only)",
    )
    args = parser.parse_args()

    if args.remaps != "oz4":
        # Build configuration: which OpenZeppelin tree solc resolves imports
        # against. Detection logic is unaffected.
        import src.rules._shared as _shared
        import src.rules._storage as _storage

        _shared.REMAPS = list(REMAP_SETS[args.remaps])
        _storage.REMAPPINGS = list(REMAP_SETS[args.remaps])

    fixtures_dir = (ROOT / args.fixtures).resolve()
    cases = load_cases(fixtures_dir)
    n_pos = sum(1 for c in cases if c["label"] == "positive")
    n_neg = len(cases) - n_pos

    if args.empty_detector:
        # Every registered rule is replaced by a rule that never fires.
        rules = {rule_id: (lambda *_: False) for rule_id in REGISTERED_RULES}
        mode = "--empty-detector (all rules disabled)"
    else:
        rules = dict(REGISTERED_RULES)
        mode = "normal"

    print("Chainwatch scorer")
    print(f"  mode            : {mode}")
    print(f"  fixtures        : {args.fixtures}  (remaps: {args.remaps})")
    print(f"  cases loaded    : {len(cases)} ({n_pos} positive, {n_neg} negative)")
    print(f"  rules registered: {len(REGISTERED_RULES)}")
    print()
    if rules:
        print("Per-case verdicts:")
    stats, total_detections = score(rules, cases, default_remaps=args.remaps)
    print()
    print(f"  detections      : {total_detections}/{len(cases)}")
    print()

    if not rules:
        print("No rules registered - nothing to score.")
        print("RESULT: PASS (vacuous: no shipped rule exists to violate a gate)")
        return 0

    failed = False
    print(f"{'rule':<6} {'TP':>3} {'FP':>3} {'FN':>3} {'N/S':>4} {'precision':>10} {'recall':>8}  gates")
    for rule_id, s in sorted(stats.items()):
        tp, fp, fn, ns = s["tp"], s["fp"], s["fn"], s["unsupported"]
        precision = tp / (tp + fp) if (tp + fp) else 0.0
        recall = tp / (tp + fn) if (tp + fn) else 0.0
        if (tp + fn) == 0 and fp == 0:
            # No scoreable positive for this rule in this set (e.g. its only
            # positive is flagged known_unsupported). Not a pass, not a failure.
            verdict = "N/A" if ns else "no-cases"
        else:
            p_ok = (tp + fp) > 0 and precision >= PRECISION_GATE
            r_ok = recall >= RECALL_GATE
            verdict = "OK" if (p_ok and r_ok) else "FAIL"
            if verdict == "FAIL":
                failed = True
        print(
            f"{rule_id:<6} {tp:>3} {fp:>3} {fn:>3} {ns:>4} {precision:>10.2f} {recall:>8.2f}  {verdict}"
        )
        if s["fp"]:
            fp_cases = [c for c in s["detections"]]
            print(f"       fired on: {', '.join(fp_cases)}")

    print()
    if failed:
        print("RESULT: FAIL (a rule is below precision 1.00 or recall 0.70)")
        return 1
    print("RESULT: PASS")
    return 0


if __name__ == "__main__":
    sys.exit(main())
