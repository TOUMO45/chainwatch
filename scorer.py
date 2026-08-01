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

PRECISION_GATE = 1.00
RECALL_GATE = 0.70

# Registry: rule_id -> callable(before_path: Path, after_path: Path, meta: dict) -> bool
# The callable returns True iff the rule FIRES (claims a regression) on the case.
# Rules register themselves here via src/rules/. ZERO rules are registered yet.
REGISTERED_RULES: dict[str, object] = {}


def load_cases() -> list[dict]:
    with open(MANIFEST, encoding="utf-8") as fh:
        cases = json.load(fh)
    for case in cases:
        case_dir = FIXTURES / case["path"]
        before = case_dir / "before.sol"
        after = case_dir / "after.sol"
        if not before.is_file() or not after.is_file():
            sys.exit(f"FATAL: fixture files missing for case {case['id']} in {case_dir}")
        case["_before"] = before
        case["_after"] = after
    return cases


def score(rules: dict, cases: list[dict]) -> tuple[dict, int]:
    """Run every rule against every case. Returns (per-rule stats, total detections)."""
    stats = {
        rule_id: {"tp": 0, "fp": 0, "fn": 0, "detections": []} for rule_id in rules
    }
    total_detections = 0
    for case in cases:
        expected_rule = str(case["rule"])
        is_positive = case["label"] == "positive"
        for rule_id, rule_fn in rules.items():
            fired = bool(rule_fn(case["_before"], case["_after"], case))
            if fired:
                total_detections += 1
                stats[rule_id]["detections"].append(case["id"])
            if rule_id == expected_rule and is_positive:
                if fired:
                    stats[rule_id]["tp"] += 1
                else:
                    stats[rule_id]["fn"] += 1
            elif fired:
                # Fired on a negative case, or on a case belonging to another
                # rule: false positive either way.
                stats[rule_id]["fp"] += 1
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
    args = parser.parse_args()

    cases = load_cases()
    n_pos = sum(1 for c in cases if c["label"] == "positive")
    n_neg = len(cases) - n_pos

    if args.empty_detector:
        # Every registered rule is replaced by a rule that never fires.
        rules = {rule_id: (lambda *_: False) for rule_id in REGISTERED_RULES}
        mode = "--empty-detector (all rules disabled)"
    else:
        rules = dict(REGISTERED_RULES)
        mode = "normal"

    stats, total_detections = score(rules, cases)

    print("Chainwatch scorer")
    print(f"  mode            : {mode}")
    print(f"  cases loaded    : {len(cases)} ({n_pos} positive, {n_neg} negative)")
    print(f"  rules registered: {len(REGISTERED_RULES)}")
    print(f"  detections      : {total_detections}/{len(cases)}")
    print()

    if not rules:
        print("No rules registered - nothing to score.")
        print("RESULT: PASS (vacuous: no shipped rule exists to violate a gate)")
        return 0

    failed = False
    print(f"{'rule':<6} {'TP':>3} {'FP':>3} {'FN':>3} {'precision':>10} {'recall':>8}  gates")
    for rule_id, s in sorted(stats.items()):
        tp, fp, fn = s["tp"], s["fp"], s["fn"]
        precision = tp / (tp + fp) if (tp + fp) else 0.0
        recall = tp / (tp + fn) if (tp + fn) else 0.0
        p_ok = (tp + fp) > 0 and precision >= PRECISION_GATE
        r_ok = recall >= RECALL_GATE
        verdict = "OK" if (p_ok and r_ok) else "FAIL"
        if verdict == "FAIL":
            failed = True
        print(
            f"{rule_id:<6} {tp:>3} {fp:>3} {fn:>3} {precision:>10.2f} {recall:>8.2f}  {verdict}"
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
