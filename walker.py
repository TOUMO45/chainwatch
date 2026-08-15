#!/usr/bin/env python3
"""Chainwatch trajectory walker.

Runs every registered detection rule against a caller-specified list of
(prev, cur) commit pairs in a target git repository, using src/history.py's
env-reconstruction primitives (per-commit node/submodule install with
lifecycle scripts disabled, cached on the resolved dependency set), and
emits per-pair JSON findings.

The scorer's counterpart in trajectory mode: scorer.py runs the rules
against the frozen self-contained fixture set to prove precision/recall
gates; walker.py runs them against real historical commit pairs to check
whether a rule fires (or stays quiet) on a specific measured case
(e.g., PHASE 5 confirmation of a Reserve FP after a rule-side fix).

Function-level attribution: the rules currently return only a boolean
verdict (per rule module's `run` contract); which function inside the
changed file triggered a fire is not part of the return value, so the
`function` field in the emitted JSON is null. Per-pair granularity is
(rule_id, fired?, changed_file). To resolve a fire to a function name
today, hand-inspect the changed file's diff at the reported commit
pair. Rule-level instrumentation to return richer findings is a
separate change; not made here to avoid breaking scorer.py's contract.

CHARTER rule 5 (read-only on the target): the walker only READS the
target repo's history via `git worktree`. Nothing is committed, pushed,
or written to a tracked path inside the target. Dependency installs run
with --ignore-scripts (per src/history.py's install()).

Usage:
    python walker.py --repo <path> --pairs <prev1>:<cur1>,<prev2>:<cur2> \
                     [--out findings.json] [--worktrees <dir>] \
                     [--cache <dir>]

Pairs are prev:cur; multiple pairs comma-separated. The walker reuses
two Worktree slots ("prev" and "cur") across the pair list so the
installed dependency tree survives across checkouts (cache is keyed by
resolved dependency set, not by commit).
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import traceback
from pathlib import Path

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))

from src import history as H
from src.rules import register_all
import src.rules._shared as _shared
import src.rules._storage as _storage

REGISTERED: dict[str, object] = {}
register_all(REGISTERED)


def _parse_pairs(spec: str) -> list[tuple[str, str]]:
    """'a:b,c:d' -> [('a','b'),('c','d')]. Non-empty, colon-separated only."""
    pairs: list[tuple[str, str]] = []
    for chunk in spec.split(","):
        chunk = chunk.strip()
        if not chunk:
            continue
        if ":" not in chunk:
            raise ValueError(f"pair {chunk!r} missing ':' separator")
        prev, cur = chunk.split(":", 1)
        prev, cur = prev.strip(), cur.strip()
        if not prev or not cur:
            raise ValueError(f"pair {chunk!r} has empty side")
        pairs.append((prev, cur))
    if not pairs:
        raise ValueError("--pairs is empty")
    return pairs


def _run_rules_on_file(
    before_path: Path,
    after_path: Path,
    rel_path: str,
    all_changed: list[str],
) -> list[dict]:
    """Invoke every registered rule against one (before, after) file pair.

    Returns one record per rule: {rule_id, fired, candidate, error, file, function}.
    `function` is null (see module docstring). Exceptions from a rule are
    caught per-rule so one broken rule does not silence the rest.
    """
    case_meta = {
        "source_path": rel_path,
        "changed_files": list(all_changed),
    }
    findings: list[dict] = []
    for rule_id, run_fn in REGISTERED.items():
        rec: dict = {
            "rule_id": rule_id,
            "file": rel_path,
            "function": None,
            "fired": False,
            "candidate": False,
            "error": None,
        }
        try:
            raw = run_fn(before_path, after_path, case_meta)
            rec["candidate"] = raw == "candidate"
            rec["fired"] = bool(raw) and not rec["candidate"]
        except Exception as exc:  # noqa: BLE001 - report, do not crash the pair
            rec["error"] = f"{type(exc).__name__}: {exc}"[:400]
        findings.append(rec)
    return findings


def _apply_build_config(spec: H.EnvSpec) -> None:
    """Point _shared.REMAPS / _storage.REMAPPINGS at this checkout's derived
    remaps and set SOLC_VERSION to the pinned compiler, mirroring scorer.py's
    per-case _apply_build_config for a live checkout.

    `absolute=True` because rule-side Slither invocations may run with any cwd
    (the two worktrees are two different roots); an absolute remap resolves
    the same on both sides.
    """
    remaps = H.derive_remaps(spec.root, absolute=True)
    _shared.REMAPS = list(remaps)
    _storage.REMAPPINGS = list(remaps)
    if spec.solc_pin:
        os.environ["SOLC_VERSION"] = spec.solc_pin


def walk(
    repo: Path,
    pairs: list[tuple[str, str]],
    worktrees_root: Path,
    cache_root: Path,
) -> list[dict]:
    """Return one report dict per pair.

    Each report:
      {"prev", "cur",
       "env": {"prev": {ok, cause, detail, solc_pin, node_manager}, "cur": {...}},
       "changed": {"modified": [...], "added": [...], "deleted": [...]},
       "findings": [<per (file, rule) record>...]}
    """
    worktrees_root.mkdir(parents=True, exist_ok=True)
    prev_wt = H.Worktree(repo, worktrees_root / "prev")
    cur_wt = H.Worktree(repo, worktrees_root / "cur")

    reports: list[dict] = []
    for prev, cur in pairs:
        rep: dict = {"prev": prev, "cur": cur, "env": {}, "changed": {}, "findings": []}
        try:
            prev_wt.checkout(prev)
            cur_wt.checkout(cur)
        except Exception as exc:  # noqa: BLE001
            rep["error"] = f"checkout failed: {type(exc).__name__}: {exc}"[:400]
            reports.append(rep)
            continue

        # MANDATORY after every checkout. _shared.parse and
        # _storage.storage_layouts memoize on absolute path alone, which is
        # sound only while a path's content is stable in-process. This walker
        # deliberately reuses two worktree paths across every pair (that reuse
        # is what makes the dependency-install cache pay off), so the same
        # path holds different commits' content over the run. Without this
        # reset, the second pair to touch a given file silently re-serves the
        # first pair's analysis - a file appearing in several pairs (e.g.
        # contracts/spells/4_2_0.sol across three Reserve pairs) would report
        # whichever commit happened to be analyzed first.
        _shared.reset_caches()
        _storage.reset_caches()

        prev_spec = H.detect_env(prev_wt.path)
        cur_spec = H.detect_env(cur_wt.path)
        p_ok, p_cause, p_detail = H.install(prev_spec, cache_root)
        c_ok, c_cause, c_detail = H.install(cur_spec, cache_root)
        rep["env"]["prev"] = {"ok": p_ok, "cause": p_cause, "detail": p_detail,
                              "solc_pin": prev_spec.solc_pin,
                              "node_manager": prev_spec.node_manager}
        rep["env"]["cur"] = {"ok": c_ok, "cause": c_cause, "detail": c_detail,
                             "solc_pin": cur_spec.solc_pin,
                             "node_manager": cur_spec.node_manager}
        if not (p_ok and c_ok):
            rep["error"] = "env reconstruction failed on one side"
            reports.append(rep)
            continue

        rep["changed"] = H.changed_sol(repo, prev, cur)
        modified: list[str] = list(rep["changed"].get("modified", []))
        if not modified:
            reports.append(rep)
            continue

        # Build config is per-commit; the cur side's remaps are typically the
        # same as prev's for adjacent commits (see EnvSpec.key). Apply cur.
        _apply_build_config(cur_spec)

        for rel in modified:
            before_p = prev_wt.path / rel
            after_p = cur_wt.path / rel
            if not before_p.is_file() or not after_p.is_file():
                rep["findings"].append({
                    "rule_id": None, "file": rel, "function": None,
                    "fired": False, "candidate": False,
                    "error": "one side missing on disk after checkout",
                })
                continue
            rep["findings"].extend(_run_rules_on_file(before_p, after_p, rel, modified))
        reports.append(rep)

    return reports


def main() -> int:
    ap = argparse.ArgumentParser(description="Chainwatch trajectory walker")
    ap.add_argument("--repo", required=True, help="target repository (working tree)")
    ap.add_argument("--pairs", required=True,
                    help="prev:cur[,prev:cur...] commit SHA pairs")
    ap.add_argument("--worktrees",
                    default=str(ROOT / ".walker-worktrees"),
                    help="directory holding the 'prev' and 'cur' scratch worktrees")
    ap.add_argument("--cache",
                    default=str(ROOT / ".walker-cache"),
                    help="dep-install cache root (keyed by EnvSpec.key)")
    ap.add_argument("--out", default=None,
                    help="write JSON to this path; default: stdout")
    ap.add_argument("--pretty", action="store_true",
                    help="indent JSON for humans")
    args = ap.parse_args()

    try:
        pairs = _parse_pairs(args.pairs)
    except ValueError as exc:
        print(f"ERROR: --pairs: {exc}", file=sys.stderr)
        return 2

    repo = Path(args.repo).resolve()
    if not (repo / ".git").exists():
        print(f"ERROR: {repo} is not a git working tree (no .git)", file=sys.stderr)
        return 2

    try:
        reports = walk(repo, pairs,
                       Path(args.worktrees).resolve(),
                       Path(args.cache).resolve())
    except Exception:  # noqa: BLE001
        traceback.print_exc()
        return 1

    text = json.dumps(reports, indent=2 if args.pretty else None)
    if args.out:
        Path(args.out).write_text(text, encoding="utf-8")
    else:
        print(text)
    return 0


if __name__ == "__main__":
    sys.exit(main())
