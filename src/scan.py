"""The Chainwatch scan pipeline: a repository's git history -> classified findings.

This is the one place the pieces are joined, and it is shared by both front
ends (`chainwatch.py` on the command line, `webapp/server.py` over HTTP) so
there is exactly one implementation of what a scan means.

    history.py   which commits touched Solidity, and how to rebuild each
                 commit's dependency environment
    rules/       what regressed between two commits, and where (attribution)
    verdict.py   whether the surrounding proof is complete enough to call it
                 a finding
    liveness.py  whether the regressed code is what is deployed on-chain

THE COVERAGE INVARIANT (finding HIST-L1, and the reason this module reports
what it could NOT do as loudly as what it could):

    A scan that analysed nothing reports zero findings, and so does a scan of a
    clean repository. Those two results are indistinguishable unless coverage
    is part of the report. Every report this module produces therefore carries
    `coverage`: pairs seen, pairs analysed, pairs skipped WITH A REASON, and
    the same for individual file comparisons. A consumer that hides those
    numbers is misrepresenting the result.

TRAJECTORY (the product's actual claim):

    For every finding we record the commit that introduced it, that commit's
    first parent, author and date, the changed line range, and - by re-running
    the SAME rule against (N-1, HEAD) - whether the regression is still present
    at HEAD or was repaired later. "Which commit made it vulnerable" is the
    first half of the charter's one sentence; `liveness` is the second.

CHARTER rule 5, and it is now literal (finding WALK-L6): the target repository
is READ-ONLY. `mirror_clone` makes a bare clone inside Chainwatch's own scratch
directory and every worktree, checkout and piece of git bookkeeping happens
there - so the target is touched only by the clone and the fetch that produced
it, both of which read it and nothing else. Verified against a read-only bind
mount: the scan completes and `.git/worktrees/` in the target stays ABSENT, not
merely unchanged. Dependency installs run with lifecycle scripts disabled (see
history.INSTALL_ENV), inside the scratch worktrees. Nothing here can construct
a transaction.
"""

from __future__ import annotations

import hashlib
import os
import re
import subprocess
import time
import traceback
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Optional

from . import history as H
from . import verdict as V
from .rules import register_all
from .rules import _shared, _storage

RULES: dict = {}
register_all(RULES)

ROOT = Path(__file__).resolve().parent.parent

# Rule ids in report order (matches CHARTER's scope table).
RULE_ORDER = ["1", "2a", "2b", "3a", "3b", "3c", "4", "5", "6", "10"]

RULE_TITLES = {
    "1": "SC01 Access control removed",
    "2a": "SC08 Reentrancy guard removed",
    "2b": "SC08 CEI ordering broken",
    "3a": "SC10 Upgrade authorization weakened",
    "3b": "SC10 Initializer re-callable",
    "3c": "SC10 Storage layout collision",
    "4": "SC09 Overflow protection removed",
    "5": "SC06 External call return unchecked",
    "6": "SC05 Input validation removed",
    "10": "SC01 Control migrated to an unguarded entry point",
}

_HUNK = re.compile(r"^@@ -\d+(?:,\d+)? \+(\d+)(?:,(\d+))? @@")

# Imported lazily-ish: liveness pulls in web3, which a repo-only scan does not
# need. The text itself is a constant and must match liveness.LIVE_CAVEAT.
try:
    from .liveness import LIVE_CAVEAT as _LIVE_CAVEAT
except Exception:  # noqa: BLE001 - web3 absent: the caveat text still ships
    _LIVE_CAVEAT = (
        "LIVE = this exact bytecode is present on-chain at this address and is "
        "what executes there. It does NOT mean the contract is currently "
        "reachable, funded, or exploitable - liveness compares code, not risk."
    )


# --------------------------------------------------------------------------- git


def commit_meta(repo: Path, sha: str) -> dict:
    """author / date / subject / parent for one commit."""
    out = H._git(repo, "show", "-s", "--format=%H%x1f%an%x1f%aI%x1f%s%x1f%P", sha)
    parts = out.strip().split("\x1f")
    if len(parts) < 5:
        return {"hash": sha}
    parents = parts[4].split()
    return {
        "hash": parts[0],
        "author": parts[1],
        "date": parts[2],
        "subject": parts[3],
        "parent": parents[0] if parents else None,
    }


def changed_line_ranges(repo: Path, prev: str, cur: str, rel: str) -> list[tuple[int, int]]:
    """[(first, last)] line ranges touched in the AFTER file, from `git diff -U0`."""
    try:
        out = H._git(repo, "diff", "-U0", prev, cur, "--", rel)
    except Exception:
        return []
    ranges: list[tuple[int, int]] = []
    for line in out.splitlines():
        m = _HUNK.match(line)
        if not m:
            continue
        start = int(m.group(1))
        count = int(m.group(2) or 1)
        if count == 0:  # pure deletion: point at the surrounding line
            ranges.append((start, start))
        else:
            ranges.append((start, start + count - 1))
    return ranges


def _range_text(ranges: list[tuple[int, int]], line: Optional[int]) -> Optional[str]:
    """The hunk containing `line`, else every hunk. `None` only when the diff
    produced no hunks at all, which is what keeps evidence field 1 honest."""
    if not ranges:
        return None
    if line is not None:
        for lo, hi in ranges:
            if lo <= line <= hi:
                return f"{lo}-{hi}"
    return ",".join(f"{lo}-{hi}" for lo, hi in ranges)


# --------------------------------------------------------------------------- scan


@dataclass
class ScanOptions:
    repo: Path
    limit: int = 50
    pathspec: str = "**/*.sol"
    root_dir: str = ""              # restrict the diff to this subdirectory
    address: Optional[str] = None   # capability 11
    rpc_url: Optional[str] = None
    worktrees: Optional[Path] = None
    cache: Optional[Path] = None
    check_head_survival: bool = True
    rules: Optional[list[str]] = None  # None = every registered rule
    # Explicit (prev, cur) pairs instead of history discovery. This is how a
    # previously root-caused case is re-measured on the real repository - the
    # regression test for a false positive that was fixed at rule level.
    explicit_pairs: Optional[list[tuple[str, str]]] = None


@dataclass
class Coverage:
    pairs_total: int = 0
    pairs_analyzed: int = 0
    pairs_skipped: int = 0
    skips: list[dict] = field(default_factory=list)
    files_total: int = 0
    files_ok: int = 0
    files_error: int = 0
    # Comparisons that could not even be ATTEMPTED, kept separate from ones that
    # were attempted and failed. Collapsing the two would misreport a missing
    # toolchain as a broken rule (finding HIST-L2).
    files_skipped: int = 0
    file_skips: list[dict] = field(default_factory=list)
    # Every compiler auto-provision decision (HIST-L2): cache-hit, installed, or
    # install-failed. Recorded even on success, so a run can always account for
    # WHY a comparison became analysable - the same transparency standard the
    # skip reasons already meet.
    solc_installs: list[dict] = field(default_factory=list)
    rule_errors: list[dict] = field(default_factory=list)

    def as_dict(self) -> dict:
        pct = (self.pairs_analyzed / self.pairs_total * 100) if self.pairs_total else 0.0
        fpct = (self.files_ok / self.files_total * 100) if self.files_total else 0.0
        return {
            "pairs_total": self.pairs_total,
            "pairs_analyzed": self.pairs_analyzed,
            "pairs_skipped": self.pairs_skipped,
            "pairs_analyzed_pct": round(pct, 1),
            "files_total": self.files_total,
            "files_ok": self.files_ok,
            "files_error": self.files_error,
            "files_skipped": self.files_skipped,
            "files_ok_pct": round(fpct, 1),
            "file_skips": self.file_skips[:200],
            "skips": self.skips,
            "rule_errors": self.rule_errors[:200],
            "solc_provision_counts": dict(
                Counter(r["result"].split(":")[0] for r in self.solc_installs)
            ),
            "solc_installs": self.solc_installs[:200],
            # Distinct versions actually DOWNLOADED by this run, so the bound
            # HIST-L2 asked for ("say up front which versions it will fetch")
            # is at least reported after the fact.
            "solc_versions_installed": sorted(
                {r["version"] for r in self.solc_installs if r["result"] == "installed"}
            ),
        }


def _apply_build_config(spec: H.EnvSpec) -> list[str]:
    """Bind one checkout to its own remappings and compiler pin.

    Registered per checkout rather than set globally, because a pair spans two
    of them (see `_shared.register_root`). The global REMAPS/REMAPPINGS are
    still pointed at the N side so any code path that has not been taught about
    roots degrades to the previous behaviour rather than to nothing.
    """
    remaps = H.derive_remaps(spec.root, absolute=True)
    _shared.register_root(spec.root, remaps)
    _shared.REMAPS = list(remaps)
    _storage.REMAPPINGS = list(remaps)
    _storage.PROJECT_ROOT = Path(spec.root)
    if spec.solc_pin:
        os.environ["SOLC_VERSION"] = spec.solc_pin
    return remaps


def _run_rule(rule_id: str, before_p: Path, after_p: Path, meta: dict):
    """One rule, one file pair. Returns (raw_verdict, records, error)."""
    run_fn = RULES[rule_id]
    try:
        raw = run_fn(before_p, after_p, meta)
        return raw, list(meta.get("_findings", [])), None
    except Exception as exc:  # noqa: BLE001 - one broken rule must not end the scan
        return False, [], f"{type(exc).__name__}: {exc}"[:300]


def scan(opts: ScanOptions, on_event: Optional[Callable[[dict], None]] = None,
         should_stop: Optional[Callable[[], bool]] = None) -> dict:
    """Walk the repository's Solidity history and return a full report dict."""

    def emit_event(kind: str, **kw):
        if on_event:
            try:
                on_event({"kind": kind, "t": time.time(), **kw})
            except Exception:  # noqa: BLE001 - a broken listener never stops a scan
                pass

    repo = Path(opts.repo).resolve()
    # Scratch worktrees are namespaced PER TARGET REPOSITORY. Two scans of
    # different repos would otherwise check out into the same `prev`/`cur`
    # directories and silently analyse each other's files; the process-level
    # lock in the web app only covers one process. Repeat scans of the same
    # repo still reuse their slots, which is what keeps the dependency install
    # amortised (see history.EnvSpec.key).
    worktrees = Path(opts.worktrees or (
        ROOT / ".walker-worktrees" / hashlib.sha1(str(repo).encode()).hexdigest()[:10]
    )).resolve()
    cache = Path(opts.cache or (ROOT / ".walker-cache")).resolve()
    worktrees.mkdir(parents=True, exist_ok=True)

    rule_ids = [r for r in (opts.rules or RULE_ORDER) if r in RULES]
    started = time.time()
    cov = Coverage()
    findings: list[V.Finding] = []

    emit_event("start", repo=str(repo), limit=opts.limit, rules=rule_ids)

    # CLONE FIRST (finding WALK-L6). Everything after this line reads `origin`,
    # a bare clone inside OUR scratch directory - never the repository the user
    # pointed us at. Worktrees, checkouts and all git bookkeeping therefore
    # happen in a repository we own, and the target is touched only by the
    # clone and the fetch that produced it, both of which read it and nothing
    # else. This is what lets a target be mounted read-only.
    origin = H.mirror_clone(repo, worktrees / "origin.git")
    emit_event("mirror", path=str(origin))

    pairs = (list(opts.explicit_pairs) if opts.explicit_pairs
             else H.sol_commit_pairs(origin, opts.limit, opts.pathspec))
    cov.pairs_total = len(pairs)
    emit_event("pairs", total=len(pairs))
    if not pairs:
        return _report(opts, cov, findings, started, head=None)

    head = H._git(origin, "rev-parse", "HEAD").strip()
    # `wt/` rather than the old flat layout: worktrees created against the
    # TARGET by earlier versions still sit at the old paths, and reusing those
    # names would collide with bookkeeping that belongs to a different repo.
    prev_wt = H.Worktree(origin, worktrees / "wt" / "prev")
    cur_wt = H.Worktree(origin, worktrees / "wt" / "cur")
    head_wt = (H.Worktree(origin, worktrees / "wt" / "head")
               if opts.check_head_survival else None)

    head_spec = None
    if head_wt is not None:
        try:
            head_wt.checkout(head)
            head_spec = H.detect_env(head_wt.path)
            ok, cause, detail = H.install(head_spec, cache)
            if not ok:
                emit_event("warn", message=f"HEAD environment unavailable ({cause}); "
                                           f"survival-to-HEAD will be reported as unknown",
                           detail=detail)
                head_wt = None
        except Exception as exc:  # noqa: BLE001
            emit_event("warn", message=f"HEAD worktree unavailable: {exc}")
            head_wt = None

    # Oldest first: a reader follows history forward, and the first time a
    # regression appears is the commit that introduced it.
    for idx, (prev, cur) in enumerate(reversed(pairs), start=1):
        if should_stop and should_stop():
            emit_event("cancelled", at_pair=idx)
            break

        meta_cur = commit_meta(origin, cur)
        emit_event("pair", index=idx, total=len(pairs), prev=prev[:12], cur=cur[:12],
                   subject=meta_cur.get("subject", ""))

        try:
            prev_wt.checkout(prev)
            cur_wt.checkout(cur)
        except Exception as exc:  # noqa: BLE001
            cov.pairs_skipped += 1
            cov.skips.append({"pair": f"{prev[:12]}..{cur[:12]}", "reason": "checkout-failed",
                              "detail": str(exc)[:200]})
            continue

        # MANDATORY after every checkout (finding WALK-L1): the parse and
        # layout memos are keyed on absolute path, and these worktree paths are
        # reused for every commit, so a stale entry would silently serve the
        # previous commit's analysis for this one.
        _shared.reset_caches()
        _storage.reset_caches()
        _shared.clear_roots()

        prev_spec = H.detect_env(prev_wt.path)
        cur_spec = H.detect_env(cur_wt.path)
        p_ok, p_cause, p_detail = H.install(prev_spec, cache)
        c_ok, c_cause, c_detail = H.install(cur_spec, cache)
        if not (p_ok and c_ok):
            cov.pairs_skipped += 1
            cov.skips.append({
                "pair": f"{prev[:12]}..{cur[:12]}",
                "reason": f"env-reconstruction-failed ({p_cause if not p_ok else c_cause})",
                "detail": (p_detail if not p_ok else c_detail)[:200],
            })
            emit_event("skip", prev=prev[:12], cur=cur[:12],
                       reason=(p_cause if not p_ok else c_cause))
            continue

        # Register every checkout this pair can touch, N last so the global
        # fallback (used by anything not path-aware) describes commit N.
        _apply_build_config(prev_spec)
        if head_spec is not None and head_wt is not None:
            _apply_build_config(head_spec)
        _apply_build_config(cur_spec)

        changed = H.changed_sol(origin, prev, cur, opts.root_dir)
        modified = list(changed.get("modified", []))
        if not modified:
            cov.pairs_analyzed += 1
            continue

        pair_findings = 0
        for rel in modified:
            before_p = prev_wt.path / rel
            after_p = cur_wt.path / rel
            cov.files_total += 1
            if not before_p.is_file() or not after_p.is_file():
                cov.files_error += 1
                cov.rule_errors.append({"pair": f"{prev[:12]}..{cur[:12]}", "file": rel,
                                        "rule": None, "error": "one side missing on disk"})
                continue

            # PRE-FLIGHT (finding HIST-L2). An exact pragma pin whose compiler
            # is not installed cannot be satisfied by any other version, so the
            # nine rule invocations that would follow are doomed before they
            # start - and the error they eventually produce names whichever
            # compiler the fallback loop happened to try last, not the missing
            # one. Decide it here, once, and say which version is missing.
            # AUTO-PROVISION (finding HIST-L2). An exact pin is decidable, and
            # when the compiler is absent it is also FIXABLE: fetch it rather
            # than skip. Both sides are asked, because a diff can straddle a
            # pragma bump and either side being uncompilable dooms the pair.
            # ensure_solc is called even when the version IS present, so a cache
            # hit is LOGGED rather than silently taking the same branch as a
            # caret range - otherwise the coverage report can never show why a
            # comparison was cheap.
            pin_blocked = None
            for side in (after_p, before_p):
                pin = H.exact_pin(_shared.source_pragma_expr(side))
                if pin is None:
                    continue  # caret/range: solc_candidates + solc arbitrate
                got, why = H.ensure_solc(pin)
                cov.solc_installs.append({
                    "pair": f"{prev[:12]}..{cur[:12]}", "file": rel,
                    "version": pin, "result": why,
                })
                if why != "cache-hit":
                    emit_event("solc-provision", version=pin, result=why)
                if not got:
                    pin_blocked = (pin, why)
                    break
            if pin_blocked:
                version, why = pin_blocked
                cov.files_skipped += 1
                cov.file_skips.append({
                    "pair": f"{prev[:12]}..{cur[:12]}", "file": rel,
                    "reason": f"solc {version} unavailable ({why})",
                })
                emit_event("file-skip", file=rel,
                           reason=f"solc {version} unavailable ({why})")
                continue

            ranges = changed_line_ranges(origin, prev, cur, rel)
            file_ok = True
            for rule_id in rule_ids:
                meta = {"source_path": rel, "changed_files": modified}
                raw, records, err = _run_rule(rule_id, before_p, after_p, meta)
                if err:
                    file_ok = False
                    cov.rule_errors.append({"pair": f"{prev[:12]}..{cur[:12]}",
                                            "file": rel, "rule": rule_id, "error": err})
                    continue
                if not raw or not records:
                    continue

                survives, fixed_at = _head_survival(
                    rule_id, before_p, rel, modified, head_wt, head)

                for rec in records:
                    f = V.build(
                        rec,
                        # `parent` is the commit actually COMPARED AGAINST, not
                        # merely git's first parent, so the diff a reader opens
                        # from a finding is the diff the rule read.
                        commit={**meta_cur, "parent": prev,
                                "line_range": _range_text(ranges, rec.get("line"))},
                        survives_to_head=survives,
                    )
                    f.fixed_at = fixed_at
                    f.file = rel          # repo-relative beats worktree-absolute
                    V.classify(f)
                    findings.append(f)
                    pair_findings += 1
                    emit_event("finding", rule=rule_id, title=RULE_TITLES.get(rule_id, ""),
                               file=rel, contract=f.contract, function=f.function,
                               commit=cur[:12], verdict=f.verdict,
                               severity=f.severity_hint, detail=f.detail)
            if file_ok:
                cov.files_ok += 1
            else:
                cov.files_error += 1

        cov.pairs_analyzed += 1
        emit_event("pair-done", index=idx, total=len(pairs), findings=pair_findings)

    if opts.address:
        _attach_liveness(opts, findings, head_wt, emit_event)

    report = _report(opts, cov, findings, started, head=head)
    emit_event("done", **{k: report["summary"][k] for k in report["summary"]})
    return report


def _head_survival(rule_id: str, before_p: Path, rel: str, modified: list[str],
                   head_wt, head_sha: str) -> tuple[Optional[bool], Optional[str]]:
    """Is this regression still present at HEAD?

    Answered with the SAME rule, not a heuristic: run it on (N-1 file, HEAD
    file). If it still fires, the control that existed at N-1 is still missing
    today. If it stays quiet, some later commit restored it, so the finding is
    history rather than a live exposure - real trajectory information, but never
    CONFIRMED (RULES.md: reachable at HEAD, not just at commit N).

    Returns (survives, fixed_at). `None` means UNDETERMINED - the file is gone
    at HEAD, or no HEAD environment could be built - and undetermined never
    counts as proof in either direction.
    """
    if head_wt is None:
        return None, None
    head_file = head_wt.path / rel
    if not head_file.is_file():
        return None, None
    meta = {"source_path": rel, "changed_files": modified}
    raw, _records, err = _run_rule(rule_id, before_p, head_file, meta)
    if err:
        return None, None
    if raw:
        return True, None
    return False, head_sha[:12]


def _attach_liveness(opts: ScanOptions, findings: list[V.Finding], head_wt, emit_event):
    """Capability 11 on every finding's contract, once per contract.

    A finding whose contract is not what is deployed at the given address is not
    the code holding funds; the verdict model downgrades it accordingly.
    """
    try:
        from . import liveness as L
    except Exception as exc:  # noqa: BLE001 - web3/RPC optional at import time
        emit_event("warn", message=f"liveness unavailable: {exc}")
        return
    if head_wt is None:
        emit_event("warn", message="liveness needs a HEAD checkout to compile against")
        return

    emit_event("liveness", address=opts.address)
    cache: dict[str, tuple[str, str]] = {}
    for f in findings:
        key = f"{f.file}:{f.contract}"
        if key not in cache:
            try:
                runtime = _runtime_bytecode(head_wt.path, f.file, f.contract)
                if not runtime:
                    cache[key] = (V.UNKNOWN, "contract not present at HEAD, or it does "
                                             "not compile to runtime bytecode")
                else:
                    res = L.check_against_artifact(opts.address, runtime,
                                                   rpc_url=opts.rpc_url)
                    cache[key] = (res.verdict, res.reason)
            except Exception as exc:  # noqa: BLE001
                cache[key] = (V.UNKNOWN, f"{type(exc).__name__}: {exc}"[:200])
        f.liveness, f.liveness_reason = cache[key]
        f.evidence.liveness = f.liveness
        V.classify(f)


def _runtime_bytecode(root: Path, rel: str, contract: str,
                      optimize_runs: Optional[int] = None) -> Optional[str]:
    """`solc --bin-runtime` for one contract in a checkout. Build config only.

    `optimize_runs` matters for liveness and nothing else: deployed bytecode was
    produced with whatever optimizer setting the project used, and comparing
    against an unoptimized build guarantees a mismatch that 11-R3 must then
    report as UNKNOWN. Passing the project's own setting is the one cheap thing
    that can turn an uninformative UNKNOWN into a real answer.
    """
    remaps = H.derive_remaps(root, absolute=True)
    # Same widening as _storage._run_layout: since WALK-L4 the dependency remaps
    # resolve to the cache directory, which lies outside the checkout.
    allowed = [str(root)]
    for rm in remaps:
        dest = rm.partition("=")[2].rstrip("/")
        if dest and dest not in allowed:
            allowed.append(dest)
    cmd = ["solc", *remaps, "--allow-paths", ",".join(allowed)]
    if optimize_runs is not None:
        cmd += ["--optimize", "--optimize-runs", str(optimize_runs)]
    proc = subprocess.run(
        [*cmd, "--combined-json", "bin-runtime", rel],
        cwd=str(root), capture_output=True, text=True,
    )
    if proc.returncode != 0:
        return None
    import json
    data = json.loads(proc.stdout)
    for qualified, payload in data.get("contracts", {}).items():
        if qualified.rpartition(":")[2] == contract:
            code = payload.get("bin-runtime") or ""
            return code or None
    return None


def _report(opts: ScanOptions, cov: Coverage, findings: list[V.Finding],
            started: float, head: Optional[str]) -> dict:
    confirmed = [f for f in findings if f.verdict == V.CONFIRMED]
    candidates = [f for f in findings if f.verdict == V.CANDIDATE]
    by_rule: dict[str, int] = {}
    for f in findings:
        by_rule[f.rule_id] = by_rule.get(f.rule_id, 0) + 1
    return {
        "repo": str(opts.repo),
        "head": head,
        "address": opts.address,
        "summary": {
            "findings": len(findings),
            "confirmed": len(confirmed),
            "candidates": len(candidates),
            "pairs_analyzed": cov.pairs_analyzed,
            "pairs_total": cov.pairs_total,
            "coverage_pct": cov.as_dict()["pairs_analyzed_pct"],
            "seconds": round(time.time() - started, 1),
        },
        "by_rule": by_rule,
        "coverage": cov.as_dict(),
        "findings": [f.as_dict() for f in findings],
        "rule_titles": RULE_TITLES,
        # Shipped with the report so every consumer shows the same qualification
        # next to a LIVE verdict rather than inventing its own wording.
        "live_caveat": _LIVE_CAVEAT,
    }
