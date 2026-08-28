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

import functools
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
from . import sizing as SZ
from . import verdict as V
from . import verified as VER
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


def _repo_relative(abs_path: Optional[str], *roots: Path) -> Optional[str]:
    """`abs_path` (a worktree-absolute path `_shared.emit` recorded from the
    fired declaration's own source mapping) made repo-relative against
    whichever checkout root it actually sits under. `None` if it matches
    neither - the caller falls back to the loop's own `rel`."""
    if not abs_path:
        return None
    ap = Path(abs_path)
    for root in roots:
        if root is None:
            continue
        try:
            return str(ap.relative_to(root)).replace("\\", "/")
        except ValueError:
            continue
    return None


def _dedupe(findings: list[V.Finding]) -> list[V.Finding]:
    """RC-DEDUP1: the same declaration can be DISCOVERED TWICE in one commit
    when it is reachable from more than one changed file's compiled unit -
    e.g. `UniswapV3Factory.sol` and `UniswapV3Pair.sol` are both genuinely
    changed, `UniswapV3Pair` is importable from Factory's compilation too, and
    `accept_finding`'s per-file scope correctly admits BOTH discoveries
    because both files really did change. That is not a scoping bug, so
    tightening `accept_finding` cannot fix it - the fix is to stop treating
    "found while compiling file X" as part of the finding's identity.

    Collapses by what the finding actually says (rule, commit, contract, the
    variable/function it names, its line, its detail text) rather than by
    which file the walker happened to be compiling when a rule found it. Two
    GENUINELY different findings on the same contract (e.g. two different
    variables shifted in the same commit) keep distinct `detail` text and
    survive; only true re-discoveries of the same fact collapse.
    """
    seen: set = set()
    out: list[V.Finding] = []
    for f in findings:
        key = (f.rule_id, f.commit, f.contract, f.function,
               f.raw_evidence.get("variable"), f.line, f.detail)
        if key in seen:
            continue
        seen.add(key)
        out.append(f)
    return out


# --------------------------------------------------------------------------- scan


@dataclass
class ScanOptions:
    repo: Path
    limit: int = 50
    pathspec: str = "**/*.sol"
    # An EXPLICIT subdirectory. Honoured exactly - no test/mock filtering is
    # applied on top, because an explicit root is an instruction rather than a
    # hint, and changing what it means would silently move every pinned result.
    # Left empty, the scope is DETECTED from the tree (finding SCAN-L1).
    root_dir: str = ""
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
    # Capability 13 (src/exposure.py): for every file this scan already
    # compiled at HEAD because it produced a finding, also check whether any
    # one-shot init/critical-config function Rule 3b would recognise is still
    # UNCONSUMED on the deployed contract - a live, present-tense question
    # independent of the CONFIRMED/CANDIDATE verdict model. Needs --address.
    check_exposure: bool = False
    # Capability 14 (src/exploit_proof.py): for every CONFIRMED finding whose
    # rule is in the narrow access-control class (1, 3a, 3b), a read-only
    # eth_call proving the exact regressed function is callable by an
    # unprivileged address right now. Opt-in for the same reason capability
    # 13 is: it spends a real RPC call per eligible finding and nobody asked
    # for it by default. Needs --address.
    check_exploit_proof: bool = False


@dataclass
class Coverage:
    pairs_total: int = 0
    pairs_analyzed: int = 0
    pairs_skipped: int = 0
    skips: list[dict] = field(default_factory=list)
    files_total: int = 0
    files_ok: int = 0
    files_error: int = 0
    # COV-ACCT1. Coverage is EARNED per rule but was scored per file: one
    # boolean spanning ~10 rule invocations meant a single failure discarded the
    # credit for every rule that had run cleanly on that file. Measured on
    # 88mph: 0/43 files "ok" while 387/430 rule invocations had in fact
    # succeeded and produced a real finding - a 90-point self-understatement.
    # The invocation counters are the honest denominator; the three file buckets
    # below are the roll-up a human actually reads.
    rule_invocations_total: int = 0
    rule_invocations_ok: int = 0
    rule_invocations_error: int = 0
    # Asked of a compiler generation that has no such question (COV-ACCT2).
    # Counted, reported, and excluded from BOTH numerator and denominator when
    # computing what fraction of the answerable work actually got done.
    rule_invocations_unsupported: int = 0
    # Files where some rules ran and some failed. Previously indistinguishable
    # from "nothing ran at all", which is a materially different situation.
    files_partial: int = 0
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
    # ONE RECORD PER PAIR, whatever happened to it (SIZE-L1). Wall clock and
    # comparison counts are the only inputs a size estimate may legitimately
    # use, and nothing recorded them before: `summary.seconds` was a single
    # aggregate, so a pilot had no observed VARIANCE to build a range from and
    # every projection was forced to be a point. A skipped pair is recorded
    # too - it cost real time, and dropping it would under-state what remains.
    pair_records: list[dict] = field(default_factory=list)

    def as_dict(self) -> dict:
        pct = (self.pairs_analyzed / self.pairs_total * 100) if self.pairs_total else 0.0
        fpct = (self.files_ok / self.files_total * 100) if self.files_total else 0.0
        # The answerable denominator: an unsupported rule was never a question
        # this compiler generation could be asked, so it is removed from both
        # sides rather than counted as work that failed (COV-ACCT2).
        answerable = self.rule_invocations_total - self.rule_invocations_unsupported
        rpct = (self.rule_invocations_ok / answerable * 100) if answerable else 0.0
        return {
            "pair_records": list(self.pair_records),
            "pairs_total": self.pairs_total,
            "pairs_analyzed": self.pairs_analyzed,
            "pairs_skipped": self.pairs_skipped,
            "pairs_analyzed_pct": round(pct, 1),
            "files_total": self.files_total,
            "files_ok": self.files_ok,
            "files_partial": self.files_partial,
            "files_error": self.files_error,
            "files_skipped": self.files_skipped,
            "files_ok_pct": round(fpct, 1),
            "rule_invocations_total": self.rule_invocations_total,
            "rule_invocations_ok": self.rule_invocations_ok,
            "rule_invocations_error": self.rule_invocations_error,
            "rule_invocations_unsupported": self.rule_invocations_unsupported,
            "rule_invocations_answerable": answerable,
            "rule_coverage_pct": round(rpct, 1),
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
    """One rule, one file pair. Returns (raw_verdict, records, error, unsupported).

    `unsupported` separates "this rule cannot be asked here at all" from "this
    rule was asked and broke" (finding COV-ACCT2). Only the second is a defect;
    the first is a range limit, and conflating them is what let a 90%-covered
    scan report 0% coverage.
    """
    run_fn = RULES[rule_id]
    try:
        raw = run_fn(before_p, after_p, meta)
        return raw, list(meta.get("_findings", [])), None, False
    except _shared.RuleUnsupported as exc:
        return False, [], f"{type(exc).__name__}: {exc}"[:300], True
    except Exception as exc:  # noqa: BLE001 - one broken rule must not end the scan
        return False, [], f"{type(exc).__name__}: {exc}"[:300], False


def _restores_build_config(fn):
    """Undo `_apply_build_config`'s process-wide writes when a scan ends (11-L4).

    `_apply_build_config` points four globals at the checkout it is configuring.
    Three of them (`_shared.REMAPS`, `_storage.REMAPPINGS`,
    `_storage.PROJECT_ROOT`) are only ever consulted as a FALLBACK: both
    `_shared.remaps_for` and `_storage._root_and_remaps` prefer a registered
    root and reach the global only for a path outside every registered
    checkout. In-process, that fallback is precisely the fixture set - so one
    scan left every later fixture parse in the same interpreter pointed at some
    scanned repository's dependency tree, and the fourth global, `SOLC_VERSION`,
    left the compiler pinned to that repository's commit.

    This is why `tests/test_exposure.py` snapshots `_shared.REMAPS` at
    collection time and restores it around each fixture-parsing test: a
    work-around at one call site for a leak at the source. Fixing it here fixes
    it for every caller, including any future test that would otherwise have
    had to know about the hazard.

    Deliberately restore-AFTER rather than never-set: during the scan the
    globals still hold the scanned checkout's values, so any code path not yet
    taught about registered roots keeps degrading to previous behaviour rather
    than to nothing - which is the documented reason they are set at all.

    Applied as a decorator so `scan`'s body, and its several exit points, are
    untouched.
    """
    @functools.wraps(fn)
    def wrapper(*args, **kwargs):
        saved_remaps = list(_shared.REMAPS)
        saved_remappings = list(_storage.REMAPPINGS)
        saved_root = _storage.PROJECT_ROOT
        saved_solc = os.environ.get("SOLC_VERSION")
        try:
            return fn(*args, **kwargs)
        finally:
            _shared.REMAPS = saved_remaps
            _storage.REMAPPINGS = saved_remappings
            _storage.PROJECT_ROOT = saved_root
            _shared.clear_roots()
            if saved_solc is None:
                os.environ.pop("SOLC_VERSION", None)
            else:
                os.environ["SOLC_VERSION"] = saved_solc
    return wrapper


def _checkout(wt, sha: str, emit_event: Callable[..., None]) -> None:
    """`Worktree.checkout`, plus surfacing SEC-L1 (symlink stripping) at
    BANNER weight - a target repository shipping a tracked symlink is a
    genuine, non-accidental signal worth a scan's reader seeing plainly,
    not a detail buried in a debug log.

    Module-level (not a closure inside `scan()`) because `_attach_liveness`'s
    own clone-fallback checkout needs it too, and a per-function local of the
    same name silently shadowed nothing but its OWN scope: a call from
    `_attach_liveness` raised `NameError: name 'checkout' is not defined`,
    caught by that call site's blanket `except Exception`, so the immutable-
    EIP-1167-clone liveness fallback silently degraded to UNKNOWN on every
    call instead of erroring loudly. Found while re-verifying the 88mph demo
    case still reaches CONFIRMED after this session's SEC-L1 change - it no
    longer did, for exactly this reason.
    """
    stripped = wt.checkout(sha)
    if stripped:
        emit_event("warn", message=(
                f"removed {len(stripped)} symlink(s) from the target's own "
                f"tracked tree at {sha[:12]} before reading any file "
                f"(SEC-L1): {', '.join(stripped[:5])}"
                + (f" (+{len(stripped) - 5} more)" if len(stripped) > 5 else "")))


@_restores_build_config
def scan(opts: ScanOptions, on_event: Optional[Callable[[dict], None]] = None,
         should_stop: Optional[Callable[[], bool]] = None) -> dict:
    """Walk the repository's Solidity history and return a full report dict."""

    def emit_event(kind: str, **kw):
        if on_event:
            try:
                on_event({"kind": kind, "t": time.time(), **kw})
            except Exception:  # noqa: BLE001 - a broken listener never stops a scan
                pass

    def checkout(wt, sha: str) -> None:
        _checkout(wt, sha, emit_event)

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
    scope: dict = {}

    emit_event("start", repo=str(repo), limit=opts.limit, rules=rule_ids)

    # CLONE FIRST (finding WALK-L6). Everything after this line reads `origin`,
    # a bare clone inside OUR scratch directory - never the repository the user
    # pointed us at. Worktrees, checkouts and all git bookkeeping therefore
    # happen in a repository we own, and the target is touched only by the
    # clone and the fetch that produced it, both of which read it and nothing
    # else. This is what lets a target be mounted read-only.
    origin = H.mirror_clone(repo, worktrees / "origin.git")
    emit_event("mirror", path=str(origin))

    # WHAT THIS SCAN WILL LOOK AT, decided before it starts and reported to the
    # caller (SCAN-L1). Without this the web app's `contracts` default
    # diffed a directory morpho-blue does not have: every pair was "analysed",
    # not one file was compared, and the result read as a clean scan.
    if opts.root_dir:
        scope = {"mode": "explicit", "roots": [opts.root_dir],
                 "exclude_segments": [],
                 "reason": f"restricted to {opts.root_dir}/ as requested; "
                           f"nothing else is filtered out"}
    else:
        scope = {**H.detect_source_scope(origin), "mode": "auto"}
    emit_event("scope", **{k: scope.get(k) for k in
                           ("mode", "roots", "reason", "source_files",
                            "excluded_files", "total_files")})

    pairs = (list(opts.explicit_pairs) if opts.explicit_pairs
             else H.sol_commit_pairs(origin, opts.limit, opts.pathspec))
    cov.pairs_total = len(pairs)
    emit_event("pairs", total=len(pairs))
    if not pairs:
        return _report(opts, cov, findings, started, head=None, scope=scope)

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
            checkout(head_wt, head)
            head_spec = H.detect_env(head_wt.path)
            # Progress BEFORE the call, not after. A dependency install is the
            # longest silent phase of a scan - a Yarn Berry monorepo can run for
            # many minutes - and with nothing emitted first, a user (or a judge
            # watching a demo) cannot tell "working" from "hung".
            emit_event("env", phase="head", manager=head_spec.node_manager or "none",
                       message=f"installing HEAD dependencies "
                               f"({head_spec.node_manager or 'none'}); "
                               f"first run on a large repo can take minutes")
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

        # SIZE-L1. Every exit from this iteration records one pair, so the
        # observed set is the whole run and not just its successful part.
        # Baselines rather than local counters: the per-file bookkeeping below
        # already maintains these, and a second copy is a second thing to keep
        # in step.
        pair_started = time.time()
        files_seen_at_start = cov.files_total
        files_ok_at_start = cov.files_ok

        def record_pair() -> None:
            cov.pair_records.append({
                "pair": f"{prev[:12]}..{cur[:12]}",
                "seconds": round(time.time() - pair_started, 2),
                "comparisons": cov.files_total - files_seen_at_start,
                "comparisons_ok": cov.files_ok - files_ok_at_start,
            })

        try:
            checkout(prev_wt, prev)
            checkout(cur_wt, cur)
        except Exception as exc:  # noqa: BLE001
            cov.pairs_skipped += 1
            cov.skips.append({"pair": f"{prev[:12]}..{cur[:12]}", "reason": "checkout-failed",
                              "detail": str(exc)[:200]})
            # THIS EMIT WAS MISSING. The sibling skip below always announced
            # itself; this branch updated coverage and said nothing, so a pair
            # could emit `pair` and then never resolve on the event stream.
            # The final report showed the skip, the live view hung on it
            # forever, and any progress indicator built on these events would
            # have been wrong for exactly the pairs that went worst.
            emit_event("skip", index=idx, total=len(pairs),
                       prev=prev[:12], cur=cur[:12], reason="checkout-failed")
            record_pair()
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
        emit_event("env", phase="pair", manager=cur_spec.node_manager or "none",
                   message=f"installing dependencies for {prev[:12]}..{cur[:12]} "
                           f"({cur_spec.node_manager or 'none'})")
        p_ok, p_cause, p_detail = H.install(prev_spec, cache)
        c_ok, c_cause, c_detail = H.install(cur_spec, cache)
        if not (p_ok and c_ok):
            cov.pairs_skipped += 1
            cov.skips.append({
                "pair": f"{prev[:12]}..{cur[:12]}",
                "reason": f"env-reconstruction-failed ({p_cause if not p_ok else c_cause})",
                "detail": (p_detail if not p_ok else c_detail)[:200],
            })
            emit_event("skip", index=idx, total=len(pairs),
                       prev=prev[:12], cur=cur[:12],
                       reason=(p_cause if not p_ok else c_cause))
            record_pair()
            continue

        # Register every checkout this pair can touch, N last so the global
        # fallback (used by anything not path-aware) describes commit N.
        _apply_build_config(prev_spec)
        if head_spec is not None and head_wt is not None:
            _apply_build_config(head_spec)
        _apply_build_config(cur_spec)

        changed = H.changed_sol(origin, prev, cur, opts.root_dir,
                                roots=scope.get("roots"),
                                exclude_segments=scope.get("exclude_segments"))
        modified = list(changed.get("modified", []))
        if not modified:
            cov.pairs_analyzed += 1
            record_pair()
            emit_event("pair-done", index=idx, total=len(pairs), findings=0,
                       sizing=SZ.from_pair_records(cov.pair_records)
                              .as_dict(len(pairs) - idx))
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
            rules_ok = rules_failed = 0
            for rule_id in rule_ids:
                meta = {"source_path": rel, "changed_files": modified}
                raw, records, err, unsupported = _run_rule(
                    rule_id, before_p, after_p, meta)
                cov.rule_invocations_total += 1
                if err:
                    if unsupported:
                        cov.rule_invocations_unsupported += 1
                    else:
                        cov.rule_invocations_error += 1
                        rules_failed += 1
                    cov.rule_errors.append({"pair": f"{prev[:12]}..{cur[:12]}",
                                            "file": rel, "rule": rule_id,
                                            "error": err,
                                            "unsupported": unsupported})
                    continue
                cov.rule_invocations_ok += 1
                rules_ok += 1
                if not raw or not records:
                    continue

                survives, fixed_at = _head_survival(
                    rule_id, before_p, rel, modified, head_wt, head,
                    origin=origin, commit=cur)

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
                    # `f.file` is currently the ABSOLUTE path of whatever file
                    # actually DECLARES the fired contract/function (set by
                    # `_shared.emit`, carried through `V.build`) - not
                    # necessarily `rel`, the file the walker asked Slither to
                    # compile. Reachable-but-unchanged-entry-point cases (a
                    # changed file transitively pulling in another changed
                    # file) mean those two can differ; stamping `rel` over it
                    # unconditionally mislabels the finding (RC-DEDUP1).
                    # Repo-relative is still preferred over worktree-absolute,
                    # so resolve against the checkout roots first and only
                    # fall back to `rel` if that fails.
                    f.file = _repo_relative(f.file, cur_wt.path, prev_wt.path) or rel
                    V.classify(f)
                    findings.append(f)
                    pair_findings += 1
                    emit_event("finding", rule=rule_id, title=RULE_TITLES.get(rule_id, ""),
                               file=f.file, contract=f.contract, function=f.function,
                               commit=cur[:12], verdict=f.verdict,
                               severity=f.severity_hint, detail=f.detail)
            # Three outcomes, not two (COV-ACCT1). A file where every
            # answerable rule ran is fully analysed even if some rule was
            # out of range for its compiler; a file where SOME ran is partial,
            # and only a file where nothing ran at all is a lost comparison.
            if rules_failed == 0:
                cov.files_ok += 1
            elif rules_ok > 0:
                cov.files_partial += 1
            else:
                cov.files_error += 1

        cov.pairs_analyzed += 1
        record_pair()
        # Sizing rides the EXISTING event rather than a new type: the web app
        # needs no new stream to show a converging range.
        emit_event("pair-done", index=idx, total=len(pairs), findings=pair_findings,
                   sizing=SZ.from_pair_records(cov.pair_records)
                          .as_dict(len(pairs) - idx))

    # RC-DEDUP1: collapse re-discoveries of the same declaration before
    # liveness (so an on-chain RPC call is never spent twice on one fact) and
    # before the report is built.
    findings = _dedupe(findings)

    if opts.address:
        _attach_liveness(opts, findings, head_wt, emit_event, cur_wt=cur_wt, cache=cache)

    if opts.check_exploit_proof and opts.address:
        _attach_exploit_proof(opts, findings, emit_event)

    exposure_results: list[dict] = []
    if opts.check_exposure and opts.address and head_wt is not None:
        exposure_results = _check_exposure(opts, findings, head_wt, emit_event)

    report = _report(opts, cov, findings, started, head=head, scope=scope,
                     exposure=exposure_results)
    emit_event("done", **{k: report["summary"][k] for k in report["summary"]})
    return report


def _check_exposure(opts: ScanOptions, findings: list[V.Finding], head_wt,
                    emit_event) -> list[dict]:
    """Capability 13 (src/exposure.py). For every file this scan already
    compiled at HEAD because it produced a finding, also check whether any
    one-shot init/critical-config function - identified the same way Rule 3b
    identifies one - is still unconsumed on the deployed contract at
    `opts.address`. A live, present-tense signal, deliberately kept OUT of
    `report["findings"]` and the CONFIRMED/CANDIDATE verdict model: it answers
    a different question (has the window been claimed yet) than a regression
    finding does (did a control get removed), and conflating the two would
    blur RULES.md's six-field evidence contract for no reason.

    Scoped to files this scan already touched, not a whole-repo compile: a
    file with no finding was never established as "in scope for this run" the
    way `changed_sol` establishes it for the pair loop, and compiling
    everything HEAD contains just to look for initializers would be a
    different, heavier feature than this one.

    INHERITED SCOPE LIMIT, stated rather than left implicit (found while
    smoke-testing this capability): every candidate found across every
    finding file is probed against the SAME single `opts.address`. Correct
    for a single-contract investigation - which is what every real scan this
    project has ever run has been - but silently wrong for a multi-contract
    repo where `--address` targets one specific proxy while a DIFFERENT
    finding file belongs to an unrelated contract with its own address: the
    probe would call a real selector on the wrong deployed contract and most
    likely observe a revert (no matching selector) that looks identical to
    "already initialized" for the wrong reason. `_attach_liveness` above has
    the identical inherited assumption and has for as long as capability 11
    has existed; this module doesn't introduce it, but it's worth a fix
    together if a multi-contract `--address` need ever arises.
    """
    try:
        from . import exposure as E
        from . import liveness as L
    except Exception as exc:  # noqa: BLE001 - web3/RPC optional at import time
        emit_event("warn", message=f"exposure probe unavailable: {exc}")
        return []

    try:
        w3 = L._w3(opts.rpc_url)
    except Exception as exc:  # noqa: BLE001
        emit_event("warn", message=f"exposure probe needs an RPC endpoint: {exc}")
        return []

    files = sorted({f.file for f in findings})
    out: list[dict] = []
    seen: set = set()
    for rel in files:
        path = head_wt.path / rel
        if not path.is_file():
            continue
        try:
            _shared.reset_caches()
            slither_obj = _shared.parse(path)
            candidates = E.find_candidates(slither_obj, source_path=rel)
        except Exception as exc:  # noqa: BLE001 - one uncompilable file must not end the probe
            emit_event("warn", message=f"exposure probe: {rel} did not compile "
                                       f"at HEAD ({type(exc).__name__})")
            continue
        for contract, fn in candidates:
            key = (contract.name, fn.full_name)
            if key in seen:
                continue
            seen.add(key)
            res = E.probe(w3, opts.address, contract.name, fn.name, fn.full_name)
            emit_event("exposure", contract=contract.name, function=fn.name,
                       status=res.status)
            out.append(res.as_dict())
    return out


def _attach_exploit_proof(opts: ScanOptions, findings: list[V.Finding],
                          emit_event) -> None:
    """Capability 14 (src/exploit_proof.py). For every CONFIRMED finding whose
    rule is in the narrow, honestly-provable access-control class (1, 3a,
    3b - see that module's docstring for why every other rule is excluded),
    one read-only eth_call proving the exact regressed function is callable
    by an unprivileged address right now.

    Additive and best-effort by construction: a probe failure here is
    recorded ON the finding as `exploit_proof.status = UNKNOWN` and never
    touches `f.verdict` - this capability answers a different, live,
    present-tense question (is the regression callable right now) from the
    six-field CONFIRMED/CANDIDATE model, exactly as capability 13's exposure
    probe already does.
    """
    try:
        from . import exploit_proof as X
        from . import liveness as L
    except Exception as exc:  # noqa: BLE001 - web3/RPC optional at import time
        emit_event("warn", message=f"exploit-proof unavailable: {exc}")
        return
    try:
        w3 = L._w3(opts.rpc_url)
    except Exception as exc:  # noqa: BLE001
        emit_event("warn", message=f"exploit-proof needs an RPC endpoint: {exc}")
        return

    for f in findings:
        if f.verdict != V.CONFIRMED or f.rule_id not in X.ACCESS_CONTROL_RULES:
            continue
        try:
            result = X.prove(w3, {**f.as_dict(), "address": opts.address})
            f.exploit_proof = result.as_dict()
            emit_event("exploit-proof", contract=f.contract, function=f.function,
                       status=result.status)
        except Exception as exc:  # noqa: BLE001 - one probe failure must not end the scan
            f.exploit_proof = {"status": "UNKNOWN", "rule_id": f.rule_id,
                               "contract": f.contract, "function": f.function,
                               "signature": f.signature, "address": opts.address or "",
                               "reason": f"{type(exc).__name__}: {exc}"[:200]}
            emit_event("warn", message=f"exploit-proof failed for "
                                       f"{f.contract}.{f.function}: {exc}")


def _renamed_path_at_head(origin: Path, commit: str, head_sha: str, rel: str,
                          contract: Optional[str] = None) -> Optional[str]:
    """If the file at `rel` (as of `commit`) is gone from that path by
    `head_sha`, find where it actually went - real git evidence about a FACT
    (did this file move), never a guess about whether the regression it once
    held still fires. That question stays with `_head_survival` re-running
    the real rule against whatever this function locates.

    Two signals, most-trusted first:
      1. Git's own rename pairing on the FULL diff between the two commits
         (`git diff --name-status -M`) - authoritative when it fires, but
         similarity-based, so it misses a rename bundled with a heavy
         rewrite. Measured on a real case this project has anchored on all
         session: 88mph's `contracts/NFT.sol` -> `contracts/tokens/NFT.sol`,
         solc 0.5.17 -> 0.8.4, a bespoke constructor-style `init()` rewritten
         onto OZ's `Initializable` - git's default ~50% similarity threshold
         does not pair these, confirmed directly (`git diff --name-status -M
         a4c48d61661a <v3 HEAD>` reports `D contracts/NFT.sol` /
         `A contracts/tokens/NFT.sol` as two unrelated lines, not one `R`).
      2. Same-basename fallback, ONLY when signal 1 found nothing: among
         files ADDED between the two commits, one whose basename matches
         `rel`'s exactly. Refuses (returns `None`, never guesses) when this
         matches more than one file - an ambiguous basename is not evidence.
         If `contract` is given, also requires the candidate to still declare
         `contract <contract>` at `head_sha`, so a same-named-file-in-a-
         different-product coincidence cannot be mistaken for a real move.

    This is a LOCATION HINT, not a verdict. `_head_survival` still re-runs
    the actual rule against whatever this returns; a wrong guess here would
    at worst point the rule at the wrong file, which the rule's own compile
    would then either fire on correctly or not - it cannot fabricate a fact
    the rule itself does not independently establish.
    """
    try:
        out = H._git(origin, "diff", "--name-status", "-M", commit, head_sha)
    except Exception:  # noqa: BLE001
        return None

    added: list[str] = []
    removed_this = False
    for line in out.splitlines():
        parts = line.split("\t")
        if len(parts) == 3 and parts[0].startswith("R") and parts[1] == rel:
            return parts[2]
        if len(parts) == 2 and parts[0] == "A":
            added.append(parts[1])
        elif len(parts) == 2 and parts[0] == "D" and parts[1] == rel:
            removed_this = True

    if not removed_this:
        return None
    base = rel.rsplit("/", 1)[-1]
    candidates = [p for p in added if p.rsplit("/", 1)[-1] == base]
    if len(candidates) != 1:
        return None  # none, or ambiguous - never guess which one
    candidate = candidates[0]
    if contract:
        try:
            content = H._git(origin, "show", f"{head_sha}:{candidate}")
        except Exception:  # noqa: BLE001
            return None
        if not re.search(rf"\bcontract\s+{re.escape(contract)}\b", content):
            return None
    return candidate


def _head_survival(rule_id: str, before_p: Path, rel: str, modified: list[str],
                   head_wt, head_sha: str, origin: Optional[Path] = None,
                   commit: Optional[str] = None,
                   contract: Optional[str] = None) -> tuple[Optional[bool], Optional[str]]:
    """Is this regression still present at HEAD?

    Answered with the SAME rule, not a heuristic: run it on (N-1 file, HEAD
    file). If it still fires, the control that existed at N-1 is still missing
    today. If it stays quiet, some later commit restored it, so the finding is
    history rather than a live exposure - real trajectory information, but never
    CONFIRMED (RULES.md: reachable at HEAD, not just at commit N).

    RENAME-FOLLOWING: a file MOVED and a file DELETED are different facts: the
    first still has a rule to re-run, the second genuinely does not. Previously
    both collapsed into the same bare "undetermined" the moment `rel` was
    missing at HEAD's path, discarding real, checkable evidence. When `origin`
    and `commit` are supplied, a missing file is now first checked against
    `_renamed_path_at_head` before giving up - see that function for exactly
    what is (real git rename evidence, or an unambiguous same-basename match)
    and is not (a guess about the regression itself) trusted here.

    Returns (survives, fixed_at). `None` means UNDETERMINED - the file is gone
    at HEAD (and, if checked, was not found to have moved either), or no HEAD
    environment could be built - and undetermined never counts as proof in
    either direction.
    """
    if head_wt is None:
        return None, None
    resolved_rel = rel
    head_file = head_wt.path / rel
    if not head_file.is_file():
        if origin is not None and commit is not None:
            renamed = _renamed_path_at_head(origin, commit, head_sha, rel, contract)
            if renamed:
                candidate = head_wt.path / renamed
                if candidate.is_file():
                    head_file = candidate
                    resolved_rel = renamed
        if not head_file.is_file():
            return None, None
    # DESIGN-L2 (_shared.accept_finding) attributes a fire only to a
    # declaration whose file is IN `changed_files` - if a rename was
    # followed above, the declaration now lives at `resolved_rel`, not the
    # original `rel` still sitting in `modified`, and every rule's fire
    # would be silently suppressed as "unchanged file" without this update.
    changed_files = modified if resolved_rel == rel else (
        [resolved_rel if p == rel else p for p in modified] +
        ([resolved_rel] if resolved_rel not in modified else [])
    )
    meta = {"source_path": resolved_rel, "changed_files": changed_files}
    raw, _records, err, _unsupported = _run_rule(rule_id, before_p, head_file, meta)
    if err:
        # Unsupported and broken both land here on purpose: either way this
        # re-run established nothing about HEAD, and UNDETERMINED is the honest
        # answer. The distinction matters for COVERAGE accounting, not for a
        # survival claim - which must never be inferred from a question that
        # was not actually answered.
        return None, None
    if raw:
        return True, None
    return False, head_sha[:12]


# Truffle, Hardhat and Foundry all default here. Passing it is not a guess
# that trades precision for recall: check_against_artifact still requires an
# EXACT normalized-bytecode match, so a project built with a different
# optimizer-runs value still, correctly, falls through to UNKNOWN (11-R3) -
# this only turns a spurious unoptimized-vs-optimized mismatch into a real
# answer, never the reverse. Previously `_runtime_bytecode` was called with no
# `optimize_runs` at all, i.e. always unoptimized, which is wrong for nearly
# every real deployment and was silently inflating UNKNOWN. Measured: the real
# deployed 88mph NFT implementation, solc 0.5.17 --optimize --optimize-runs
# 200, is byte-exact against this setting.
DEFAULT_OPTIMIZE_RUNS = 200


def _attach_liveness(opts: ScanOptions, findings: list[V.Finding], head_wt, emit_event,
                     cur_wt=None, cache=None):
    """Capability 11 on every finding's contract, once per contract.

    A finding whose contract is not what is deployed at the given address is not
    the code holding funds; the verdict model downgrades it accordingly.

    IMMUTABLE-CLONE FALLBACK (measured on the real, publicly-disclosed 88mph
    NFT.init() regression, `a4c48d61661a`, 2026-08-26). The HEAD-based check
    below assumes the deployed contract keeps tracking the repository's current
    source - true for an ordinary contract, false for an EIP-1167 minimal-proxy
    clone target. A clone's implementation is immutable at deploy time: a later
    source fix protects only FUTURE clones, so an already-deployed clone's
    target keeps running the exact pre-fix bytecode forever, regardless of what
    HEAD says. `contracts/NFT.sol` was fixed in the real 88mph repo six weeks
    after the regression (`29be743`), then the file was moved and rewritten
    again later - HEAD has no trace of the vulnerable shape left to compile -
    yet the real deployed implementation at `0xDe71B24F...` is, TODAY, still
    byte-for-byte the `a4c48d6` build (verified against real mainnet RPC:
    `.walker-cache` is irrelevant here, this was a live `eth_getCode` read).
    When the address resolves to a structurally-confirmed (never assumed)
    `eip1167-clone` and the HEAD-based check above did not already prove LIVE,
    this recompiles from the REGRESSION COMMIT's own source (`f.commit`)
    instead and checks that. A match is labelled explicitly as such - never
    silently reported as "matches HEAD" - and also supplies survival, because
    for immutable code "this exact bytecode is still running" and "the
    regression still exists" are the same fact, more direct than the
    source-diff heuristic `_head_survival` uses.
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

    proxy_kind: Optional[str] = None
    try:
        w3 = L._w3(opts.rpc_url)
        proxy_kind = L.resolve_implementation(w3, opts.address).get("proxy_kind")
    except Exception as exc:  # noqa: BLE001 - fallback simply stays disarmed
        # Not silent: a transient RPC failure here (rate limit, timeout) means
        # the immutable-clone fallback never gets a chance to run for THIS
        # scan, and every affected finding's report would otherwise show only
        # the unrelated HEAD-based reason with no trace of why the clone check
        # was skipped. Emitted, not raised - the HEAD-based liveness path
        # below is unaffected and still runs.
        proxy_kind = None
        emit_event("warn", message=f"could not resolve proxy kind for "
                                   f"{opts.address} ({type(exc).__name__}: {exc}); "
                                   f"immutable-clone liveness fallback disarmed "
                                   f"for this scan")

    # Capability 17: the settings the deployment was ACTUALLY built with, if it
    # is verified. Fetched once per scan (one address, immutable per address),
    # and every field falls back to the previous guess when unknown - so an
    # unverified contract behaves exactly as it did before this existed.
    build = VER.settings_for(opts.address)
    emit_event("info", message=f"build settings for {opts.address}: "
                               f"{VER.describe(build)}")
    _runs = build["optimize_runs"] if build["optimize_runs"] is not None \
        else DEFAULT_OPTIMIZE_RUNS
    _bc = {"optimize_runs": _runs, "optimize": build["optimize"],
           "evm_version": build["evm_version"],
           "compiler_version": build["compiler_version"]}

    head_cache: dict[str, tuple[str, str]] = {}
    clone_cache: dict[str, tuple[str, str]] = {}   # keyed by regression commit sha
    for f in findings:
        key = f"{f.file}:{f.contract}"
        if key not in head_cache:
            try:
                runtime = _runtime_bytecode(head_wt.path, f.file, f.contract, **_bc)
                if not runtime:
                    head_cache[key] = (V.UNKNOWN, "contract not present at HEAD, or it does "
                                                  "not compile to runtime bytecode")
                else:
                    res = L.check_against_artifact(opts.address, runtime,
                                                   rpc_url=opts.rpc_url)
                    head_cache[key] = (res.verdict, res.reason)
            except Exception as exc:  # noqa: BLE001
                head_cache[key] = (V.UNKNOWN, f"{type(exc).__name__}: {exc}"[:200])
        f.liveness, f.liveness_reason = head_cache[key]

        if (f.liveness != V.LIVE and proxy_kind == "eip1167-clone"
                and f.commit and cur_wt is not None and cache is not None):
            ck = f.commit
            if ck not in clone_cache:
                try:
                    _checkout(cur_wt, ck, emit_event)
                    spec = H.detect_env(cur_wt.path)
                    ok, cause, _detail = H.install(spec, cache)
                    if not ok:
                        clone_cache[ck] = (V.UNKNOWN,
                                           f"regression-commit env unavailable ({cause})")
                    else:
                        runtime = _runtime_bytecode(cur_wt.path, f.file,
                                                    f.contract, **_bc)
                        if not runtime:
                            clone_cache[ck] = (V.UNKNOWN, "regression commit does not "
                                                          "compile to runtime bytecode")
                        else:
                            res = L.check_against_artifact(opts.address, runtime,
                                                           rpc_url=opts.rpc_url)
                            clone_cache[ck] = (res.verdict, res.reason)
                except Exception as exc:  # noqa: BLE001
                    clone_cache[ck] = (V.UNKNOWN, f"{type(exc).__name__}: {exc}"[:200])
            verdict, reason = clone_cache[ck]
            if verdict == V.LIVE:
                f.liveness = V.LIVE
                f.liveness_reason = (
                    "matched the REGRESSION COMMIT's own build, not current HEAD "
                    "(deployed target is an immutable EIP-1167 clone; a later source "
                    f"fix cannot reach it): {reason}")
                if f.survives_to_head is not True:
                    V.update_survival(f, True)

        f.evidence.liveness = f.liveness
        V.classify(f)


def _runtime_bytecode(root: Path, rel: str, contract: str,
                      optimize_runs: Optional[int] = None,
                      *, optimize: Optional[bool] = None,
                      evm_version: Optional[str] = None,
                      compiler_version: Optional[str] = None) -> Optional[str]:
    """`solc --bin-runtime` for one contract in a checkout. Build config only.

    `optimize_runs` matters for liveness and nothing else: deployed bytecode was
    produced with whatever optimizer setting the project used, and comparing
    against an unoptimized build guarantees a mismatch that 11-R3 must then
    report as UNKNOWN. Passing the project's own setting is the one cheap thing
    that can turn an uninformative UNKNOWN into a real answer.

    11-L3 (found alongside 11-L2, same session): this used to invoke plain
    `solc` on PATH with no version pin at all, trusting whatever solc-select's
    AMBIENT global version happened to be at that exact moment - which is
    whatever the rule-compile path (`_shared._compile_attempt`) last switched
    it to, via `SOLC_VERSION`, for a COMPLETELY unrelated file. Measured: on
    the real 88mph pair (`contracts/NFT.sol`, `pragma solidity 0.5.17`), by the
    time `_attach_liveness`'s fallback ran, the ambient compiler was 0.8.4 -
    solc's own error was explicit ("Source file requires different compiler
    version") but nothing surfaced it; the caller only ever saw a bare `None`.
    Now pins the SAME way `_compile_attempt` does for an exact pragma pin - via
    the `SOLC_VERSION` env var, which the solc-select shim itself reads (not
    merely crytic-compile's own internal selection) - so this compile is
    correct regardless of what any other compile in this process last touched.
    A caret/range pragma (rare for the single-file, already-resolved-pragma
    case this function is used for) falls through to the still-ambient
    compiler unchanged, matching this function's prior behaviour exactly for
    that case.
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
    # Capability 17. `optimize` is a TRI-state, and the distinction is
    # load-bearing: None means "not known, keep the historical behaviour of
    # optimizing whenever runs were supplied", while False means a verified
    # deployment says the optimizer was OFF. Measured on WETH9
    # (optimizer.enabled == False): passing --optimize there rebuilds bytecode
    # the deployment never had, so liveness could only ever answer UNKNOWN.
    want_optimize = optimize if optimize is not None else (optimize_runs is not None)
    if want_optimize:
        cmd += ["--optimize"]
        if optimize_runs is not None:
            cmd += ["--optimize-runs", str(optimize_runs)]
    # evmVersion was never set at all before this. It is the most invisible of
    # the three settings: a contract built for `istanbul` and rebuilt under a
    # modern compiler's default differs in the opcodes available (PUSH0), so
    # the hashes cannot match however correct everything else is.
    if evm_version:
        cmd += ["--evm-version", str(evm_version)]

    env = dict(os.environ)
    # A verified compiler version is stronger evidence than the file's own
    # pragma: the pragma says what was ALLOWED, the verification record says
    # what was actually USED (a `^0.8.0` file may be deployed by any 0.8.x).
    pin = compiler_version or H.exact_pin(
        _shared.source_pragma_expr(Path(root) / rel))
    if pin:
        env["SOLC_VERSION"] = pin

    proc = subprocess.run(
        [*cmd, "--combined-json", "bin-runtime", rel],
        cwd=str(root), capture_output=True, text=True, encoding="utf-8", errors="replace", env=env,
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


def _nothing_compared(cov: Coverage, scope: dict) -> Optional[str]:
    """Why this scan compared no Solidity at all, or None if it compared some.

    HIST-L1 one level down. Coverage already refuses to let "0 findings over 3
    analysed pairs" read like "0 findings over 40". It did NOT catch the case
    where every pair was analysed and each contained nothing to analyse:
    `pairs_analyzed` hits 100%, `files_total` stays 0, and the report looks
    complete. That is exactly what the web app's `contracts` default produced
    against a repository whose Solidity lives in `src/`.
    """
    if cov.files_total:
        return None
    roots = scope.get("roots")
    if scope.get("mode") == "explicit":
        return (f"No Solidity file was compared: no commit in this range "
                f"modified a .sol file under {_scope_roots_text(scope)}. Check the "
                f"subdirectory - a scope that matches nothing produces a quiet "
                f"result that is UNMEASURED, not clean.")
    if not roots:
        return (f"No Solidity file was compared: {scope.get('reason', '')}. "
                f"Nothing was measured, so nothing here is evidence about this "
                f"repository's code.")
    return (f"No Solidity file was compared: no commit in this range modified a "
            f"file under {', '.join(r or 'the repository root' for r in roots)}. "
            f"Widen the commit count, or name a subdirectory explicitly.")


def _scope_roots_text(scope: dict) -> str:
    roots = scope.get("roots") or [""]
    return ", ".join((r + "/") if r else "the repository root" for r in roots)


def _report(opts: ScanOptions, cov: Coverage, findings: list[V.Finding],
            started: float, head: Optional[str], scope: Optional[dict] = None,
            exposure: Optional[list[dict]] = None) -> dict:
    scope = scope or {}
    confirmed = [f for f in findings if f.verdict == V.CONFIRMED]
    candidates = [f for f in findings if f.verdict == V.CANDIDATE]
    by_rule: dict[str, int] = {}
    for f in findings:
        by_rule[f.rule_id] = by_rule.get(f.rule_id, 0) + 1
    return {
        "repo": str(opts.repo),
        "head": head,
        "address": opts.address,
        # WHAT WAS LOOKED AT. Shipped with the report rather than left to the
        # caller to infer, so "0 findings" can never be read without it.
        "scope": scope,
        "nothing_compared": _nothing_compared(cov, scope),
        # HOW LONG IT TOOK AND WHAT THAT SUPPORTS (SIZE-L1). Carried in the
        # report for the same reason `scope` is: so the CLI and the web app
        # quote one set of numbers. `remaining` is normally 0 on a finished
        # run and non-zero only when it was cancelled - which is exactly when
        # someone wants to know what the rest would have cost.
        "sizing": SZ.from_pair_records(cov.pair_records).as_dict(
            max(cov.pairs_total - cov.pairs_analyzed - cov.pairs_skipped, 0)),
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
        # `address_used` rides on each finding so DEEPEN-1 can tell "no address
        # was supplied" from "an address was supplied and did not match" - two
        # different gaps with two different next steps, indistinguishable from
        # `liveness: UNKNOWN` alone.
        "findings": [{**f.as_dict(), "address_used": bool(opts.address)}
                     for f in findings],
        "rule_titles": RULE_TITLES,
        # Shipped with the report so every consumer shows the same qualification
        # next to a LIVE verdict rather than inventing its own wording.
        "live_caveat": _LIVE_CAVEAT,
        # Capability 13: NEVER merged into `findings` or the verdict model -
        # a live "is the window still open" signal, independent of whether a
        # historical regression was found. Empty unless --check-exposure was
        # passed with --address.
        "exposure": exposure or [],
    }
