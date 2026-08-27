"""Deployment anchoring (ANCHOR-1) - which commit built the code that is live?

The normal pipeline runs forwards: walk history, find a regression, then ask
whether it is live. That needs a deployed address per finding, which a user
rarely has, so almost everything correctly caps at CANDIDATE for want of the
liveness field.

This inverts it. Given ONE address, fetch its runtime bytecode and search
history for the commit whose build matches it:

    address -> runtime bytecode -> the commit that produced it

Everything downstream changes character once that is known. "Does this
regression survive to HEAD" becomes "is this regression on the deployed side of
the anchor", answerable from git alone. One address anchors an entire
trajectory instead of one finding.

WHAT MAKES THIS TRUSTWORTHY IS THAT IT REUSES THE DECISIVE GATE, not a new one.
The comparison is `liveness.normalize` - the same CBOR-metadata stripping,
immutable masking and keccak comparison that capability 11 already uses, and
that CHARTER names the decisive gate. This module adds a search over commits;
it does not add a second opinion about what "the same code" means.

COST, STATED PLAINLY. One compile per candidate commit. Bytecode equality is
not monotonic over history, so this cannot bisect - a linear scan is the honest
implementation. Callers bound it with `limit`, and `find_anchor` reports how
many commits it actually examined so a null result is never mistaken for "not
deployed from this repository" when it only means "not in the window searched".
"""

from __future__ import annotations

from pathlib import Path
from typing import Callable, Optional

from . import history as H
from . import liveness as L

# Outcomes. `NO_MATCH` deliberately does NOT claim the contract is foreign to
# the repository - only that nothing in the searched window matched.
ANCHORED = "ANCHORED"
NO_MATCH = "NO_MATCH"
UNRUNNABLE = "UNRUNNABLE"


def commits_touching(repo, rel: str, limit: int = 40) -> list[str]:
    """Commits that changed `rel`, newest first.

    Only these are anchor candidates: a commit that did not touch the file
    cannot have changed its bytecode, so compiling it would spend a compile to
    re-derive a hash already known. `--follow` so a renamed file keeps its
    history (the 88mph case renamed `contracts/NFT.sol` and lost it otherwise).
    """
    out = H._git(repo, "log", f"-{int(limit)}", "--follow", "--format=%H",
                 "--", rel)
    return [line.strip() for line in (out or "").splitlines() if line.strip()]


def deployed_fingerprint(address: str, rpc_url: Optional[str] = None,
                         block: str | int = "latest") -> dict:
    """Normalized runtime bytecode of whatever actually executes at `address`.

    Resolves proxies first (EIP-1967, beacon, EIP-1167 clone, zeppelinos), so
    anchoring a proxy address anchors its IMPLEMENTATION - which is the code a
    commit could have built. Anchoring the proxy's own dispatcher bytecode would
    match nothing in a normal repository and look like a failed search.
    """
    w3 = L._w3(rpc_url)
    resolved = L.resolve_implementation(w3, address, block=block)
    target = resolved.get("target")
    if not target:
        return {"ok": False, "reason": f"no code at {address} "
                                       f"({resolved.get('proxy_kind')})",
                "resolved": resolved}
    code = w3.eth.get_code(target, block_identifier=block)
    if not code:
        return {"ok": False, "reason": f"no code at resolved target {target}",
                "resolved": resolved}
    norm = L.normalize(bytes(code))
    return {"ok": True, "resolved": resolved, "target": target,
            "normalized_keccak": norm["normalized_keccak"],
            "code_len": len(code)}


def find_anchor(
    repo: Path,
    address: str,
    rel: str,
    contract: str,
    *,
    rpc_url: Optional[str] = None,
    limit: int = 40,
    optimize_runs: Optional[int] = 200,
    compile_at: Optional[Callable[[Path, str, str, Optional[int]], Optional[str]]] = None,
    on_event: Optional[Callable[[dict], None]] = None,
) -> dict:
    """Search `repo`'s history for the commit whose build of `contract` matches
    what is deployed at `address`.

    `compile_at(worktree_root, rel, contract, optimize_runs) -> hex runtime`
    is injected rather than imported so this module has no dependency on
    `scan.py` (which imports plenty) and so the search is testable without a
    compiler. `scan._runtime_bytecode` is the production implementation.

    Only commits that TOUCHED `rel` are candidates: a commit that did not change
    the file cannot have changed its bytecode, so compiling it would burn a
    compile to re-derive a hash already known.
    """
    def emit(kind: str, **kw):
        if on_event:
            try:
                on_event({"kind": kind, **kw})
            except Exception:  # noqa: BLE001
                pass

    out: dict = {"status": UNRUNNABLE, "address": address, "file": rel,
                 "contract": contract, "examined": 0, "candidates": 0,
                 "commit": None, "reason": ""}

    fp = deployed_fingerprint(address, rpc_url=rpc_url)
    if not fp["ok"]:
        out["reason"] = fp["reason"]
        return out
    out["target"] = fp["target"]
    out["proxy_kind"] = fp["resolved"].get("proxy_kind")
    emit("anchor-target", target=fp["target"], proxy_kind=out["proxy_kind"])

    if compile_at is None:
        from .scan import _runtime_bytecode as compile_at  # local: avoids a cycle

    try:
        commits = commits_touching(repo, rel, limit=limit)
    except Exception as exc:  # noqa: BLE001
        out["reason"] = f"could not list history for {rel}: {exc}"[:200]
        return out

    out["candidates"] = len(commits)
    if not commits:
        out["reason"] = f"no commit in the last {limit} touched {rel}"
        return out

    # Mirror-clone first, exactly as `scan` does: every checkout below then
    # happens in a repository we own, and the caller's tree is only ever read
    # (CHARTER rule 5 / WALK-L6). Anchoring must not be the one path that
    # writes worktree metadata into someone else's .git.
    scratch = Path(repo).resolve().parent / ".anchor-scratch"
    origin = H.mirror_clone(repo, scratch / "origin.git")
    wt = H.Worktree(origin, scratch / "wt")

    cache = scratch / "cache"
    for i, sha in enumerate(commits, 1):
        emit("anchor-try", index=i, total=len(commits), commit=sha[:12])
        try:
            stripped = wt.checkout(sha)
            if stripped:  # SEC-L1: notable, but the checkout still proceeds -
                          # a distinct event, not "anchor-skip" (which means
                          # this commit was abandoned; this one was not).
                emit("anchor-warn", commit=sha[:12],
                    reason=f"removed {len(stripped)} symlink(s) from the "
                           f"target's own tracked tree before reading any file")
            # A commit's own dependency tree, or nothing compiles and every
            # answer below is vacuous. Cached by manifest hash, so consecutive
            # commits that share a package.json pay for one install between
            # them, not one each.
            spec = H.detect_env(wt.path)
            ok, cause, detail = H.install(spec, cache)
            if not ok:
                emit("anchor-skip", commit=sha[:12], reason=f"{cause}: {detail}"[:120])
                continue
            _bind_build_config(spec)
            built = compile_at(wt.path, rel, contract, optimize_runs)
        except Exception as exc:  # noqa: BLE001
            emit("anchor-skip", commit=sha[:12], reason=str(exc)[:120])
            continue
        if not built:
            emit("anchor-skip", commit=sha[:12], reason="did not compile")
            continue
        # Counts SUCCESSFUL builds only. Counting attempts here is what let an
        # earlier version of this function report NO_MATCH over a window where
        # nothing compiled at all - the exact "a miss over uncompiled code is
        # unmeasured, not a negative" error this project documents elsewhere.
        out["examined"] += 1
        norm = L.normalize(bytes.fromhex(built.removeprefix("0x")))
        if norm["normalized_keccak"] == fp["normalized_keccak"]:
            out["status"] = ANCHORED
            out["commit"] = sha
            out["reason"] = (
                f"normalized runtime bytecode of {contract} at {sha[:12]} is "
                f"identical to the code deployed at {fp['target']}")
            emit("anchor-found", commit=sha[:12])
            return out

    if out["examined"] == 0:
        # NOT a NO_MATCH. Nothing was compared, so nothing was learned.
        out["status"] = UNRUNNABLE
        out["reason"] = (
            f"none of the {len(commits)} commit(s) touching {rel} could be "
            f"built, so no comparison was made. This says nothing about where "
            f"the deployed code came from - fix the build environment first")
        return out

    out["status"] = NO_MATCH
    out["reason"] = (
        f"no commit among the {out['examined']} successfully built (of "
        f"{len(commits)} touching {rel}, limit={limit}) matches the deployed "
        f"bytecode. This does NOT establish the contract came from elsewhere - "
        f"widen --limit, or the deployment may use compiler settings "
        f"(optimizer runs, viaIR, evmVersion) this build did not reproduce")
    return out


def _bind_build_config(spec) -> None:
    """Point the compiler at this checkout, the same way `scan` does.

    Imported lazily and kept in one place so anchoring cannot drift from the
    walker's notion of how a checkout is configured.
    """
    from .scan import _apply_build_config

    _apply_build_config(spec)
