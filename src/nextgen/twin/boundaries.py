"""Phase 3 - mine behavioural boundaries from Phase 1/2 output.

Every function here INFERS a candidate constraint from observed behaviour; it
never proves one. A boundary starts INFERRED (the pattern exists in the
sample), moves to TESTED once it holds across N>=`_MIN_SAMPLES` observations
with zero counterexamples in the same sample, and only Phase 4/6/7 (which see
a DIFFERENT sample - a second version, or a live replay) can promote it to
VALIDATED or knock it back to REJECTED. Mining alone therefore never returns a
VALIDATED boundary - that would be circular (validated by the same data that
proposed it).

Each miner is independent and best-effort: a fingerprint with too little
signal for one boundary kind simply contributes nothing for it, same
discipline as the rest of this project's "quiet != safe" rule - an empty
`mine_boundaries()` result means "nothing inferrable from this sample", not
"this contract has no constraints".
"""

from __future__ import annotations

from collections import Counter
from typing import Optional

from . import model as M

_MIN_SAMPLES = 3          # below this, a pattern is a hint, not even TESTED
_GOVERNANCE_HINT = ("propose", "vote", "queue", "execute", "cancel", "timelock",
                    "schedule", "grant", "revoke", "setowner", "transferownership",
                    "settimelock", "setadmin")


def mine_boundaries(fingerprints: dict[str, M.FunctionFingerprint],
                    transfers: list[M.TransferEvent],
                    traces: Optional[dict[str, M.Trace]] = None
                    ) -> list[M.Boundary]:
    traces = traces or {}
    out: list[M.Boundary] = []
    out += _mine_authorization(fingerprints)
    out += _mine_conservation(fingerprints, transfers)
    out += _mine_accounting(fingerprints, traces)
    out += _mine_replay_protection(fingerprints, traces)
    out += _mine_state_machine(fingerprints, traces)
    out += _mine_oracle_freshness(fingerprints, traces)
    out += _mine_governance(fingerprints)
    out += _mine_collateral_withdrawal(fingerprints)
    return out


# --- AUTHORIZATION ----------------------------------------------------------- #

def _mine_authorization(fps: dict[str, M.FunctionFingerprint]) -> list[M.Boundary]:
    """A selector whose EVERY successful call came from a small, fixed caller
    set (`FunctionFingerprint.caller_exclusive`) is a candidate access-control
    boundary. TESTED once at least `_MIN_SAMPLES` successful calls agree and no
    call from outside that set ever succeeded."""
    out = []
    for sel, fp in fps.items():
        excl = fp.caller_exclusive
        if not excl:
            continue
        status = M.TESTED if fp.n_success >= _MIN_SAMPLES else M.INFERRED
        b = M.Boundary(
            kind=M.AUTHORIZATION,
            statement=f"{sel} succeeds only when called by "
                     f"{{{', '.join(sorted(excl))}}} ({fp.n_success} sample(s))",
            selector=sel, status=status, support=list(fp.example_success),
            detail={"callers": sorted(excl), "n_success": fp.n_success,
                    "n_revert": fp.n_revert})
        out.append(b)
    return out


# --- CONSERVATION ------------------------------------------------------------- #

def _mine_conservation(fps: dict[str, M.FunctionFingerprint],
                       transfers: list[M.TransferEvent]) -> list[M.Boundary]:
    """A selector whose successful calls NEVER move a token out without a
    matching in (or vice versa) across the sample is a candidate conservation
    boundary - e.g. a swap/deposit/withdraw that always balances per-token.
    Coarse: aggregated in/out COUNTS per fingerprint, not per-call amounts (a
    per-call amount check needs the trace-level transfer list, which Phase 4/7
    re-derive with the actual replay at hand)."""
    out = []
    for sel, fp in fps.items():
        if fp.n_success < _MIN_SAMPLES:
            continue
        moves = fp.transfers_in or fp.transfers_out
        if not moves:
            continue
        one_sided = bool(fp.transfers_in) != bool(fp.transfers_out)
        status = M.TESTED if fp.n_success >= _MIN_SAMPLES else M.INFERRED
        if one_sided:
            statement = (f"{sel} only ever moves tokens "
                        f"{'in' if fp.transfers_in else 'out'} "
                        f"({fp.n_success} sample(s)) - a call that reversed "
                        f"this direction would be a conservation violation")
        else:
            statement = (f"{sel} moves tokens both in ({fp.transfers_in}) and "
                        f"out ({fp.transfers_out}) across {fp.n_success} "
                        f"sample(s)")
        out.append(M.Boundary(
            kind=M.CONSERVATION, statement=statement, selector=sel,
            status=status, support=list(fp.example_success),
            detail={"transfers_in": fp.transfers_in,
                    "transfers_out": fp.transfers_out, "one_sided": one_sided}))
    return out


# --- ACCOUNTING --------------------------------------------------------------- #

def _mine_accounting(fps: dict[str, M.FunctionFingerprint],
                     traces: dict[str, M.Trace]) -> list[M.Boundary]:
    """A storage slot that changes on EVERY successful call to a selector that
    also emits a Transfer is a candidate supply/accounting slot - the classic
    "mint/burn touch a balance AND the total-supply-like slot together" shape,
    observed from the trace's own state diff rather than assumed from a name."""
    out = []
    for sel, fp in fps.items():
        if not fp.storage_slots_written or not (fp.transfers_in or fp.transfers_out):
            continue
        if fp.n_success < _MIN_SAMPLES:
            continue
        out.append(M.Boundary(
            kind=M.ACCOUNTING,
            statement=f"{sel} writes {len(fp.storage_slots_written)} storage "
                     f"slot(s) on every sampled successful call that also moves "
                     f"a token - candidate accounting slot(s)",
            selector=sel, status=M.TESTED, support=list(fp.example_success),
            detail={"slots": sorted(fp.storage_slots_written)[:10]}))
    return out


# --- REPLAY_PROTECTION -------------------------------------------------------- #

def _mine_replay_protection(fps: dict[str, M.FunctionFingerprint],
                            traces: dict[str, M.Trace]) -> list[M.Boundary]:
    """A slot written by every successful call to a selector, whose written
    value is DIFFERENT every time (never repeats within the sample) across at
    least `_MIN_SAMPLES` calls, is a candidate nonce/replay-guard slot."""
    out = []
    for sel, fp in fps.items():
        if fp.n_success < _MIN_SAMPLES:
            continue
        by_slot: dict[str, list[str]] = {}
        for tx_hash in fp.example_success:
            tr = traces.get(tx_hash)
            if not tr:
                continue
            sd = tr.state_diff.get(tr.tx.to, {})
            for slot, (pre, post) in (sd.get("storage") or {}).items():
                by_slot.setdefault(slot, []).append(post)
        for slot, posts in by_slot.items():
            if len(posts) >= min(_MIN_SAMPLES, len(fp.example_success)) and \
                    len(set(posts)) == len(posts):
                out.append(M.Boundary(
                    kind=M.REPLAY_PROTECTION,
                    statement=f"{sel} writes a distinct value to slot {slot} "
                             f"on every sampled call - candidate replay/nonce "
                             f"guard (no repeated value observed)",
                    selector=sel, status=M.INFERRED,
                    support=list(fp.example_success),
                    detail={"slot": slot, "n_distinct": len(set(posts))}))
    return out


# --- STATE_MACHINE ------------------------------------------------------------ #

def _mine_state_machine(fps: dict[str, M.FunctionFingerprint],
                        traces: dict[str, M.Trace]) -> list[M.Boundary]:
    """Two selectors that write the SAME slot but are never both successful in
    a way that suggests interleaving without a guard - here approximated as: a
    slot written by selector A's successes is later read/branched on
    (represented by selector B failing whenever that slot holds a value A
    wrote) is out of reach without per-slot semantic decoding. What IS mineable
    without semantics: a selector with a high revert rate driven by calldata
    shape rather than caller (i.e. NOT an authorization boundary) is a
    candidate state-gated function - it accepts some states and rejects
    others."""
    out = []
    for sel, fp in fps.items():
        if fp.n_total < _MIN_SAMPLES or fp.n_revert == 0 or fp.n_success == 0:
            continue
        if fp.caller_exclusive:
            continue        # already explained by AUTHORIZATION - don't double-count
        shared_callers = fp.callers_success & fp.callers_revert
        if not shared_callers:
            continue         # reverts explained by caller identity, not state
        out.append(M.Boundary(
            kind=M.STATE_MACHINE,
            statement=f"{sel} both succeeds and reverts for the SAME caller(s) "
                     f"({len(shared_callers)}) - rejection correlates with "
                     f"contract state, not identity; candidate state-machine gate",
            selector=sel, status=M.INFERRED,
            support=list(fp.example_success)[:3] + list(fp.example_revert)[:3],
            detail={"revert_rate": fp.revert_rate,
                    "shared_callers": sorted(shared_callers)[:6]}))
    return out


# --- ORACLE_FRESHNESS ---------------------------------------------------------- #

_ORACLE_HINT_SELECTORS = {
    "0x50d25bcd",   # latestAnswer()
    "0xfeaf968c",   # latestRoundData()
    "0x313ce567",   # decimals() - frequently colocated but not itself a read
}


def _mine_oracle_freshness(fps: dict[str, M.FunctionFingerprint],
                           traces: dict[str, M.Trace]) -> list[M.Boundary]:
    """A selector whose successful calls ALWAYS make an external staticcall to
    a target/selector matching a common price-oracle read shape is a candidate
    oracle-freshness boundary - the underlying source has no way to observe
    the staleness bound itself (that needs the oracle's own timestamp, which a
    plain call trace does not decode), so this stays INFERRED, never TESTED."""
    out = []
    for sel, fp in fps.items():
        oracle_calls = {(a, s) for a, s in fp.external_call_targets
                        if s in _ORACLE_HINT_SELECTORS}
        if not oracle_calls or fp.n_success < 1:
            continue
        out.append(M.Boundary(
            kind=M.ORACLE_FRESHNESS,
            statement=f"{sel} reads what looks like a price oracle "
                     f"({sorted(a[:10] for a, _ in oracle_calls)}) on every "
                     f"sampled successful call - staleness bound not "
                     f"observable from a call trace alone",
            selector=sel, status=M.INFERRED, support=list(fp.example_success),
            detail={"oracle_like_targets": sorted(f"{a}:{s}" for a, s in oracle_calls)}))
    return out


# --- GOVERNANCE ----------------------------------------------------------------- #

def _mine_governance(fps: dict[str, M.FunctionFingerprint]) -> list[M.Boundary]:
    """Selectors are unnamed (we only ever see a 4-byte hash), so this cannot
    match a function NAME. What is mineable: a SMALL caller set (a candidate
    multisig/timelock) that is the exclusive successful caller of MULTIPLE
    distinct selectors is a stronger governance signal than any one
    AUTHORIZATION boundary alone - the same small set gatekeeping several
    functions looks like a privileged role, not a per-function owner check."""
    by_caller_set: dict[frozenset, list[str]] = {}
    for sel, fp in fps.items():
        excl = fp.caller_exclusive
        if not excl:
            continue
        by_caller_set.setdefault(frozenset(excl), []).append(sel)
    out = []
    for callers, sels in by_caller_set.items():
        if len(sels) < 2:
            continue
        out.append(M.Boundary(
            kind=M.GOVERNANCE,
            statement=f"{{{', '.join(sorted(callers))}}} is the exclusive "
                     f"successful caller of {len(sels)} distinct selectors "
                     f"{sorted(sels)} - candidate privileged/governance role",
            status=M.INFERRED, detail={"callers": sorted(callers),
                                       "selectors": sorted(sels)}))
    return out


# --- COLLATERAL / WITHDRAWAL ---------------------------------------------------- #

def _mine_collateral_withdrawal(fps: dict[str, M.FunctionFingerprint]
                                ) -> list[M.Boundary]:
    """A selector whose successful calls move tokens OUT of the address and
    also write storage is a candidate withdrawal path with an accounting
    slot behind it (the slot IS the accounting boundary above; this records
    the withdrawal-specific framing separately since Phase 5/7 mutate/check
    withdrawal paths with their own kind of counterfactual: draining beyond
    the recorded balance)."""
    out = []
    for sel, fp in fps.items():
        if fp.transfers_out == 0 or fp.n_success < _MIN_SAMPLES:
            continue
        kind = M.COLLATERAL if fp.transfers_in and fp.transfers_out else M.WITHDRAWAL
        out.append(M.Boundary(
            kind=kind,
            statement=f"{sel} releases tokens on {fp.n_success} sampled "
                     f"successful call(s)"
                     + (" and also accepts deposits - candidate collateral path"
                        if kind == M.COLLATERAL else " - candidate withdrawal path"),
            selector=sel, status=M.TESTED if fp.n_success >= _MIN_SAMPLES else M.INFERRED,
            support=list(fp.example_success),
            detail={"transfers_out": fp.transfers_out,
                    "transfers_in": fp.transfers_in,
                    "storage_slots": sorted(fp.storage_slots_written)[:10]}))
    return out


def summarize(boundaries: list[M.Boundary]) -> str:
    lines = ["MINED BOUNDARIES (Phase 3)", "=" * 27, ""]
    by_kind: dict[str, list[M.Boundary]] = {}
    for b in boundaries:
        by_kind.setdefault(b.kind, []).append(b)
    for kind in sorted(by_kind):
        lines.append(f"[{kind}]  ({len(by_kind[kind])})")
        for b in by_kind[kind]:
            lines.append(f"  ({b.status})  {b.statement}")
    return "\n".join(lines)
