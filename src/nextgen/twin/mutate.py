"""Phase 5 - counterfactual variants of a REAL trace.

Every mutation still carries the base tx's real `{to, data}` shape - what
changes is exactly one thing (actor, a boundary value, ordering/timing,
permission state, or a dependency's balance). `calls` is the exact
`{from,to,value,data}` sequence Phase 6 submits to the fork, in submission
order; `state_overrides` is applied via `anvil_setStorageAt` BEFORE the calls
run; `detail` carries kind-specific instructions Phase 6 interprets (a time
jump, a snapshot/revert boundary) that don't fit the call/override shape.

Nothing here is a weaponised artifact: every call targets the SAME
already-deployed contract at `tx.to`, on an isolated local fork, and nothing
is ever broadcast (charter carve-out, 2026-08-28 amendment).

Two kinds are honestly weaker than the rest, documented rather than hidden:
CALLBACK_INSERT approximates re-entrancy with a same-sender repeat call
rather than deploying an attacker contract (Phase 6 has no contract-deploy
step); ORACLE_STATE and CROSS_CONTRACT_VARIATION can only manipulate what a
local fork actually exposes (time, balances, EIP-1967's own admin slot) -
not an arbitrary dependency's internal storage layout, which is not
decodable without its own ABI/source.
"""

from __future__ import annotations

from typing import Optional

from .rpc import EIP1967_ADMIN
from . import model as M

_UNPRIVILEGED = "0x2222222222222222222222222222222222222222"
_SECOND_UNPRIVILEGED = "0x3333333333333333333333333333333333333333"
_BOUNDARY_WORDS = ("0" * 64,                                    # zero
                   "f" * 64,                                    # uint256 max
                   "0" * 63 + "1")                               # one


def generate_mutations(tx: M.TxRecord, trace: Optional[M.Trace],
                       ctx: Optional[dict] = None,
                       changed_selectors: Optional[set] = None
                       ) -> list[M.Mutation]:
    """`ctx` (optional) may carry `boundaries: list[Boundary]` (this
    selector's mined constraints, to target BOUNDARY_VALUE / PERMISSION_CHANGE
    / ORACLE_STATE precisely) and `related_txs: list[TxRecord]` (other real
    txs against the same address, for REORDER). Every mutation is weighted by
    proximity to `changed_selectors` (Phase 4 output) so Phase 6 spends its
    replay budget where behaviour is known to have moved."""
    ctx = ctx or {}
    changed = changed_selectors or set()
    boundaries: list[M.Boundary] = ctx.get("boundaries") or []
    related: list[M.TxRecord] = ctx.get("related_txs") or []
    near_change = tx.selector in changed

    out: list[M.Mutation] = []
    out += _actor_substitution(tx, near_change)
    out += _boundary_value(tx, boundaries, near_change)
    out += _repetition(tx, near_change)
    out += _reorder(tx, related, near_change)
    out += _delay(tx, near_change)
    out += _callback_insert(tx, trace, near_change)
    out += _state_timing(tx, boundaries, near_change)
    out += _oracle_state(tx, boundaries, near_change)
    out += _permission_change(tx, boundaries, near_change)
    out += _cross_contract_variation(tx, trace, near_change)
    return out


def _call(tx: M.TxRecord, *, sender: str = None, data: str = None,
         value: int = None) -> dict:
    return {"from": sender or tx.sender, "to": tx.to,
            "value": value if value is not None else tx.value,
            "data": data if data is not None else tx.input}


def _w(base: float, near: bool) -> float:
    return base * (2.0 if near else 1.0)


# --- ACTOR_SUBSTITUTION ------------------------------------------------------- #

def _actor_substitution(tx: M.TxRecord, near: bool) -> list[M.Mutation]:
    if tx.sender.lower() == _UNPRIVILEGED:
        return []          # the real sender already IS the probe address
    return [M.Mutation(
        kind=M.ACTOR_SUBSTITUTION, base_tx=tx.hash, selector=tx.selector,
        statement=f"replay {tx.selector} from an unrelated, unprivileged "
                 f"address ({_UNPRIVILEGED}) instead of the real sender "
                 f"({tx.sender})",
        calls=[_call(tx, sender=_UNPRIVILEGED)], fork_block=max(tx.block - 1, 0),
        weight=_w(1.0, near))]


# --- BOUNDARY_VALUE ------------------------------------------------------------ #

def _boundary_value(tx: M.TxRecord, boundaries: list[M.Boundary], near: bool
                    ) -> list[M.Mutation]:
    """No ABI, so this mutates the LAST 32-byte calldata word (the common
    trailing-argument position for an amount/id) to each of a small set of
    boundary values, rather than a decoded, named argument."""
    if len(tx.input) < 10 + 64:
        return []
    head, tail = tx.input[:-64], tx.input[-64:]
    out = []
    for word in _BOUNDARY_WORDS:
        if word == tail:
            continue
        out.append(M.Mutation(
            kind=M.BOUNDARY_VALUE, base_tx=tx.hash, selector=tx.selector,
            statement=f"replay {tx.selector} with its trailing calldata word "
                     f"forced to 0x{word[:16]}... (boundary value) instead of "
                     f"the real 0x{tail[:16]}...",
            calls=[_call(tx, data=head + word)], fork_block=max(tx.block - 1, 0),
            weight=_w(0.8, near), detail={"original_word": tail, "new_word": word}))
    return out


# --- REPETITION --------------------------------------------------------------- #

def _repetition(tx: M.TxRecord, near: bool) -> list[M.Mutation]:
    return [M.Mutation(
        kind=M.REPETITION, base_tx=tx.hash, selector=tx.selector,
        statement=f"replay {tx.selector} twice in immediate succession from "
                 f"the same sender - tests idempotency / replay protection",
        calls=[_call(tx), _call(tx)], fork_block=max(tx.block - 1, 0),
        weight=_w(0.9, near))]


# --- REORDER -------------------------------------------------------------------- #

def _reorder(tx: M.TxRecord, related: list[M.TxRecord], near: bool
            ) -> list[M.Mutation]:
    """Needs a second real tx to reorder against. Best-effort: the nearest
    prior related tx to the SAME address, swapped to run AFTER `tx` instead of
    before."""
    prior = [r for r in related if r.block <= tx.block and r.hash != tx.hash]
    if not prior:
        return []
    other = max(prior, key=lambda r: (r.block, r.tx_index))
    return [M.Mutation(
        kind=M.REORDER, base_tx=tx.hash, selector=tx.selector,
        statement=f"replay {other.selector} (real tx {other.hash[:10]}) AFTER "
                 f"{tx.selector} instead of before - tests an ordering "
                 f"assumption",
        calls=[_call(tx), _call(other)], fork_block=max(min(tx.block, other.block) - 1, 0),
        weight=_w(0.6, near), detail={"other_tx": other.hash})]


# --- DELAY ---------------------------------------------------------------------- #

def _delay(tx: M.TxRecord, near: bool, *, seconds: int = 86400 * 30) -> list[M.Mutation]:
    return [M.Mutation(
        kind=M.DELAY, base_tx=tx.hash, selector=tx.selector,
        statement=f"advance the fork's clock by {seconds}s (~{seconds // 86400}d), "
                 f"then replay {tx.selector} - tests a time-based assumption "
                 f"(vesting, cooldown, deadline)",
        calls=[_call(tx)], fork_block=max(tx.block - 1, 0),
        weight=_w(0.5, near), detail={"delay_seconds": seconds})]


# --- CALLBACK_INSERT (documented approximation) --------------------------------- #

def _callback_insert(tx: M.TxRecord, trace: Optional[M.Trace], near: bool
                     ) -> list[M.Mutation]:
    """Approximation, stated plainly: a true callback-insert deploys an
    attacker contract implementing the callback the base call would invoke
    (e.g. an ERC-777/721 hook) and only THEN replays. Phase 6 has no
    contract-deploy step, so this instead re-issues the exact same call
    immediately after itself without an intervening state settle - the
    coarsest available proxy for "what if this call re-entered itself". A
    call tree with NO external calls at all gets no mutation here, since a
    same-call repeat tells nothing a REPETITION mutation didn't already."""
    if not trace or not trace.call_tree or not trace.external_calls():
        return []
    return [M.Mutation(
        kind=M.CALLBACK_INSERT, base_tx=tx.hash, selector=tx.selector,
        statement=f"{tx.selector} makes {len(trace.external_calls())} external "
                 f"call(s) mid-execution; replay it immediately followed by "
                 f"itself again with no settle in between (re-entrancy-shaped "
                 f"proxy - not a deployed callback contract)",
        calls=[_call(tx), _call(tx)], fork_block=max(tx.block - 1, 0),
        weight=_w(0.9, near),
        detail={"external_calls": trace.external_calls()[:5],
                "approximation": "same-sender immediate repeat, not a real "
                                 "callback contract"})]


# --- STATE_TIMING ----------------------------------------------------------------- #

def _state_timing(tx: M.TxRecord, boundaries: list[M.Boundary], near: bool
                  ) -> list[M.Mutation]:
    """For a REPLAY_PROTECTION boundary on this selector (a slot Phase 3
    inferred changes every call), force that slot BACKWARD to an earlier
    observed value before replaying - tests whether the guard is actually
    enforced, or just happens to always advance in the honest sample."""
    out = []
    for b in boundaries:
        if b.kind != M.REPLAY_PROTECTION or b.selector != tx.selector:
            continue
        slot = b.detail.get("slot")
        if not slot:
            continue
        out.append(M.Mutation(
            kind=M.STATE_TIMING, base_tx=tx.hash, selector=tx.selector,
            statement=f"force replay-guard slot {slot} back to its zero value "
                     f"before replaying {tx.selector} - tests whether the "
                     f"guard is enforced or merely observed to advance",
            calls=[_call(tx)], fork_block=max(tx.block - 1, 0),
            state_overrides={tx.to: {slot: "0x" + "0" * 64}},
            weight=_w(0.7, near), detail={"slot": slot}))
    return out


# --- ORACLE_STATE ------------------------------------------------------------------ #

def _oracle_state(tx: M.TxRecord, boundaries: list[M.Boundary], near: bool
                  ) -> list[M.Mutation]:
    """A forked oracle's own stored `updatedAt` does not advance with the
    fork's local block.timestamp - so jumping the fork's clock forward
    WITHOUT touching the oracle genuinely reproduces "the reading is now
    stale relative to now", exactly as it would on a real chain if the oracle
    stopped updating. This is real, not a proxy, unlike CALLBACK_INSERT."""
    out = []
    for b in boundaries:
        if b.kind != M.ORACLE_FRESHNESS or b.selector != tx.selector:
            continue
        out.append(M.Mutation(
            kind=M.ORACLE_STATE, base_tx=tx.hash, selector=tx.selector,
            statement=f"advance the fork's clock by 7 days without touching "
                     f"the oracle at {b.detail.get('oracle_like_targets')} - "
                     f"its stored update timestamp does not move with the "
                     f"fork's clock, reproducing a stale read",
            calls=[_call(tx)], fork_block=max(tx.block - 1, 0),
            weight=_w(0.7, near), detail={"delay_seconds": 86400 * 7,
                                          "oracle_targets": b.detail.get("oracle_like_targets")}))
    return out


# --- PERMISSION_CHANGE -------------------------------------------------------------- #

def _permission_change(tx: M.TxRecord, boundaries: list[M.Boundary], near: bool
                       ) -> list[M.Mutation]:
    """Only the EIP-1967 admin slot is standardised enough to target without
    an ABI. A non-proxy Ownable `_owner` slot position varies by contract
    layout and is not recoverable from a call trace alone - that gap is
    stated, not silently skipped."""
    return [M.Mutation(
        kind=M.PERMISSION_CHANGE, base_tx=tx.hash, selector=tx.selector,
        statement=f"force the EIP-1967 admin slot to the unprivileged probe "
                 f"address, then replay {tx.selector} as that address - tests "
                 f"whether admin-gating is enforced beyond that one slot",
        calls=[_call(tx, sender=_UNPRIVILEGED)], fork_block=max(tx.block - 1, 0),
        state_overrides={tx.to: {EIP1967_ADMIN:
                                 "0x" + "0" * 24 + _UNPRIVILEGED[2:]}},
        weight=_w(0.4, near),
        detail={"note": "targets the standardised EIP-1967 admin slot only; "
                        "a non-proxy owner slot is not decodable without an ABI"})]


# --- CROSS_CONTRACT_VARIATION ------------------------------------------------------- #

def _cross_contract_variation(tx: M.TxRecord, trace: Optional[M.Trace], near: bool
                              ) -> list[M.Mutation]:
    """A local fork can zero a dependency's ETH balance (real, meaningful for
    an ETH-holding counterparty) but cannot rewrite an arbitrary dependency's
    internal token/storage state without that dependency's own ABI - that is
    the same limit PERMISSION_CHANGE documents, applied to a different
    target."""
    if not trace or not trace.external_calls():
        return []
    target = trace.external_calls()[0][0]
    return [M.Mutation(
        kind=M.CROSS_CONTRACT_VARIATION, base_tx=tx.hash, selector=tx.selector,
        statement=f"zero the ETH balance of the first external dependency "
                 f"({target}) called mid-execution, then replay {tx.selector} "
                 f"- tests an implicit solvency assumption about that "
                 f"dependency",
        calls=[_call(tx)], fork_block=max(tx.block - 1, 0),
        state_overrides={}, weight=_w(0.5, near),
        detail={"dependency": target, "anvil_set_balance": {target: "0x0"}})]


def summarize(mutations: list[M.Mutation]) -> str:
    lines = ["COUNTERFACTUAL MUTATIONS (Phase 5)", "=" * 35, ""]
    for m in sorted(mutations, key=lambda x: -x.weight):
        lines.append(f"  [{m.kind}]  w={m.weight:.2f}  {m.statement}")
    return "\n".join(lines)
