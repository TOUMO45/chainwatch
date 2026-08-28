"""Phase 4 - compare fingerprints + boundaries across two implementation
versions of the same address.

`Collection.upgrades` gives the block ranges either side of an EIP-1967/1167
implementation change; the caller collects two windows (one per side) and
fingerprints/mines each independently, then hands both pairs here. Divergence
is the input to Phase 5 (mutations are weighted toward the selectors that
changed) and a genuine finding on its own: a selector that used to reject an
input and now accepts it is exactly the shape of a removed guard, seen from
behaviour rather than source.
"""

from __future__ import annotations

from typing import Optional

from . import model as M


def compare_versions(fp_old: dict[str, M.FunctionFingerprint],
                     fp_new: dict[str, M.FunctionFingerprint],
                     b_old: list[M.Boundary], b_new: list[M.Boundary],
                     *, old_ref: str = "", new_ref: str = ""
                     ) -> list[M.Divergence]:
    out: list[M.Divergence] = []
    out += _accept_reject_flips(fp_old, fp_new, old_ref, new_ref)
    out += _asset_flow_divergence(fp_old, fp_new, old_ref, new_ref)
    out += _external_call_divergence(fp_old, fp_new, old_ref, new_ref)
    out += _boundary_divergence(b_old, b_new, old_ref, new_ref)
    return out


def _selector_union(*fps: dict[str, M.FunctionFingerprint]) -> set:
    out: set = set()
    for m in fps:
        out |= set(m)
    return out


def _accept_reject_flips(fp_old: dict, fp_new: dict, old_ref: str, new_ref: str
                         ) -> list[M.Divergence]:
    """A caller set that always reverted on the old side and always succeeds
    on the new side (or vice versa) for the SAME selector - the trace-derived
    analogue of "this rule used to fire and no longer does" from the
    git-history pipeline, but observed from behaviour, not a diff."""
    out = []
    for sel in _selector_union(fp_old, fp_new):
        old, new = fp_old.get(sel), fp_new.get(sel)
        if old is None or new is None:
            continue        # a selector introduced or removed is a different signal (below)
        old_ok = old.n_success > 0 and old.n_revert == 0 and old.n_total >= 1
        old_rej = old.n_success == 0 and old.n_revert > 0
        new_ok = new.n_success > 0 and new.n_revert == 0 and new.n_total >= 1
        new_rej = new.n_success == 0 and new.n_revert > 0
        if old_rej and new_ok:
            out.append(M.Divergence(
                kind=M.REJECT_TO_ACCEPT, selector=sel,
                statement=f"{sel} always reverted in the old sample "
                         f"({old.n_revert} call(s)) and always succeeds in the "
                         f"new one ({new.n_success} call(s)) - a guard that used "
                         f"to reject this input no longer does",
                old_ref=old_ref, new_ref=new_ref,
                detail={"old_callers_revert": sorted(old.callers_revert)[:6],
                        "new_callers_success": sorted(new.callers_success)[:6]}))
        elif old_ok and new_rej:
            out.append(M.Divergence(
                kind=M.ACCEPT_TO_REJECT, selector=sel,
                statement=f"{sel} always succeeded in the old sample and "
                         f"always reverts in the new one - a new guard, or a "
                         f"regression that broke a previously-working path",
                old_ref=old_ref, new_ref=new_ref, detail={}))
    return out


def _asset_flow_divergence(fp_old: dict, fp_new: dict, old_ref: str, new_ref: str
                           ) -> list[M.Divergence]:
    out = []
    for sel in _selector_union(fp_old, fp_new):
        old, new = fp_old.get(sel), fp_new.get(sel)
        if old is None or new is None or not old.n_success or not new.n_success:
            continue
        old_shape = (bool(old.transfers_in), bool(old.transfers_out))
        new_shape = (bool(new.transfers_in), bool(new.transfers_out))
        if old_shape != new_shape and (old_shape != (False, False)
                                       or new_shape != (False, False)):
            out.append(M.Divergence(
                kind=M.ASSET_FLOW_DIVERGENCE, selector=sel,
                statement=f"{sel}'s asset-flow shape changed: "
                         f"in/out={old_shape} (old, n={old.n_success}) -> "
                         f"in/out={new_shape} (new, n={new.n_success})",
                old_ref=old_ref, new_ref=new_ref,
                detail={"old": {"in": old.transfers_in, "out": old.transfers_out},
                        "new": {"in": new.transfers_in, "out": new.transfers_out}}))
    return out


def _external_call_divergence(fp_old: dict, fp_new: dict, old_ref: str, new_ref: str
                              ) -> list[M.Divergence]:
    out = []
    for sel in _selector_union(fp_old, fp_new):
        old, new = fp_old.get(sel), fp_new.get(sel)
        if old is None or new is None:
            continue
        old_targets = {t for t, _ in old.external_call_targets}
        new_targets = {t for t, _ in new.external_call_targets}
        added, removed = new_targets - old_targets, old_targets - new_targets
        if not added and not removed:
            continue
        out.append(M.Divergence(
            kind=M.EXTERNAL_CALL_DIVERGENCE, selector=sel,
            statement=f"{sel}'s cross-contract call targets changed: "
                     f"+{len(added)} new, -{len(removed)} no longer called",
            old_ref=old_ref, new_ref=new_ref,
            detail={"added": sorted(added)[:10], "removed": sorted(removed)[:10]}))
    return out


def _boundary_divergence(b_old: list[M.Boundary], b_new: list[M.Boundary],
                         old_ref: str, new_ref: str) -> list[M.Divergence]:
    """A boundary present (TESTED+) on the old side for a selector, absent on
    the new side entirely - the clearest trace-derived signal of a weakened
    invariant. AUTHORIZATION is treated separately from the others: a widened
    caller set is reported even when the boundary still technically exists."""
    out = []
    old_by_key = {(b.kind, b.selector): b for b in b_old if b.status != M.INFERRED
                 or b.kind == M.AUTHORIZATION}
    new_by_key = {(b.kind, b.selector): b for b in b_new if b.status != M.INFERRED
                 or b.kind == M.AUTHORIZATION}
    for key, ob in old_by_key.items():
        nb = new_by_key.get(key)
        kind, sel = key
        if nb is None:
            out.append(M.Divergence(
                kind=M.INVARIANT_WEAKENING, selector=sel,
                statement=f"a {kind} boundary observed on the old side "
                         f"({ob.statement}) has no counterpart on the new side "
                         f"- the constraint may no longer hold",
                old_ref=old_ref, new_ref=new_ref,
                detail={"old_boundary": ob.as_dict()}))
            continue
        if kind == M.AUTHORIZATION:
            old_callers = set(ob.detail.get("callers", []))
            new_callers = set(nb.detail.get("callers", []))
            widened = new_callers - old_callers
            if widened and not (old_callers - new_callers):
                # strictly a superset - the door got WIDER, never narrower here
                out.append(M.Divergence(
                    kind=M.AUTHORIZATION_DIVERGENCE, selector=sel,
                    statement=f"{sel}'s authorized caller set widened: "
                             f"{sorted(old_callers)} -> {sorted(new_callers)}",
                    old_ref=old_ref, new_ref=new_ref,
                    detail={"old_callers": sorted(old_callers),
                            "new_callers": sorted(new_callers),
                            "added": sorted(widened)}))
    return out


def summarize(divs: list[M.Divergence]) -> str:
    lines = ["VERSION DIVERGENCE (Phase 4)", "=" * 28, ""]
    if not divs:
        lines.append("  none found")
    for d in divs:
        lines.append(f"  [{d.kind}]  {d.statement}")
    return "\n".join(lines)
