"""Phase 7 - did a replayed mutation actually violate a mined boundary?

Deliberately conservative: every check here needs a CONCRETE, observed signal
(the replay succeeded where the boundary predicted a revert, a balance moved
in the disallowed direction) - never "this mutation is suspicious" on its own.
A mutation that merely differs from the baseline without crossing a specific
boundary produces no Violation; that is the whole point of mining boundaries
FIRST (Phase 3) rather than treating every counterfactual as a finding.

Each Violation names the Boundary it crosses (`boundary=b.kind`) so Phase 9/10
can be shown exactly what was checked, and a reader can go re-derive it from
`ReplayResult.as_dict()` rather than trust a label.
"""

from __future__ import annotations

from typing import Optional

from . import model as M

_ATTACK_SHAPED = frozenset({
    M.ACTOR_SUBSTITUTION, M.PERMISSION_CHANGE, M.BOUNDARY_VALUE,
    M.STATE_TIMING, M.ORACLE_STATE,
})


def check_violations(baseline_trace: Optional[M.Trace], replay_result: M.ReplayResult,
                     boundaries: list[M.Boundary]) -> list[M.Violation]:
    mutation = replay_result.mutation
    if mutation is None or not replay_result.executed or replay_result.trace is None:
        return []       # nothing ran to completion - no basis for a claim

    out: list[M.Violation] = []
    sel_boundaries = [b for b in boundaries if b.selector == mutation.selector]
    succeeded = bool(replay_result.trace.tx.status)

    out += _authorization_bypass(mutation, replay_result, sel_boundaries, succeeded)
    out += _balance_gain(mutation, replay_result, succeeded)
    out += _protocol_loss(mutation, replay_result, baseline_trace, succeeded)
    out += _unexpected_success(mutation, replay_result, sel_boundaries, succeeded)
    out += _replay_bypass(mutation, replay_result, sel_boundaries, succeeded)
    out += _conservation_break(mutation, replay_result, sel_boundaries, baseline_trace)
    return out


def _authorization_bypass(mutation: M.Mutation, rr: M.ReplayResult,
                          boundaries: list[M.Boundary], succeeded: bool
                          ) -> list[M.Violation]:
    if mutation.kind not in (M.ACTOR_SUBSTITUTION, M.PERMISSION_CHANGE) or not succeeded:
        return []
    auth = [b for b in boundaries if b.kind == M.AUTHORIZATION and b.status != M.INFERRED]
    if not auth:
        return []
    caller = mutation.calls[-1].get("from", "")
    known = set(auth[0].detail.get("callers", []))
    if caller.lower() in {c.lower() for c in known}:
        return []       # the probe address happens to already be authorized
    return [M.Violation(
        kind=M.V_UNAUTHORIZED_TRANSITION,
        statement=f"{mutation.selector} succeeded when called by {caller}, "
                 f"outside the observed authorized set {sorted(known)} "
                 f"({auth[0].status})",
        selector=mutation.selector, boundary=M.AUTHORIZATION,
        evidence={"caller": caller, "authorized_set": sorted(known),
                  "mutation": mutation.kind, "tx": rr.trace.tx.hash})]


def _balance_gain(mutation: M.Mutation, rr: M.ReplayResult, succeeded: bool
                  ) -> list[M.Violation]:
    if not succeeded or mutation.kind not in _ATTACK_SHAPED:
        return []
    sender = mutation.calls[-1].get("from", "")
    before = rr.balances_before.get(sender)
    after = rr.balances_after.get(sender)
    if before is None or after is None:
        return []
    gain = after - before
    # gas is spent from the sender's own balance too, so ANY net increase
    # (not merely "less loss than gas would predict") is unambiguous signal.
    if gain > 0:
        return [M.Violation(
            kind=M.V_BALANCE_GAIN,
            statement=f"the calling address's ETH balance increased by "
                     f"{gain} wei from a {mutation.kind} replay of "
                     f"{mutation.selector} - a net gain net of its own gas "
                     f"cost is not explained by simply calling a function",
            selector=mutation.selector, boundary=None,
            evidence={"sender": sender, "before": before, "after": after,
                     "gain_wei": gain, "mutation": mutation.kind})]
    return []


def _protocol_loss(mutation: M.Mutation, rr: M.ReplayResult,
                   baseline: Optional[M.Trace], succeeded: bool
                   ) -> list[M.Violation]:
    if not succeeded or mutation.kind not in _ATTACK_SHAPED:
        return []
    target = mutation.calls[-1].get("to", "")
    senders = {c.get("from") for c in mutation.calls if c.get("from")}
    if target in senders:
        # `replay()` pre-funds every SENDER with a large synthetic balance
        # before sampling `balances_before` - correct for `_balance_gain`
        # (an unexpected excess ABOVE that known baseline is real signal),
        # wrong here: a target that is ALSO one of the mutation's own senders
        # (a genuine self-call transaction, `from == to`) never had a real
        # "before" balance to lose - its drop is just the synthetic
        # balance's own gas cost. Measured directly against a real Uniswap
        # V3 pool interaction (a self-calling router tx): without this
        # guard, ordinary gas expenditure against a 10**24-wei synthetic
        # balance read as a 651330042304960-wei "protocol loss".
        return []
    before = rr.balances_before.get(target)
    after = rr.balances_after.get(target)
    if before is None or after is None or before == 0:
        return []
    loss = before - after
    if loss <= 0:
        return []
    baseline_moved_out = bool(baseline and baseline.tx.value == 0
                              and any(t.frm == target for t in baseline.transfers))
    return [M.Violation(
        kind=M.V_PROTOCOL_LOSS,
        statement=f"the target contract's ETH balance dropped by {loss} wei "
                 f"during a {mutation.kind} replay of {mutation.selector} "
                 + ("(the real baseline call also moved funds out, so this "
                    "may be ordinary behaviour - check the amount)"
                    if baseline_moved_out else
                    "; the real baseline call did not move funds out this way"),
        selector=mutation.selector, boundary=None,
        evidence={"target": target, "before": before, "after": after,
                 "loss_wei": loss, "baseline_also_paid_out": baseline_moved_out})]


def _unexpected_success(mutation: M.Mutation, rr: M.ReplayResult,
                        boundaries: list[M.Boundary], succeeded: bool
                        ) -> list[M.Violation]:
    if mutation.kind not in (M.BOUNDARY_VALUE, M.STATE_TIMING, M.ORACLE_STATE) \
            or not succeeded:
        return []
    relevant = [b for b in boundaries
               if b.kind in (M.STATE_MACHINE, M.ORACLE_FRESHNESS, M.CONSERVATION)
               and b.status == M.TESTED]
    if not relevant:
        return []
    return [M.Violation(
        kind=M.V_UNEXPECTED_SUCCESS,
        statement=f"{mutation.statement} - and it SUCCEEDED, against a "
                 f"TESTED boundary ({relevant[0].kind}: {relevant[0].statement})",
        selector=mutation.selector, boundary=relevant[0].kind,
        evidence={"mutation_detail": mutation.detail,
                 "boundary": relevant[0].as_dict()})]


def _replay_bypass(mutation: M.Mutation, rr: M.ReplayResult,
                   boundaries: list[M.Boundary], succeeded: bool
                   ) -> list[M.Violation]:
    if mutation.kind != M.STATE_TIMING or not succeeded:
        return []
    guard = [b for b in boundaries if b.kind == M.REPLAY_PROTECTION]
    if not guard:
        return []
    return [M.Violation(
        kind=M.V_REVERT_BYPASS,
        statement=f"{mutation.selector} succeeded after its replay-guard "
                 f"slot ({mutation.detail.get('slot')}) was forced back to a "
                 f"prior value - the guard did not stop it",
        selector=mutation.selector, boundary=M.REPLAY_PROTECTION,
        evidence={"slot": mutation.detail.get("slot")})]


def _conservation_break(mutation: M.Mutation, rr: M.ReplayResult,
                        boundaries: list[M.Boundary],
                        baseline: Optional[M.Trace]) -> list[M.Violation]:
    if mutation.kind != M.REPETITION or not rr.executed:
        return []
    cons = [b for b in boundaries if b.kind == M.CONSERVATION
           and b.detail.get("one_sided") and b.status == M.TESTED]
    if not cons or not baseline:
        return []
    # both calls in a REPETITION must individually succeed for a doubled
    # one-sided outflow to mean anything - a second call that reverted is
    # exactly the replay-protection working as intended, not a violation.
    if not all(t.tx.status for t in rr.all_traces):
        return []
    doubled_out = sum(len(t.transfers) for t in rr.all_traces
                      if t.tx.to == mutation.calls[0]["to"])
    if doubled_out < 2:
        return []
    return [M.Violation(
        kind=M.V_ASSET_CONSERVATION,
        statement=f"{mutation.selector} (one-sided outflow per the mined "
                 f"CONSERVATION boundary) succeeded TWICE from the same "
                 f"real call replayed back to back, moving tokens out both "
                 f"times",
        selector=mutation.selector, boundary=M.CONSERVATION,
        evidence={"transfer_events_total": doubled_out})]


def summarize(violations: list[M.Violation]) -> str:
    lines = ["VIOLATIONS (Phase 7)", "=" * 20, ""]
    if not violations:
        lines.append("  none - no replayed mutation crossed a mined boundary")
    for v in violations:
        lines.append(f"  [{v.kind}]  {v.statement}")
    return "\n".join(lines)
