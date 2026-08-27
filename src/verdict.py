"""The three-state verdict model (RULES.md "Verdict model", finding X-L1).

    DISCARDED  an exclusion matched -> never surfaced.
    CANDIDATE  the trigger matched and no exclusion did, but at least one of the
               six required evidence fields is missing.
    CONFIRMED  CANDIDATE + all six evidence fields present + liveness == LIVE.

This module owns exactly one decision - `classify()` - and it is deliberately
mechanical: it counts evidence, it does not judge. A rule decides whether its
trigger fired; this decides whether the surrounding proof is complete enough to
call the result a finding. Nothing here can turn a quiet rule into a finding.

WHY THE BAR IS THIS HIGH
------------------------
RULES.md: "Missing any one -> downgrade to CANDIDATE. No exceptions, no
'confidence 0.8.'" The practical consequence is worth stating plainly because
it surprises people: **a repo-only scan, with no on-chain address, produces
zero CONFIRMED findings.** Liveness is one of the six, and without an address
liveness is UNKNOWN. That is not a bug in this module - it is the charter's
decisive gate doing its job. A regression in git that is not the code holding
funds is a CANDIDATE, and calling it anything more would be the exact
overclaim this project exists to avoid.

THE SIX FIELDS, AND WHO FILLS THEM
----------------------------------
1. regression_commit  - the walker (hash, author, date, changed line range)
2. pre_state          - the rule (the before-side AST fact it measured)
3. post_state         - the rule (the after-side AST fact it measured)
4. reachability       - the rule (externally reachable AND state-changing) plus
                        the walker (the regression still present at HEAD)
5. no_compensating_control - the rule, by construction: reaching a fire means
                        every exclusion in its set was evaluated and none
                        matched. The exclusions actually implemented are listed
                        per rule below; the ones that are NOT implemented are
                        recorded in LIMITATIONS.md, which is why this field
                        names the set rather than asserting a bare boolean.
6. liveness           - src/liveness.py (LIVE / PATCHED / UNKNOWN)
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Optional

DISCARDED = "DISCARDED"
CANDIDATE = "CANDIDATE"
CONFIRMED = "CONFIRMED"

LIVE = "LIVE"
PATCHED = "PATCHED"
UNKNOWN = "UNKNOWN"

# --------------------------------------------------------------------------
# Per-rule evidence mapping.
#
# PRE_POST: (evidence key holding the N-1 fact, evidence key holding the N
# fact). These are the keys each rule's emit() actually writes - see the
# `evidence={...}` literal at every fire site. A rule id absent here yields no
# pre/post state and therefore caps at CANDIDATE, which is the safe direction.
#
# EXCLUSIONS: the exclusion identifiers from RULES.md that the SHIPPED
# implementation evaluates before it can reach a fire. Deliberately not the
# full spec list: unimplemented exclusions (6.4, 6.6, 3c.2 on the OZ 5 path,
# ...) are tracked in LIMITATIONS.md and must not be claimed as proof here.
# --------------------------------------------------------------------------

PRE_POST: dict[str, tuple[str, str]] = {
    "1": ("constrained_before", "constrained_after"),
    "2a": ("mutex_before", "mutex_after"),
    "2b": ("cei_ordering_broken", "moved_after_call"),
    # "3a" is deliberately ABSENT here - see PRE_POST_BY_TRIGGER below.
    # "3b" is deliberately ABSENT here - see PRE_POST_BY_TRIGGER below.
    # "3c" is deliberately ABSENT here - see PRE_POST_BY_TRIGGER below.
    # "4" is deliberately ABSENT here - see PRE_POST_BY_TRIGGER below.
    "5": ("checked_before", "checked_after"),
    "6": ("guarded_before", "guarded_after"),
    # Rule 10's pre-state is that the variable was established ONE-SHOT at N-1
    # (a constructor anywhere in the chain, or an init-guarded function); its
    # post-state is the unguarded run-time writer that exists at N. Absent
    # here, every rule 10 finding carried pre_state=null / post_state=null and
    # could never have reached CONFIRMED even with liveness - the exact failure
    # tests/test_verdict.py::test_every_shipped_rule_has_pre_post_and_exclusions
    # exists to catch, and it caught it.
    "10": ("oneshot_writers_before", "unguarded_writer_after"),
}

# Rule 4 fires from THREE structurally distinct triggers (RULES.md), each on
# a different regression fact - one (pre_key, post_key) pair keyed on rule id
# alone cannot describe all three. Measured: before this existed, PRE_POST["4"]
# was ("pragma_before", "pragma_after"), which only the pragma-lowered trigger
# ever populates - `_safemath_removed` and `_unchecked_added` emit neither
# key, so their findings (both real, both fixture-verified-firing:
# fixtures-r4 P4-02 / P4-01) carried pre_state=None / post_state=None and
# could NEVER reach CONFIRMED, regardless of liveness. This is the exact
# defect class already fixed once for Rule 10 (see the comment on PRE_POST's
# "10" entry) - one level deeper: the rule id WAS registered, but only one of
# its three live firing paths actually matched what was registered. Keyed on
# the rule's own "trigger" evidence field, present at every rule 4 emit site
# for exactly this purpose.
PRE_POST_BY_TRIGGER: dict[str, dict[str, tuple[str, str]]] = {
    # Rule 3a fires from TWO structurally distinct triggers (3a-L2, closed
    # 2026-08-26, RULES.md): the original "constraint removed" shape, and
    # "caller-set-widened" - a msg.sender check that SURVIVES but now compares
    # against an unguarded, attacker-settable target. Registered from day one
    # (unlike rule 4/3b/3c's history, where the second trigger shipped before
    # its evidence keys were registered and every finding silently capped at
    # CANDIDATE forever) precisely because that failure class is now a known,
    # named risk in this project rather than one to rediscover.
    "3a": {
        "constraint-removed": ("constrained_before", "constrained_after"),
        "caller-set-widened": ("target_protected_before", "target_protected_after"),
    },
    "4": {
        "pragma-lowered": ("pragma_before", "pragma_after"),
        "safemath-removed": ("wrapper_calls_before", "wrapper_calls_after"),
        "unchecked-block-added": ("checked_before", "checked_after"),
    },
    # Rule 3b's SECOND trigger (constructor's `_disableInitializers()` call
    # removed) had exactly the same gap, found by auditing every OTHER
    # multi-trigger rule after RC-VERDICT1: its emit() carried no pre/post
    # keys at all - unsurprising, since the code's own comment already noted
    # "no fixture exercises this clause yet". Never observed firing on real
    # code or under test; fixed on the same principle as rule 4 regardless,
    # since a rule reaching this emit call today would silently cap forever.
    "3b": {
        "initializer-guard-removed": ("init_guard_before", "init_guard_after"),
        "disableInitializers-removed": ("disables_init_before", "disables_init_after"),
    },
    # Rule 3c's OZ 5 ERC-7201 path (the 3x-L3 unlock) had the same gap, found
    # by the same audit: its emit() reports only a boolean collision fact
    # (unlike the OZ 4 "declared-layout" mode, which has exact slot numbers
    # available), so pre/post here is coarser by necessity, not by oversight.
    # Never exercised by any fixture - same "genuinely unproven" status as
    # rule 3b's second trigger.
    "3c": {
        "declared-layout": ("slot_before", "slot_after"),
        "erc7201-namespaced": ("collision_before", "collision_after"),
    },
}

EXCLUSIONS_EVALUATED: dict[str, tuple[str, ...]] = {
    "1": ("1.1", "1.2", "1.3", "1.4", "1.6", "1.10", "upgrade-fn deferral"),
    "2a": ("2.1", "2.2", "2.3", "2.5", "2.8", "2.10"),
    "2b": ("2.1", "2.8", "2.9", "2.10", "2a-priority", "admin-gated (RC-4/RC-ROLE)"),
    "3a": ("3a.1", "3a.2", "3a.3"),
    "3b": ("3b.1", "3b.2", "3b.3", "3b.4", "rate-limit discriminator"),
    "3c": ("3c.2", "3c.3", "test-path", "RC-AST1 type identity"),
    "4": ("4.1", "4.2", "4.3", "4.4", "4.5", "4.6"),
    "5": ("5.1", "5.2", "5.4", "5.5", "5.6", "R5-L1 per-site ordinal"),
    "6": ("6.1", "6.2", "6.3", "6.5", "6.7", "RC-OZ5-R6 pointer gate"),
    "10": ("10.1", "10.2", "10.3", "10.4", "10.5", "10.6", "10.8"),
}

# Rules whose subject is a contract-level fact, where "externally callable
# function" is not the applicable reachability proof. For these the rule
# supplies an explicit `reachability` string instead (3c: the contract is
# proxy-deployed, so the upgrade path IS the reachable surface).
CONTRACT_LEVEL_RULES = frozenset({"3c"})

EXTERNAL_VISIBILITIES = frozenset({"public", "external"})


@dataclass
class Evidence:
    """The six required fields. `None` means NOT ESTABLISHED, never 'assumed'."""

    regression_commit: Optional[dict] = None
    pre_state: Optional[str] = None
    post_state: Optional[str] = None
    reachability: Optional[str] = None
    no_compensating_control: Optional[str] = None
    liveness: Optional[str] = None

    def missing(self) -> list[str]:
        return [k for k, v in asdict(self).items() if v in (None, "", [], {})]


@dataclass
class Finding:
    """One attributed regression, plus everything needed to judge it."""

    rule_id: str
    owasp: str = ""
    severity_hint: str = CONFIRMED   # what the RULE itself concluded
    file: str = ""
    contract: str = ""
    function: Optional[str] = None
    signature: Optional[str] = None
    line: Optional[int] = None
    detail: str = ""
    raw_evidence: dict = field(default_factory=dict)

    # Trajectory, filled by the walker.
    commit: Optional[str] = None
    parent: Optional[str] = None
    author: Optional[str] = None
    date: Optional[str] = None
    line_range: Optional[str] = None
    survives_to_head: Optional[bool] = None
    fixed_at: Optional[str] = None

    # Liveness, filled by src/liveness.py when an address is supplied.
    liveness: Optional[str] = None
    liveness_reason: str = ""

    # Capability 14 (src/exploit_proof.py), filled only for CONFIRMED findings
    # on the narrow set of rules a single read-only eth_call can honestly test
    # (see that module's docstring). Deliberately OUTSIDE the six evidence
    # fields, same discipline as capability 13's exposure probe: it answers a
    # different question (is this SPECIFIC regression callable right now) and
    # must never become a seventh field a CANDIDATE could lean on.
    exploit_proof: Optional[dict] = None

    evidence: Evidence = field(default_factory=Evidence)
    verdict: str = CANDIDATE
    downgrade_reasons: list[str] = field(default_factory=list)

    def as_dict(self) -> dict:
        d = asdict(self)
        d["evidence"] = asdict(self.evidence)
        return d


def _pre_post(rule_id: str, raw: dict) -> tuple[Optional[str], Optional[str]]:
    by_trigger = PRE_POST_BY_TRIGGER.get(rule_id)
    if by_trigger:
        # Rules discriminate their own trigger shapes under different evidence
        # keys - "trigger" (rules 3b, 4) or "mode" (rule 3c) - whichever a
        # given rule's emit() actually sets.
        discriminator = raw.get("trigger") if "trigger" in raw else raw.get("mode")
        keys = by_trigger.get(discriminator)
    else:
        keys = PRE_POST.get(rule_id)
    if not keys:
        return None, None
    pre_key, post_key = keys
    if pre_key not in raw or post_key not in raw:
        return None, None
    return f"{pre_key}={raw[pre_key]!r}", f"{post_key}={raw[post_key]!r}"


def _reachability(rule_id: str, raw: dict, survives_to_head: Optional[bool]) -> Optional[str]:
    """Field 4. Two halves, BOTH required.

    Half one - the after-commit function is an externally reachable state
    changer (or, for a contract-level rule, the rule's own explicit proof).
    Half two - RULES.md's "reachable at HEAD (not just at commit N)": the
    regression must still be there today. A regression that a later commit
    repaired is real history and worth reporting as trajectory, but it is not
    a live finding, so it never reaches CONFIRMED.
    """
    if survives_to_head is not True:
        return None

    if rule_id in CONTRACT_LEVEL_RULES:
        explicit = raw.get("reachability") or (
            "proxy-deployed contract: the upgrade path is the reachable surface"
            if raw.get("proxy_deployed")
            else None
        )
        return f"{explicit}; still present at HEAD" if explicit else None

    vis = raw.get("visibility_after")
    if vis not in EXTERNAL_VISIBILITIES:
        # 3a-L4. An `internal` function can still be the real attack surface if
        # an inherited PUBLIC entry point reaches it - UUPS's `_authorizeUpgrade`
        # is internal by design and is reached through `upgradeTo` /
        # `upgradeToAndCall`. Before this, every such finding capped at
        # CANDIDATE regardless of the evidence around it.
        #
        # Accepted ONLY from `reachable_via_after`, which a RULE must have
        # established from real call-graph analysis and populated with the
        # entry points it found. Nothing is inferred here: this module has no
        # call graph, and a verdict that guessed at reachability would be
        # exactly the kind of second opinion that makes CONFIRMED unreliable.
        entries = raw.get("reachable_via_after") or []
        if not entries:
            return None
        # The state-change half, for this shape. `_authorizeUpgrade` writes
        # nothing - it is a GUARD; the write happens in the entry point it
        # protects, and real UUPS writes the ERC-1967 implementation slot with
        # a raw sstore to a computed address, which is not a declared state
        # variable and so is invisible to `all_state_variables_written()`
        # either way (measured on this project's own P3a-widen-01 fixture: all
        # four upgrade entry points report zero state writes).
        #
        # Demanding a declared write here would therefore reject the entire
        # UUPS class on a technicality of how solc stores a slot. `upgrade_path`
        # is the same judgement this module ALREADY applies to contract-level
        # rules just above ("the upgrade path is the reachable surface") - an
        # upgrade replaces the whole implementation, which is the most complete
        # state change a contract can undergo. The rule must assert it; this
        # module still infers nothing.
        if not (raw.get("writes_state_after") or raw.get("upgrade_path")):
            return None
        how = ("controls the upgrade path" if raw.get("upgrade_path")
               else "writes state at commit N")
        return (f"visibility={vis} but reachable from "
                f"{', '.join(entries[:3])}; {how}, still present at HEAD")
    changes_state = raw.get("writes_state_after")
    if changes_state is None:
        # Rules whose trigger REQUIRES a state change or value movement to have
        # been reached at all (2a/2b move a state write across a call; 5 needs
        # an external call). Absence of the flag is not absence of the fact,
        # but this module never infers: say so and let it cap at CANDIDATE.
        return None
    if not changes_state:
        return None
    return f"visibility={vis}, writes state at commit N, still present at HEAD"


def update_survival(f: Finding, survives_to_head: bool,
                    fixed_at: Optional[str] = None) -> None:
    """Overwrite a finding's survival-to-HEAD fact after `build()`, and
    recompute the evidence that depends on it.

    Exists for scan.py's immutable-clone liveness fallback (measured on the
    real 88mph NFT.init() regression, 2026-08-26): the source-diff survival
    check in `_head_survival` assumes the deployed contract keeps tracking the
    repository's current source, which is false for an EIP-1167 clone target -
    its bytecode is fixed at deploy time, so a later source fix (protecting
    only FUTURE clones) can never reach it. When liveness independently proves
    the exact regression-commit bytecode is what a clone still runs, that IS
    proof of survival, more direct than the source-diff heuristic - "this exact
    code still executes" and "the regression still exists" are the same fact
    for immutable code. Callers must not invoke this from a guess; only from a
    liveness result that already required byte-exact match.
    """
    f.survives_to_head = survives_to_head
    f.fixed_at = fixed_at
    f.evidence.reachability = _reachability(f.rule_id, f.raw_evidence, f.survives_to_head)


def _no_compensating_control(rule_id: str) -> Optional[str]:
    ex = EXCLUSIONS_EVALUATED.get(rule_id)
    if not ex:
        return None
    return (
        f"rule {rule_id} exclusion set evaluated, none matched: {', '.join(ex)} "
        f"(unimplemented exclusions for this rule are listed in LIMITATIONS.md)"
    )


def build(record: dict, *, commit: Optional[dict] = None,
          survives_to_head: Optional[bool] = None,
          liveness: Optional[str] = None,
          liveness_reason: str = "") -> Finding:
    """Turn one `_shared.emit()` record into a classified Finding.

    `record` is what a rule emitted; `commit` is the walker's git metadata
    ({hash, parent, author, date, line_range}). Everything absent stays None
    and costs a CONFIRMED.
    """
    raw = dict(record.get("evidence") or {})
    commit = commit or {}

    f = Finding(
        rule_id=str(record.get("rule_id", "")),
        owasp=raw.get("owasp", ""),
        severity_hint=record.get("severity", CONFIRMED),
        file=record.get("file", "") or "",
        contract=record.get("contract", "") or "",
        function=record.get("function"),
        signature=record.get("signature"),
        line=record.get("line"),
        detail=record.get("detail", "") or "",
        raw_evidence=raw,
        commit=commit.get("hash"),
        parent=commit.get("parent"),
        author=commit.get("author"),
        date=commit.get("date"),
        line_range=commit.get("line_range"),
        survives_to_head=survives_to_head,
        liveness=liveness,
        liveness_reason=liveness_reason,
    )

    pre, post = _pre_post(f.rule_id, raw)
    f.evidence = Evidence(
        regression_commit=(
            {k: commit.get(k) for k in ("hash", "author", "date", "line_range")}
            if commit.get("hash") and commit.get("line_range")
            else None
        ),
        pre_state=pre,
        post_state=post,
        reachability=_reachability(f.rule_id, raw, survives_to_head),
        no_compensating_control=_no_compensating_control(f.rule_id),
        liveness=liveness,
    )
    classify(f)
    return f


def classify(f: Finding) -> str:
    """Set and return `f.verdict`. Mechanical; records why on every downgrade."""
    reasons: list[str] = []

    missing = f.evidence.missing()
    if missing:
        reasons.append("missing evidence: " + ", ".join(missing))

    if f.severity_hint == CANDIDATE:
        # The rule itself capped this (RULES.md 2.10 read-only reentrancy, 5.3
        # best-effort notification). A rule ceiling is never raised here.
        reasons.append(f"rule {f.rule_id} caps this trigger class at CANDIDATE")

    if f.liveness and f.liveness != LIVE:
        reasons.append(f"liveness={f.liveness}, CONFIRMED requires LIVE")

    if f.survives_to_head is False:
        reasons.append(
            "regression does not survive to HEAD"
            + (f" (repaired at {f.fixed_at})" if f.fixed_at else "")
        )

    f.downgrade_reasons = reasons
    f.verdict = CANDIDATE if reasons else CONFIRMED
    return f.verdict
