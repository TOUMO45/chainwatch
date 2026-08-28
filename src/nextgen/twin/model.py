"""Data types for the Counterfactual Protocol Twin.

Every record has `as_dict()` for serialisation into the evidence graph / report.
Where a concept already exists in `nextgen/invariants/model.py` (a candidate
security property with an INFERRED->TESTED->VALIDATED status) the Twin reuses
it, tagged `SOURCE_TRACE`.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

SOURCE_TRACE = "onchain-trace"

# --- token standards ------------------------------------------------------- #
ERC20 = "ERC20"
ERC721 = "ERC721"
ERC1155 = "ERC1155"

# --- boundary kinds (Phase 3) ------------------------------------------- #
CONSERVATION = "CONSERVATION"
AUTHORIZATION = "AUTHORIZATION"
ACCOUNTING = "ACCOUNTING"
STATE_MACHINE = "STATE_MACHINE"
REPLAY_PROTECTION = "REPLAY_PROTECTION"
COLLATERAL = "COLLATERAL"
WITHDRAWAL = "WITHDRAWAL"
ORACLE_FRESHNESS = "ORACLE_FRESHNESS"
GOVERNANCE = "GOVERNANCE"

BOUNDARY_KINDS = frozenset({
    CONSERVATION, AUTHORIZATION, ACCOUNTING, STATE_MACHINE, REPLAY_PROTECTION,
    COLLATERAL, WITHDRAWAL, ORACLE_FRESHNESS, GOVERNANCE,
})

INFERRED = "INFERRED"
TESTED = "TESTED"
VALIDATED = "VALIDATED"
REJECTED = "REJECTED"

# --- divergence kinds (Phase 4) --------------------------------------- #
ACCEPT_TO_REJECT = "ACCEPTED_NOW_REJECTED"
REJECT_TO_ACCEPT = "REJECTED_NOW_ACCEPTED"
ASSET_FLOW_DIVERGENCE = "ASSET_FLOW_DIVERGENCE"
STATE_TRANSITION_DIVERGENCE = "STATE_TRANSITION_DIVERGENCE"
AUTHORIZATION_DIVERGENCE = "AUTHORIZATION_DIVERGENCE"
INVARIANT_WEAKENING = "INVARIANT_WEAKENING"
EXTERNAL_CALL_DIVERGENCE = "EXTERNAL_CALL_BEHAVIOUR_CHANGED"

# --- mutation kinds (Phase 5) --------------------------------------- #
ACTOR_SUBSTITUTION = "ACTOR_SUBSTITUTION"
BOUNDARY_VALUE = "BOUNDARY_VALUE"
REPETITION = "REPETITION"
REORDER = "REORDER"
DELAY = "DELAY"
CALLBACK_INSERT = "CALLBACK_INSERT"
STATE_TIMING = "STATE_TIMING"
ORACLE_STATE = "ORACLE_STATE"
PERMISSION_CHANGE = "PERMISSION_CHANGE"
CROSS_CONTRACT_VARIATION = "CROSS_CONTRACT_CALL_VARIATION"

# --- violation kinds (Phase 7) ------------------------------------- #
V_INVARIANT = "INVARIANT_VIOLATION"
V_UNAUTHORIZED_TRANSITION = "UNAUTHORIZED_STATE_TRANSITION"
V_ASSET_CONSERVATION = "ASSET_CONSERVATION_VIOLATION"
V_BALANCE_GAIN = "UNEXPECTED_BALANCE_INCREASE"
V_PROTOCOL_LOSS = "UNEXPECTED_PROTOCOL_LOSS"
V_UNEXPECTED_SUCCESS = "UNEXPECTED_SUCCESSFUL_CALL"
V_REVERT_BYPASS = "REVERT_BOUNDARY_BYPASS"


@dataclass
class TxRecord:
    hash: str
    block: int
    tx_index: int
    sender: str
    to: str
    value: int
    input: str                    # full calldata, 0x...
    selector: str                 # 0x + 8 hex
    status: bool                  # True = success
    gas_used: int = 0
    nonce: int = 0
    timestamp: int = 0
    revert_reason: str = ""

    def as_dict(self) -> dict:
        return {"hash": self.hash, "block": self.block,
                "tx_index": self.tx_index, "sender": self.sender,
                "to": self.to, "value": self.value, "selector": self.selector,
                "status": self.status, "gas_used": self.gas_used,
                "nonce": self.nonce, "timestamp": self.timestamp,
                "input_len": len(self.input), "revert_reason": self.revert_reason}


@dataclass
class TransferEvent:
    token: str
    standard: str                 # ERC20 / ERC721 / ERC1155
    frm: str
    to: str
    amount: int                   # value, or tokenId for 721, or per-id amount for 1155
    token_id: Optional[int] = None
    tx_hash: str = ""
    log_index: int = 0
    block: int = 0

    def as_dict(self) -> dict:
        return {"token": self.token, "standard": self.standard, "from": self.frm,
                "to": self.to, "amount": self.amount, "token_id": self.token_id,
                "tx_hash": self.tx_hash, "log_index": self.log_index,
                "block": self.block}


@dataclass
class TraceCall:
    frm: str
    to: str
    kind: str                     # CALL / DELEGATECALL / STATICCALL / CREATE
    input: str
    output: str = ""
    value: int = 0
    success: bool = True
    error: str = ""
    depth: int = 0
    children: list["TraceCall"] = field(default_factory=list)

    def flatten(self) -> list["TraceCall"]:
        out = [self]
        for c in self.children:
            out.extend(c.flatten())
        return out

    def as_dict(self) -> dict:
        return {"from": self.frm, "to": self.to, "kind": self.kind,
                "selector": (self.input or "0x")[:10], "value": self.value,
                "success": self.success, "error": self.error,
                "depth": self.depth,
                "children": [c.as_dict() for c in self.children]}


@dataclass
class Trace:
    tx: TxRecord
    call_tree: Optional[TraceCall] = None
    state_diff: dict = field(default_factory=dict)   # {addr: {"storage": {slot:(pre,post)}, "balance":(pre,post), ...}}
    transfers: list[TransferEvent] = field(default_factory=list)
    event_topics: list[str] = field(default_factory=list)
    source: str = "tx-only"        # "tx-only" | "anvil-reexec" | "native-trace"

    def external_calls(self) -> list[tuple[str, str]]:
        if not self.call_tree:
            return []
        return sorted({(c.to.lower(), (c.input or "0x")[:10])
                       for c in self.call_tree.flatten()
                       if c.to and c.depth > 0})

    def as_dict(self) -> dict:
        return {"tx": self.tx.as_dict(), "source": self.source,
                "call_tree": self.call_tree.as_dict() if self.call_tree else None,
                "state_diff_addrs": list(self.state_diff.keys()),
                "transfers": [t.as_dict() for t in self.transfers],
                "event_topics": self.event_topics}


@dataclass
class Collection:
    address: str
    chain_id: int
    from_block: int
    to_block: int
    txs: list[TxRecord] = field(default_factory=list)
    transfers: list[TransferEvent] = field(default_factory=list)
    logs_by_tx: dict[str, list[dict]] = field(default_factory=dict)
    impl_samples: list[tuple[int, Optional[str]]] = field(default_factory=list)
    trace_capable: bool = False
    notes: list[str] = field(default_factory=list)

    @property
    def upgrades(self) -> list[tuple[int, str]]:
        out: list[tuple[int, str]] = []
        prev = None
        for blk, impl in self.impl_samples:
            if impl and impl != prev:
                if prev is not None:
                    out.append((blk, impl))
                prev = impl
        return out

    def as_dict(self) -> dict:
        return {"address": self.address, "chain_id": self.chain_id,
                "from_block": self.from_block, "to_block": self.to_block,
                "n_txs": len(self.txs), "n_transfers": len(self.transfers),
                "trace_capable": self.trace_capable,
                "impl_samples": [[b, i] for b, i in self.impl_samples],
                "upgrades": [[b, i] for b, i in self.upgrades],
                "notes": self.notes}


@dataclass
class FunctionFingerprint:
    address: str
    selector: str
    name: str = ""
    signature: str = ""
    n_total: int = 0
    n_success: int = 0
    n_revert: int = 0
    callers_success: set = field(default_factory=set)
    callers_revert: set = field(default_factory=set)
    value_buckets: dict = field(default_factory=dict)      # bucket -> count (success only)
    calldata_len_success: set = field(default_factory=set)
    calldata_len_revert: set = field(default_factory=set)
    transfers_in: int = 0
    transfers_out: int = 0
    event_topics: dict = field(default_factory=dict)       # topic0 -> count
    external_call_targets: set = field(default_factory=set)  # (addr, selector)
    storage_slots_written: set = field(default_factory=set)
    example_success: list = field(default_factory=list)     # tx hashes
    example_revert: list = field(default_factory=list)

    @property
    def revert_rate(self) -> float:
        return round(self.n_revert / self.n_total, 3) if self.n_total else 0.0

    @property
    def caller_exclusive(self) -> Optional[set]:
        """A small set of addresses that are the ONLY successful callers - a
        candidate authorization boundary. None if the caller set is large or
        equals the reverting-caller set (i.e. not actually restricted)."""
        s = self.callers_success
        if not s or len(s) > 4:
            return None
        if s & self.callers_revert == s and self.n_revert:
            return None
        return set(s)

    def as_dict(self) -> dict:
        return {"address": self.address, "selector": self.selector,
                "name": self.name, "signature": self.signature,
                "n_total": self.n_total, "n_success": self.n_success,
                "n_revert": self.n_revert, "revert_rate": self.revert_rate,
                "callers_success": sorted(self.callers_success)[:12],
                "callers_revert": sorted(self.callers_revert)[:12],
                "caller_exclusive": sorted(self.caller_exclusive) if self.caller_exclusive else None,
                "value_buckets": dict(self.value_buckets),
                "calldata_len_success": sorted(self.calldata_len_success),
                "calldata_len_revert": sorted(self.calldata_len_revert),
                "transfers_in": self.transfers_in,
                "transfers_out": self.transfers_out,
                "event_topics": dict(self.event_topics),
                "external_call_targets": sorted(f"{a}:{s}" for a, s in self.external_call_targets)[:20],
                "storage_slots_written": sorted(self.storage_slots_written)[:20],
                "examples": {"success": self.example_success[:3],
                             "revert": self.example_revert[:3]}}


@dataclass
class Boundary:
    kind: str
    statement: str
    selector: str = ""
    status: str = INFERRED
    support: list = field(default_factory=list)      # tx hashes / observations
    counterexamples: list = field(default_factory=list)
    detail: dict = field(default_factory=dict)

    def __post_init__(self) -> None:
        if self.kind not in BOUNDARY_KINDS:
            raise ValueError(f"unknown boundary kind {self.kind!r}")

    @property
    def usable(self) -> bool:
        return self.status in (VALIDATED,)

    def as_dict(self) -> dict:
        return {"kind": self.kind, "statement": self.statement,
                "selector": self.selector, "status": self.status,
                "support": self.support[:6], "counterexamples": self.counterexamples[:6],
                "detail": self.detail}


# --- Phase 4: cross-version divergence ------------------------------------- #

@dataclass
class Divergence:
    kind: str                      # one of the divergence constants above
    selector: str
    statement: str
    old_ref: str = ""               # implementation address / version label, old side
    new_ref: str = ""
    detail: dict = field(default_factory=dict)

    def __post_init__(self) -> None:
        if self.kind not in _DIVERGENCE_KINDS:
            raise ValueError(f"unknown divergence kind {self.kind!r}")

    def as_dict(self) -> dict:
        return {"kind": self.kind, "selector": self.selector,
                "statement": self.statement, "old_ref": self.old_ref,
                "new_ref": self.new_ref, "detail": self.detail}


# --- Phase 5: counterfactual mutations -------------------------------------- #

@dataclass
class Mutation:
    """One counterfactual variant of a REAL trace: still the same `base_tx`
    (an actual historical transaction), replayed with one concrete change.
    `calls` is the exact sequence of `{from,to,value,data}` dicts Phase 6 sends
    to the fork, in order - a mutation is not always a single call (REORDER /
    REPETITION / CALLBACK_INSERT touch more than one)."""

    kind: str
    base_tx: str                    # hash of the real tx this varies
    selector: str
    statement: str                  # human-readable: what changed
    calls: list = field(default_factory=list)         # [{from,to,value,data}]
    state_overrides: dict = field(default_factory=dict)  # {addr:{slot:value}}
    fork_block: int = 0
    weight: float = 1.0             # ranking only - proximity to changed_selectors
    detail: dict = field(default_factory=dict)

    def __post_init__(self) -> None:
        if self.kind not in _MUTATION_KINDS:
            raise ValueError(f"unknown mutation kind {self.kind!r}")

    def as_dict(self) -> dict:
        return {"kind": self.kind, "base_tx": self.base_tx,
                "selector": self.selector, "statement": self.statement,
                "n_calls": len(self.calls), "fork_block": self.fork_block,
                "weight": self.weight, "detail": self.detail}


# --- Phase 6: replay --------------------------------------------------------- #

@dataclass
class ReplayResult:
    mutation: Optional[Mutation]
    executed: bool                  # every call in the mutation was submitted
    trace: Optional[Trace] = None   # the LAST call's trace (call tree + state diff)
    all_traces: list = field(default_factory=list)   # Trace per call, in order
    balances_before: dict = field(default_factory=dict)   # {addr: wei}
    balances_after: dict = field(default_factory=dict)
    error: str = ""

    def as_dict(self) -> dict:
        return {"mutation": self.mutation.as_dict() if self.mutation else None,
                "executed": self.executed,
                "trace": self.trace.as_dict() if self.trace else None,
                "n_calls_traced": len(self.all_traces),
                "balances_before": self.balances_before,
                "balances_after": self.balances_after, "error": self.error}


# --- Phase 7: violations ----------------------------------------------------- #

@dataclass
class Violation:
    kind: str
    statement: str
    selector: str = ""
    boundary: Optional[str] = None     # the Boundary.kind it violates, if any
    evidence: dict = field(default_factory=dict)

    def __post_init__(self) -> None:
        if self.kind not in _VIOLATION_KINDS:
            raise ValueError(f"unknown violation kind {self.kind!r}")

    def as_dict(self) -> dict:
        return {"kind": self.kind, "statement": self.statement,
                "selector": self.selector, "boundary": self.boundary,
                "evidence": self.evidence}


# --- orchestrator verdicts (Phase 9/10) ------------------------------------- #
TWIN_CONFIRMED = "CONFIRMED"
TWIN_REJECTED = "REJECTED"
TWIN_UNKNOWN = "UNKNOWN"


@dataclass
class TwinResult:
    address: str
    from_block: int
    to_block: int
    verdict: str = TWIN_UNKNOWN
    reason: str = ""
    collection: Optional[Collection] = None
    fingerprints: dict = field(default_factory=dict)
    boundaries: list = field(default_factory=list)
    divergences: list = field(default_factory=list)
    mutations_tried: int = 0
    violations: list = field(default_factory=list)
    minimal_repro: Optional[Mutation] = None
    deployment_facts: Optional[object] = None
    provenance_chain: Optional[object] = None
    skeptic_report: Optional[object] = None
    reproducer_result: Optional[object] = None
    notes: list = field(default_factory=list)

    def render_text(self) -> str:
        lines = ["=" * 78, "COUNTERFACTUAL PROTOCOL TWIN", "=" * 78, "",
                 f"address     {self.address}",
                 f"blocks      [{self.from_block}, {self.to_block}]"]
        if self.collection:
            lines.append(f"collected   {len(self.collection.txs)} tx(s), "
                         f"{len(self.collection.transfers)} transfer(s)"
                         + (f", {len(self.collection.upgrades)} implementation "
                            f"change(s) observed" if self.collection.upgrades else ""))
        lines.append(f"fingerprints {len(self.fingerprints)} selector(s)")
        lines.append(f"boundaries  {len(self.boundaries)} mined "
                     f"({sum(1 for b in self.boundaries if b.status == TESTED)} TESTED)")
        if self.divergences:
            lines.append(f"divergence  {len(self.divergences)} cross-version "
                         f"divergence(s)")
        lines.append(f"mutations   {self.mutations_tried} replayed")
        lines.append(f"violations  {len(self.violations)}")
        for v in self.violations[:5]:
            lines.append(f"    [{v.kind}]  {v.statement}")
        if self.minimal_repro:
            lines.append(f"minimal repro: {len(self.minimal_repro.calls)} call(s) "
                         f"- {self.minimal_repro.statement}")
        if self.deployment_facts is not None:
            lines.append(f"deployment  gate={getattr(self.deployment_facts, 'gate', '?')}  "
                         f"{getattr(self.deployment_facts, 'rationale', '')}")
        if self.skeptic_report is not None:
            lines.append(f"skeptic     disproved={self.skeptic_report.disproved}")
        if self.reproducer_result is not None:
            lines.append(f"reproducer  {self.reproducer_result.status}")
        lines += ["", f"VERDICT: {self.verdict}", f"  {self.reason}"]
        if self.notes:
            lines += ["", "notes:"] + [f"  - {n}" for n in self.notes]
        return "\n".join(lines)

    def as_dict(self) -> dict:
        return {
            "address": self.address, "from_block": self.from_block,
            "to_block": self.to_block, "verdict": self.verdict,
            "reason": self.reason,
            "collection": self.collection.as_dict() if self.collection else None,
            "n_fingerprints": len(self.fingerprints),
            "boundaries": [b.as_dict() for b in self.boundaries],
            "divergences": [d.as_dict() for d in self.divergences],
            "mutations_tried": self.mutations_tried,
            "violations": [v.as_dict() for v in self.violations],
            "minimal_repro": self.minimal_repro.as_dict() if self.minimal_repro else None,
            "deployment_facts": (self.deployment_facts.as_dict()
                                 if hasattr(self.deployment_facts, "as_dict") else None),
            "provenance_chain": (self.provenance_chain.as_dict()
                                 if hasattr(self.provenance_chain, "as_dict") else None),
            "skeptic_report": (self.skeptic_report.as_dict()
                              if hasattr(self.skeptic_report, "as_dict") else None),
            "reproducer_result": (self.reproducer_result.as_dict()
                                  if hasattr(self.reproducer_result, "as_dict") else None),
            "notes": self.notes,
        }


_DIVERGENCE_KINDS = frozenset({
    ACCEPT_TO_REJECT, REJECT_TO_ACCEPT, ASSET_FLOW_DIVERGENCE,
    STATE_TRANSITION_DIVERGENCE, AUTHORIZATION_DIVERGENCE, INVARIANT_WEAKENING,
    EXTERNAL_CALL_DIVERGENCE,
})
_MUTATION_KINDS = frozenset({
    ACTOR_SUBSTITUTION, BOUNDARY_VALUE, REPETITION, REORDER, DELAY,
    CALLBACK_INSERT, STATE_TIMING, ORACLE_STATE, PERMISSION_CHANGE,
    CROSS_CONTRACT_VARIATION,
})
_VIOLATION_KINDS = frozenset({
    V_INVARIANT, V_UNAUTHORIZED_TRANSITION, V_ASSET_CONSERVATION, V_BALANCE_GAIN,
    V_PROTOCOL_LOSS, V_UNEXPECTED_SUCCESS, V_REVERT_BYPASS,
})
