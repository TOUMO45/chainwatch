"""RULE 3c - SC10: Storage layout collision.

Trigger (RULES.md): in an upgradeable contract, an existing storage variable's
slot index or type changed between commits (insertion, reordering, or
type-width change).

Per the spec's explicit instruction, the comparison is driven by a real
storage-layout comparator - `solc --storage-layout` at both commits, compared
slot-by-slot (see _storage.py) - not AST heuristics. Slither is used only for
the semantic questions the layout JSON cannot answer: is this contract behind a
proxy, and is a given variable reserved gap space.

Exclusions handled:
  3c.1 appended strictly after all existing variables: falls directly out of
       slot comparison - no pre-existing variable's slot or type changed, so
       there is nothing to report. This is why P3c-01 and N3c-01 are separated
       by resulting slot assignment alone.
  3c.2 change consumes a declared __gap with matching size reduction: a
       reserved gap is identified structurally (a fixed-size array that no
       function ever reads or writes), and its shift is forgiven only when its
       END slot is unchanged, i.e. it absorbed exactly what was inserted.
  3c.3 contract is not actually behind a proxy: see is_proxy_deployed().
  3c.4 constant/immutable: solc omits them from the storage layout entirely,
       so they can never produce a diff here.
"""

from pathlib import Path

from slither.slithir.operations import LowLevelCall, NewContract

from ._shared import (
    accept_finding,
    defines_init_machinery,
    emit,
    is_test_path_segments,
    parse,
)
from ._storage import (
    canonical_type,
    keyed_entries,
    namespaced_struct_layouts,
    slot_span,
    storage_layouts,
)

RULE_ID = "3c"


def _is_proxy_shaped(contract) -> bool:
    """A proxy delegates unmatched calls: it has a fallback and performs a
    delegatecall. Checked structurally, not by contract name.

    The fallback requirement matters: an upgradeable implementation such as
    UUPSUpgradeable also contains delegatecall (in its upgrade machinery), so
    delegatecall alone would misclassify implementations as proxies.
    """
    if contract.fallback_function is None:
        return False
    for fn in contract.functions:
        for ir in fn.all_slithir_operations():
            if isinstance(ir, LowLevelCall) and ir.function_name == "delegatecall":
                return True
        if any(node.type.name == "ASSEMBLY" for node in fn.nodes):
            return True
    return False


def _constructed_with_proxy(contract, slither_obj) -> bool:
    """Some contract in the unit builds both `contract` and a proxy in one
    function - the deploy-behind-a-proxy factory pattern."""
    for other in slither_obj.contracts:
        for fn in other.functions:
            built = [
                ir.contract_name
                for ir in fn.all_slithir_operations()
                if isinstance(ir, NewContract)
            ]
            if str(contract.name) not in [str(b) for b in built]:
                continue
            for name in built:
                target = next(
                    (c for c in slither_obj.contracts if c.name == str(name)), None
                )
                if target is not None and _is_proxy_shaped(target):
                    return True
    return False


def is_proxy_deployed(contract, slither_obj) -> bool:
    """Exclusion 3c.3. Requires POSITIVE evidence that old storage persists
    under a new implementation; absent that, the layout change is meaningless
    and we discard (RULES.md precision-first tie-break).

    Signal A - self-declaration: the contract carries one-shot initialization
    machinery. A contract meant for proxy deployment cannot use a constructor
    for setup, because constructor code never runs against proxy storage, so it
    must be initializer-based. This is the definitional signature.

    Signal B - in-unit corroboration: a factory/deploy contract constructs this
    contract together with a proxy-shaped contract.
    """
    if defines_init_machinery(contract):
        return True
    return _constructed_with_proxy(contract, slither_obj)


def _reserved_gap_labels(contract) -> set:
    """Labels of state variables that are pure reserved space: fixed-size
    arrays that no function or modifier ever reads or writes. Structural, so it
    does not depend on the `__gap` naming convention."""
    accessed = set()
    for fn in list(contract.functions) + list(contract.modifiers):
        accessed.update(fn.all_state_variables_read())
        accessed.update(fn.all_state_variables_written())
    accessed_names = {v.name for v in accessed}
    out = set()
    for var in contract.state_variables:
        if var.name in accessed_names:
            continue
        if str(var.type).endswith("]") and "[]" not in str(var.type):
            out.add(var.name)
    return out


def _namespaced_collision(structs_b: dict, structs_a: dict) -> bool:
    """True iff a member that exists in BOTH commits moved within its ERC-7201
    struct, or changed type.

    Exclusion 3c.1 falls out of this exactly as it does in the OZ 4 path: a
    member appended after every existing one leaves each pre-existing member at
    its original slot/offset, so there is nothing to report. Members that exist
    only in the new commit are ignored; members that were removed are ignored
    too, because any resulting shift is caught on the members that survived.
    """
    for sname, members_b in structs_b.items():
        members_a = structs_a.get(sname)
        if members_a is None:
            continue  # struct gone at N
        for mname, before in members_b.items():
            after = members_a.get(mname)
            if after is None:
                continue
            if (
                before["slot"] != after["slot"]
                or before["offset"] != after["offset"]
                # RC-AST1: same identity-not-raw-string rule as the OZ 4 path.
                # These come from Slither rather than solc so they carry no
                # astId today, but normalising both paths keeps the comparison
                # semantics identical and stops the trap reappearing here.
                or canonical_type(before["type"]) != canonical_type(after["type"])
            ):
                return True
    return False


def run(before_path: Path, after_path: Path, case_meta: dict) -> bool:
    """Returns True iff Rule 3c fires on this before/after pair."""
    if is_test_path_segments(case_meta.get("source_path", after_path)):
        return False

    layouts_b = storage_layouts(before_path)
    layouts_a = storage_layouts(after_path)
    after_sl = parse(after_path)
    after_contracts = {c.name: c for c in after_sl.contracts}
    # Computed lazily below only if a contract's compiler layout is empty.
    ns_layouts_b = ns_layouts_a = None

    for cname, layout_b in layouts_b.items():
        layout_a = layouts_a.get(cname)
        if layout_a is None:
            continue  # contract gone at N
        contract_a = after_contracts.get(cname)
        if contract_a is None:
            continue

        # Exclusion 3c.3 - the decisive gate.
        if not is_proxy_deployed(contract_a, after_sl):
            continue

        gaps = _reserved_gap_labels(contract_a)
        entries_b = keyed_entries(layout_b)
        entries_a = keyed_entries(layout_a)

        if not entries_b and not entries_a:
            # OZ 5 mode. The compiler layout is empty, which for an upgradeable
            # contract means its state lives in an ERC-7201 namespaced struct
            # (finding 3x-L3). Fall back to comparing member offsets computed
            # from the AST. Selected per contract by what the compiler actually
            # reported - there is no global version switch.
            if ns_layouts_b is None:
                ns_layouts_b = namespaced_struct_layouts(parse(before_path))
                ns_layouts_a = namespaced_struct_layouts(after_sl)
            if _namespaced_collision(
                ns_layouts_b.get(cname, {}), ns_layouts_a.get(cname, {})
            ):
                # DESIGN-L2: only attribute to a contract declared in a file
                # actually changed in this commit.
                if not accept_finding(contract_a, case_meta):
                    continue
                emit(
                    case_meta, RULE_ID, decl=contract_a,
                    detail=(
                        f"{cname}'s ERC-7201 namespaced storage struct changed member "
                        f"layout between commits on a proxy-deployed contract: an "
                        f"upgrade would read existing storage through shifted offsets"
                    ),
                    evidence={
                        "owasp": "SC10", "mode": "erc7201-namespaced",
                        "proxy_deployed": True,
                        "collision_before": False, "collision_after": True,
                    },
                )
                return True
            continue

        for key, entry_b in entries_b.items():
            entry_a = entries_a.get(key)
            if entry_a is None:
                continue  # variable removed; any resulting shift is caught on
                          # the variables that did survive
            same_slot = entry_b["slot"] == entry_a["slot"]
            same_offset = entry_b["offset"] == entry_a["offset"]
            # RC-AST1: compare type IDENTITY, not solc's raw string. The raw
            # string embeds the declaring node's astId, which renumbers on any
            # unrelated declaration added earlier in the file, so comparing it
            # directly reports a type change on refactors that moved no storage.
            same_type = canonical_type(entry_b["type"]) == canonical_type(
                entry_a["type"]
            )
            if same_slot and same_offset and same_type:
                continue

            # Exclusion 3c.2: reserved gap that absorbed the insertion, i.e.
            # its end slot is unchanged.
            if key[0] in gaps:
                end_b = int(entry_b["slot"]) + slot_span(entry_b, layout_b["types"])
                end_a = int(entry_a["slot"]) + slot_span(entry_a, layout_a["types"])
                if end_b == end_a:
                    continue
            # DESIGN-L2: only attribute to a contract declared in a file
            # actually changed in this commit.
            if not accept_finding(contract_a, case_meta):
                continue

            emit(
                case_meta, RULE_ID, decl=contract_a,
                detail=(
                    f"{cname}.{key[0]} moved in the storage layout between commits "
                    f"(slot {entry_b['slot']}->{entry_a['slot']}, offset "
                    f"{entry_b['offset']}->{entry_a['offset']}) on a proxy-deployed "
                    f"contract: an upgrade would read existing storage at the wrong slot"
                ),
                evidence={
                    "owasp": "SC10", "mode": "declared-layout",
                    "variable": key[0], "proxy_deployed": True,
                    "slot_before": entry_b["slot"], "slot_after": entry_a["slot"],
                    "offset_before": entry_b["offset"], "offset_after": entry_a["offset"],
                    "type_before": entry_b["type"], "type_after": entry_a["type"],
                },
            )
            return True
    return False
