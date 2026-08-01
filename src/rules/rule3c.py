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

from ._shared import defines_init_machinery, is_test_path, parse
from ._storage import keyed_entries, slot_span, storage_layouts

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


def run(before_path: Path, after_path: Path, case_meta: dict) -> bool:
    """Returns True iff Rule 3c fires on this before/after pair."""
    if is_test_path(case_meta.get("source_path", after_path)):
        return False

    layouts_b = storage_layouts(before_path)
    layouts_a = storage_layouts(after_path)
    after_sl = parse(after_path)
    after_contracts = {c.name: c for c in after_sl.contracts}

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

        for key, entry_b in entries_b.items():
            entry_a = entries_a.get(key)
            if entry_a is None:
                continue  # variable removed; any resulting shift is caught on
                          # the variables that did survive
            same_slot = entry_b["slot"] == entry_a["slot"]
            same_offset = entry_b["offset"] == entry_a["offset"]
            same_type = entry_b["type"] == entry_a["type"]
            if same_slot and same_offset and same_type:
                continue

            # Exclusion 3c.2: reserved gap that absorbed the insertion, i.e.
            # its end slot is unchanged.
            if key[0] in gaps:
                end_b = int(entry_b["slot"]) + slot_span(entry_b, layout_b["types"])
                end_a = int(entry_a["slot"]) + slot_span(entry_a, layout_a["types"])
                if end_b == end_a:
                    continue

            return True
    return False
