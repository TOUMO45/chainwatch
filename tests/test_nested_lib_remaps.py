"""COMP-L2 - nested Foundry submodules, reopened and fixed 2026-08-27.

COMP-L2 was recorded for a long time as an UNFIXABLE charter boundary. The
stated reasoning: deeply nested submodules each resolve imports in their own
remapping context, "bare solc holds one flat remapping set", and the only tool
that resolves this correctly is `forge` - which CHARTER rule 3 forbids
installing (WALK-L9 RCE class).

**The reasoning was wrong.** solc has long accepted context-dependent
remappings of the form `context:prefix=target`, where `context` restricts the
remapping to imports made from files underneath it. That is precisely the
mechanism `forge remappings` emits, and it needs no new dependency at all - so
the charter was never actually the binding constraint here.

Measured on a tree where the root and a submodule pin DIFFERENT versions of the
same dependency (this test rebuilds exactly that tree):

    flat      lib/A/src/A.sol  "dep/D.sol" -> lib/dep/src/D.sol        (root's)
    context   lib/A/src/A.sol  "dep/D.sol" -> lib/A/lib/dep/src/D.sol  (its own)

Note what the flat row shows: not a compile failure, but a SILENT resolution to
the WRONG dependency. COMP-L2 was filed as a coverage ceiling; it was also, and
undetected, a correctness hazard - a rule could read a different version of a
library than the one the submodule actually builds against, and compare two
commits through it.

Run:  python -m pytest tests/test_nested_lib_remaps.py -q
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from src.history import _foundry_lib_remaps  # noqa: E402

_LIB = ("// SPDX-License-Identifier: MIT\npragma solidity ^0.8.0;\n"
        "library D {{ function v() internal pure returns (uint) {{ return {}; }} }}\n")


def _nested_tree(root: Path, *, nested_has_sources: bool = True) -> None:
    """Root pins dep v1; submodule A pins its OWN dep v2 underneath lib/A/lib."""
    (root / "src").mkdir(parents=True)
    (root / "lib" / "dep" / "src").mkdir(parents=True)
    (root / "lib" / "A" / "src").mkdir(parents=True)
    (root / "lib" / "A" / "lib" / "dep" / "src").mkdir(parents=True)

    (root / "lib" / "dep" / "src" / "D.sol").write_text(_LIB.format(1), encoding="utf-8")
    if nested_has_sources:
        (root / "lib" / "A" / "lib" / "dep" / "src" / "D.sol").write_text(
            _LIB.format(2), encoding="utf-8")
    (root / "lib" / "A" / "src" / "A.sol").write_text(
        '// SPDX-License-Identifier: MIT\npragma solidity ^0.8.0;\n'
        'import "dep/D.sol";\ncontract A {}\n', encoding="utf-8")
    (root / "src" / "Root.sol").write_text(
        '// SPDX-License-Identifier: MIT\npragma solidity ^0.8.0;\n'
        'import "A/A.sol";\ncontract Root {}\n', encoding="utf-8")


def _by_prefix(remaps: list[str], prefix: str) -> list[str]:
    return [r for r in remaps if r.startswith(prefix)]


def test_nested_submodule_gets_a_context_scoped_remap(tmp_path):
    """THE FIX. A nested `lib/A/lib/dep` must produce a remapping scoped to
    `lib/A/`, so imports from inside A resolve to A's own copy."""
    _nested_tree(tmp_path)
    remaps = _foundry_lib_remaps(tmp_path, absolute=False)
    scoped = _by_prefix(remaps, "lib/A/:dep/=")
    assert scoped, f"no context-scoped remapping emitted; got {remaps}"
    assert scoped[0] == "lib/A/:dep/=lib/A/lib/dep/src/"


def test_root_level_remaps_stay_unscoped(tmp_path):
    """Regression guard: the top-level behaviour must be byte-identical to
    before, or every existing repository's remapping set silently changes."""
    _nested_tree(tmp_path)
    remaps = _foundry_lib_remaps(tmp_path, absolute=False)
    assert "dep/=lib/dep/src/" in remaps, "root remapping lost its unscoped form"
    assert "A/=lib/A/src/" in remaps


def test_flat_tree_is_completely_unchanged(tmp_path):
    """A repository with no nested libs must emit exactly what it always did -
    no contexts, no new entries."""
    (tmp_path / "lib" / "dep" / "src").mkdir(parents=True)
    (tmp_path / "lib" / "dep" / "src" / "D.sol").write_text(_LIB.format(1),
                                                            encoding="utf-8")
    remaps = _foundry_lib_remaps(tmp_path, absolute=False)
    assert remaps == ["dep/=lib/dep/src/"]
    assert not any(":" in r for r in remaps), "a flat tree must produce no contexts"


def test_empty_nested_submodule_is_not_remapped(tmp_path):
    """An uninitialised git submodule leaves an EMPTY `lib/A/lib/dep`. Remapping
    onto it would break imports that currently resolve - accidentally but
    usefully - through the root-level copy, turning a working scan into a broken
    one. Descend past it, but do not remap onto nothing."""
    _nested_tree(tmp_path, nested_has_sources=False)
    remaps = _foundry_lib_remaps(tmp_path, absolute=False)
    assert not _by_prefix(remaps, "lib/A/:dep/="), \
        "remapped onto an empty (uninitialised) submodule"
    assert "dep/=lib/dep/src/" in remaps, "root fallback must remain available"


def test_absolute_mode_never_emits_an_unparseable_context(tmp_path):
    """A context containing a colon is unparseable by solc's
    `context:prefix=target` grammar - and a Windows absolute path IS one
    (`C:/...`).

    MEASURED: solc then takes `C` as the context, and because context matching
    is a plain string prefix, `C` matches every source unit on that drive. The
    observed result was a silently WRONG resolution rather than an error, which
    is strictly worse than not emitting the remapping at all.

    On POSIX (including the Linux container this deploys to) absolute contexts
    contain no colon and ARE emitted, so the fix is live there.
    """
    _nested_tree(tmp_path)
    remaps = _foundry_lib_remaps(tmp_path, absolute=True)
    for entry in remaps:
        context = entry.partition("=")[0]
        if ":" in context:
            ctx = context.rpartition(":")[0]
            assert ":" not in ctx, (
                f"emitted an unparseable context (colon inside context): {entry}")


def test_recursion_is_depth_bounded(tmp_path):
    """A pathological or symlinked tree must not walk forever."""
    deep = tmp_path
    for _ in range(12):
        deep = deep / "lib" / "x"
    (deep / "src").mkdir(parents=True)
    (deep / "src" / "D.sol").write_text(_LIB.format(9), encoding="utf-8")
    remaps = _foundry_lib_remaps(tmp_path, absolute=False)
    # One entry per level walked. _MAX_LIB_DEPTH bounds it, so a 12-deep tree
    # must NOT produce 12 entries.
    assert len(remaps) <= 6, f"recursion ran past its bound: {remaps}"
