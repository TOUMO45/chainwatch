"""DEP-1 - an explicit `remappings.txt` must not defeat `absolute=True`.

THE BUG, measured end to end (2026-08-27). `derive_remaps(root, absolute=True)`
exists so a trajectory walker can compile two checkouts at once without either
side resolving against the other's dependencies - its own docstring says a
relative remapping "would resolve against whichever cwd happens to be current".

But a repository's own `remappings.txt` is appended LAST, deliberately, so an
explicit entry beats a derived one (solc takes the last matching remapping for a
prefix). Those files hold checkout-relative targets, so the appended relative
entry silently overrode the absolute one that had just been derived for the very
same prefix. Slither is invoked with no cwd, so solc then ran from Chainwatch's
own root, `node_modules/...` pointed at a directory that does not exist there,
and every import failed as "not found" - on a dependency tree that was installed
correctly the entire time.

Cost, measured on real repositories before the fix:
    1inch/swap-vm    0 of 1160 rule invocations survived   (0.0%)
    1inch/aqua       27 of 38 file comparisons lost       (28.9% ok)
After the fix, both compile completely: 80/80 and 40/40 rule invocations.

The fix keeps BOTH design intents instead of trading one for the other: the
explicit entry still wins (its prefix mapping is untouched), and it is made
cwd-independent (its target is re-rooted onto the checkout it came from).

Run:  python -m pytest tests/test_remap_absolutize.py -q
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from src.history import _absolutize_remap, derive_remaps  # noqa: E402


# ------------------------------------------------------- _absolutize_remap


def test_relative_target_is_rerooted(tmp_path):
    (tmp_path / "node_modules" / "@scope" / "pkg").mkdir(parents=True)
    out = _absolutize_remap("@scope/pkg/=node_modules/@scope/pkg/", tmp_path)
    prefix, _, target = out.partition("=")
    assert prefix == "@scope/pkg/"
    assert Path(target).is_absolute()
    assert target.endswith("/"), "trailing slash is load-bearing for solc"
    assert "node_modules/@scope/pkg" in target.replace("\\", "/")


def test_absolute_target_is_left_alone(tmp_path):
    entry = f"@scope/pkg/={(tmp_path / 'x').as_posix()}/"
    assert _absolutize_remap(entry, tmp_path) == entry


def test_prefix_is_never_altered(tmp_path):
    """Only the TARGET may move. Changing the prefix would change which imports
    match, i.e. silently re-point real source files."""
    out = _absolutize_remap("forge-std/=node_modules/forge-std/src/", tmp_path)
    assert out.startswith("forge-std/=")


def test_entry_without_target_is_returned_unchanged(tmp_path):
    assert _absolutize_remap("broken-line-no-equals", tmp_path) == \
        "broken-line-no-equals"


def test_missing_trailing_slash_is_not_invented(tmp_path):
    """solc does literal prefix substitution; adding a slash the author did not
    write would corrupt every import through that prefix."""
    out = _absolutize_remap("a/=node_modules/a", tmp_path)
    assert not out.endswith("/")


# ------------------------------------------------------- derive_remaps


def _tree(root: Path):
    """A checkout that imports one package AND ships a relative remappings.txt
    for it - the exact shape that produced the bug."""
    (root / "node_modules" / "@1inch" / "solidity-utils").mkdir(parents=True)
    (root / "contracts").mkdir()
    (root / "contracts" / "A.sol").write_text(
        'import "@1inch/solidity-utils/contracts/libraries/Calldata.sol";\n',
        encoding="utf-8")
    (root / "remappings.txt").write_text(
        "@1inch/solidity-utils/=node_modules/@1inch/solidity-utils/\n",
        encoding="utf-8")


def test_absolute_mode_emits_no_relative_target(tmp_path):
    """THE REGRESSION GUARD. Every target must be absolute - one relative
    survivor for an already-mapped prefix is all it took to lose a whole
    repository's coverage."""
    _tree(tmp_path)
    remaps = derive_remaps(tmp_path, absolute=True)
    assert remaps, "expected at least the imported package's remapping"
    for entry in remaps:
        _prefix, _, target = entry.partition("=")
        assert Path(target).is_absolute(), f"relative target survived: {entry}"


def test_explicit_entry_still_wins(tmp_path):
    """The behaviour the append order exists to provide must be preserved: the
    remappings.txt entry is still LAST for its prefix, so solc still prefers it."""
    _tree(tmp_path)
    remaps = derive_remaps(tmp_path, absolute=True)
    matching = [i for i, e in enumerate(remaps)
                if e.startswith("@1inch/solidity-utils/=")]
    assert len(matching) >= 2, "expected both a derived and an explicit entry"
    # The explicit one is last, and it points at the real package directory.
    last = remaps[matching[-1]]
    assert last.partition("=")[2].replace("\\", "/").rstrip("/").endswith(
        "node_modules/@1inch/solidity-utils")


def test_relative_mode_is_unchanged(tmp_path):
    """`absolute=False` is what the fixture scorer uses; it must keep emitting
    checkout-relative targets exactly as before."""
    _tree(tmp_path)
    remaps = derive_remaps(tmp_path, absolute=False)
    assert any(e == "@1inch/solidity-utils/=node_modules/@1inch/solidity-utils/"
               for e in remaps)
