"""COMP-L2: Foundry (submodule + remappings.txt) dependency reconstruction.

Measured on 1inch/cross-chain-swap, which scanned to 0% coverage: every pair was
skipped `dep-missing` although the dependencies were present. Two bugs, both on
the ENV/coverage axis (no rule or verdict is touched here):

  1. the pre-flight skip gate checked `lib/<pkg>` literally and was blind to
     remappings.txt, so `@1inch/solidity-utils` -> `lib/solidity-utils/` read as
     missing though the directory existed;
  2. `derive_remaps` did not replicate forge's lib auto-remapping, so imports
     that rely on it (`@openzeppelin/contracts/...`, `forge-std/...`) had no
     remapping and could not compile.

A wrong auto-remap can only make solc report "file not found" - honest
under-coverage - never a mis-compiled AST, so this cannot manufacture a finding.
"""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from src import history as H  # noqa: E402


def _foundry_tree(tmp: Path) -> Path:
    """A minimal Foundry project: an own contract importing two deps, one mapped
    by remappings.txt and one relying on forge lib auto-remapping."""
    root = tmp / "proj"
    (root / "src").mkdir(parents=True)
    (root / "src" / "Own.sol").write_text(
        'pragma solidity ^0.8.0;\n'
        'import "@1inch/solidity-utils/contracts/A.sol";\n'   # via remappings.txt
        'import "forge-std/Test.sol";\n'                       # via lib auto-remap
        'contract Own {}\n', encoding="utf-8")
    # dependency submodules, present on disk under lib/
    (root / "lib" / "solidity-utils" / "contracts").mkdir(parents=True)
    (root / "lib" / "solidity-utils" / "contracts" / "A.sol").write_text(
        "pragma solidity ^0.8.0; contract A {}", encoding="utf-8")
    (root / "lib" / "solidity-utils" / "package.json").write_text(
        '{"name": "@1inch/solidity-utils"}', encoding="utf-8")
    (root / "lib" / "forge-std" / "src").mkdir(parents=True)
    (root / "lib" / "forge-std" / "src" / "Test.sol").write_text(
        "pragma solidity ^0.8.0; contract Test {}", encoding="utf-8")
    (root / "lib" / "forge-std" / "package.json").write_text(
        '{"name": "forge-std"}', encoding="utf-8")
    (root / "remappings.txt").write_text(
        "@1inch/solidity-utils/=lib/solidity-utils/\n", encoding="utf-8")
    return root


def test_present_foundry_dependencies_are_not_flagged_missing(tmp_path):
    """The regression: both deps ARE on disk, so the skip gate must pass."""
    root = _foundry_tree(tmp_path)
    assert H._missing_imported_packages(root) == set()


def test_a_genuinely_absent_dependency_is_still_flagged(tmp_path):
    """The gate must not become a rubber stamp: an import with no dir and no
    remapping is still missing, so a truly unbuildable pair is still skipped."""
    root = _foundry_tree(tmp_path)
    (root / "src" / "Own.sol").write_text(
        'pragma solidity ^0.8.0;\n'
        'import "@chainlink/contracts/X.sol";\n'
        'contract Own {}\n', encoding="utf-8")
    assert "@chainlink/contracts" in H._missing_imported_packages(root)


def test_derive_remaps_emits_forge_lib_auto_remaps(tmp_path):
    """forge-std/ has no remappings.txt entry; it must resolve via the lib
    auto-remap to the submodule's src dir."""
    root = _foundry_tree(tmp_path)
    remaps = H.derive_remaps(root, absolute=False)
    assert any(r.startswith("forge-std/=") and "lib/forge-std/src/" in r for r in remaps), remaps
    # remappings.txt still present and last, so an explicit mapping wins.
    assert "@1inch/solidity-utils/=lib/solidity-utils/" in remaps


def test_the_gate_ignores_a_dependencys_own_transitive_imports(tmp_path):
    """A submodule's internal import of something absent must NOT skip the whole
    pair: it is the compiler's business per file, not the gate's."""
    root = _foundry_tree(tmp_path)
    # forge-std internally imports a package nothing provides:
    (root / "lib" / "forge-std" / "src" / "Vendor.sol").write_text(
        'pragma solidity ^0.8.0; import "@vendor/deep/Z.sol"; contract V {}',
        encoding="utf-8")
    assert "@vendor/deep" not in H._missing_imported_packages(root)
    # ...and it is genuinely invisible to the scoped import scan:
    assert "@vendor/deep" not in H.imported_packages(root, exclude_deps=True)


def test_a_non_foundry_repo_is_unaffected(tmp_path):
    """No lib/ -> no auto-remaps emitted, so npm/Hardhat repos see no change."""
    root = tmp_path / "npmproj"
    (root / "contracts").mkdir(parents=True)
    (root / "contracts" / "C.sol").write_text(
        'pragma solidity ^0.8.0; import "@openzeppelin/contracts/token/ERC20/ERC20.sol"; contract C {}',
        encoding="utf-8")
    assert H._foundry_lib_remaps(root) == []
    # unresolved and unmapped -> still correctly reported missing
    assert "@openzeppelin/contracts" in H._missing_imported_packages(root)
