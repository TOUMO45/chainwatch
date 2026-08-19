"""COMP-L1: a Foundry repository compiles to NOTHING without `forge` installed.

crytic-compile picks its platform from the tree, not from the file: any `.sol`
with a `foundry.toml` anywhere above it is routed to the Foundry platform,
which shells out to `forge`. With no `forge` on PATH that call raises
`FileNotFoundError` inside `Foundry.config()` - BEFORE any compiler has read
the source - so every file of every Foundry repo is uncompilable and the whole
scan reports coverage it never had. This is an ecosystem-wide hole, not one
repository's quirk; Foundry is the dominant Solidity toolchain.

The fix is a fallback and only a fallback: retry once with the Foundry platform
disabled, and ONLY when `forge` is absent, because a `forge` that exists and
fails has told us something real about the sources that bare solc would erase.

Every assertion below is about `fixtures-foundry/`, frozen by `guard.sh`. See
that directory's README for what each file pays for.

NO NETWORK, and no `forge`: if a machine running these tests HAS forge
installed, the arming tests skip rather than silently asserting nothing - a
skipped test is visible, a vacuous pass is not.
"""

from __future__ import annotations

import shutil
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from src.rules import _shared  # noqa: E402

FIX = ROOT / "fixtures-foundry"
FOUNDRY_VAULT = FIX / "project" / "src" / "Vault.sol"
FOUNDRY_BROKEN = FIX / "project" / "src" / "Broken.sol"
PLAIN_BROKEN = FIX / "plain" / "Broken.sol"

forge_installed = shutil.which("forge") is not None
needs_no_forge = pytest.mark.skipif(
    forge_installed,
    reason="`forge` is installed on this machine, so the fallback is correctly "
           "disarmed and there is nothing here to observe",
)


@pytest.fixture(autouse=True)
def _clean_parse_cache():
    """`parse` memoises successes AND failures. Without this, the first test to
    touch a file would decide the answer for every later one."""
    _shared.reset_caches()
    yield
    _shared.reset_caches()


# ---------------------------------------------------------------------------
# The fixture set says what it claims to say
# ---------------------------------------------------------------------------

def test_fixture_shape_is_what_the_tests_assume():
    """Guard against a vacuous suite. Every test below is meaningless if the
    Foundry marker is missing or if the control is not really a control."""
    assert (FIX / "project" / "foundry.toml").is_file()
    assert FOUNDRY_VAULT.is_file() and FOUNDRY_BROKEN.is_file()
    assert PLAIN_BROKEN.is_file()
    # The control must be the SAME source, so a difference in outcome can only
    # come from the platform decision.
    assert PLAIN_BROKEN.read_bytes() == FOUNDRY_BROKEN.read_bytes()
    # ...and it must not itself sit inside a Foundry project, at any depth.
    assert not any((p / "foundry.toml").is_file() for p in PLAIN_BROKEN.parents)


def test_predicate_agrees_with_crytic_compiles_own_detection():
    """The gate asks crytic-compile where the project root is; it does not
    re-implement the rule. A file in the tree resolves to the tree's root."""
    root = _shared.foundry_project_root(FOUNDRY_VAULT)
    assert root is not None
    assert Path(root).resolve() == (FIX / "project").resolve()
    assert _shared.foundry_project_root(PLAIN_BROKEN) is None


# ---------------------------------------------------------------------------
# The fallback fires - and only where it should
# ---------------------------------------------------------------------------

@needs_no_forge
def test_primary_path_alone_cannot_compile_a_foundry_file():
    """The defect itself, asserted rather than described. This is what every
    file of a Foundry repository does today without the fallback: it fails on a
    MISSING EXECUTABLE, having never looked at the Solidity."""
    with pytest.raises(Exception) as excinfo:
        _shared._compile_attempt(FOUNDRY_VAULT)
    assert isinstance(excinfo.value, FileNotFoundError)


@needs_no_forge
def test_fallback_compiles_the_same_file():
    """...and this is the fix: the identical file, through `parse`, yields a
    real analysis. No skip, no partial - the contract is there to be analysed."""
    slither = _shared.parse(FOUNDRY_VAULT)
    assert "Vault" in [c.name for c in slither.contracts]


@needs_no_forge
def test_fallback_is_the_only_retry_and_the_primary_is_tried_first():
    """Fallback, not override. The unchanged attempt runs FIRST; the second
    attempt happens only after it raised, and carries exactly one difference."""
    calls = []
    real = _shared._compile_attempt

    def spy(path, **extra):
        calls.append(dict(extra))
        return real(path, **extra)

    _shared._compile_attempt = spy
    try:
        _shared._compile(FOUNDRY_VAULT)
    finally:
        _shared._compile_attempt = real

    assert calls == [{}, {"foundry_ignore": True}]


def test_a_non_foundry_failure_is_never_retried():
    """The narrowness of the gate, from the other side. A plain broken file
    fails once and stays failed - no second platform is tried, so no unrelated
    compile error can be quietly converted into a different one."""
    calls = []
    real = _shared._compile_attempt

    def spy(path, **extra):
        calls.append(dict(extra))
        return real(path, **extra)

    _shared._compile_attempt = spy
    try:
        with pytest.raises(Exception):
            _shared._compile(PLAIN_BROKEN)
    finally:
        _shared._compile_attempt = real

    assert calls == [{}], "a non-Foundry failure must not arm the fallback"


def test_fallback_stays_disarmed_when_forge_exists(monkeypatch):
    """NEVER unconditional. On a machine that HAS forge, a Foundry build that
    fails is a real result about the sources, and retrying under bare solc
    would erase it. Forcing the platform would raise the coverage number and
    that is precisely why it is refused.

    `forge` is faked at the `shutil.which` boundary rather than installed:
    CHARTER rule 3 reserves new dependencies for the human, and a real forge
    would be one more target-adjacent binary to reason about (WALK-L9)."""
    monkeypatch.setattr(
        _shared.shutil, "which",
        lambda name, *a, **k: "/fake/bin/forge" if name == "forge" else None,
    )
    assert _shared.foundry_toolchain_absent() is False
    assert _shared._foundry_platform_unusable(FOUNDRY_VAULT) is False

    calls = []
    real = _shared._compile_attempt

    def spy(path, **extra):
        calls.append(dict(extra))
        return real(path, **extra)

    monkeypatch.setattr(_shared, "_compile_attempt", spy)
    with pytest.raises(Exception):
        _shared._compile(FOUNDRY_VAULT)
    assert calls == [{}], "forge present -> the framework's own failure stands"


# ---------------------------------------------------------------------------
# Nothing is masked
# ---------------------------------------------------------------------------

@needs_no_forge
def test_a_genuine_syntax_error_still_surfaces_as_itself():
    """The requirement that makes this safe to ship. A real syntax error inside
    a Foundry repo must reach the caller as the COMPILER's complaint, not as
    "forge is missing" and not as silence."""
    with pytest.raises(Exception) as excinfo:
        _shared.parse(FOUNDRY_BROKEN)
    message = str(excinfo.value)
    assert "Expected primary expression" in message
    assert "Broken.sol" in message
    assert not isinstance(excinfo.value, FileNotFoundError)


@needs_no_forge
def test_the_error_is_the_same_one_the_control_produces():
    """Stated as an equality so it cannot drift into a weaker claim: identical
    source, one inside a Foundry tree and one outside, must fail identically."""
    with pytest.raises(Exception) as inside:
        _shared.parse(FOUNDRY_BROKEN)
    _shared.reset_caches()
    with pytest.raises(Exception) as outside:
        _shared.parse(PLAIN_BROKEN)

    assert type(inside.value) is type(outside.value)

    def normalise(exc, path):
        """Erase only the file's LOCATION, keeping the diagnostic itself.

        Both spellings are erased because solc reports whichever it was handed:
        an absolute path here, a cwd-relative one there. Missing either would
        leave a path difference in the string and make this assertion fail for
        a reason that has nothing to do with masking.
        """
        text = str(exc)
        absolute = str(path.resolve()).replace("\\", "/")
        relative = path.resolve().relative_to(ROOT).as_posix()
        for form in (absolute, relative):
            text = text.replace(form, "<FILE>")
        return text

    assert (normalise(inside.value, FOUNDRY_BROKEN)
            == normalise(outside.value, PLAIN_BROKEN))
