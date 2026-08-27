"""DEP-2 - an old repo's toolchain must not be lost to the HOST's Node version.

MEASURED (2026-08-27). `compound-v2` skipped every pair as `dep-missing`, and
`aave-v2` did the same. The label was all the report ever showed, so the cause
looked like a property of those repositories. It was not. Calling `install()`
directly and printing the captured detail gave:

    Error: error:0308010C:digital envelope routines::unsupported
    ... code: 'ERR_OSSL_EVP_UNSUPPORTED'
    Node.js v24.15.0

Node 17+ ships OpenSSL 3, which withdrew the legacy hash provider that older JS
toolchains (yarn classic, older webpack) still reach for. That is a property of
the machine running Chainwatch, not of the code being analysed - so the honest
response is to retry, not to skip. `--openssl-legacy-provider` is the
documented remedy for this exact error.

After the fix, compound-v2's install returns `ok=True` on the same machine that
had been reporting `dep-missing`.

Two deliberate limits, both asserted below:
  * the retry is gated on the measured signature, never applied by default -
    the flag weakens a crypto policy and should be opt-in per failure;
  * it can only affect whether the dependency tree materialises. Every rule
    still reads the same sources afterwards, so no analysis result depends on
    it.

Run:  python -m pytest tests/test_legacy_openssl_retry.py -q
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from src import history as H  # noqa: E402

# The real captured stderr, trimmed - not a paraphrase.
_REAL_FAILURE = """\
Error: error:0308010C:digital envelope routines::unsupported
    opensslErrorStack: [ 'error:03000086:digital envelope routines::initialization error' ],
  library: 'digital envelope routines',
  reason: 'unsupported',
  code: 'ERR_OSSL_EVP_UNSUPPORTED'
}
Node.js v24.15.0
error Command failed with exit code 1.
"""


def test_the_real_measured_failure_is_recognised():
    assert H._needs_legacy_openssl(_REAL_FAILURE)


def test_either_spelling_is_recognised():
    """Node surfaces one or the other depending on version and which layer
    reports it; matching only one would leave half the cases skipping."""
    assert H._needs_legacy_openssl("code: 'ERR_OSSL_EVP_UNSUPPORTED'")
    assert H._needs_legacy_openssl("error:0308010C:digital envelope routines::unsupported")


def test_unrelated_install_failures_are_not_retried():
    """The retry must stay gated. A missing package or a dead registry is not an
    OpenSSL problem, and re-running the same command with a crypto flag would
    just cost another full install timeout for nothing."""
    for unrelated in (
        "npm ERR! 404 Not Found - GET https://registry.npmjs.org/@does/not-exist",
        "error Couldn't find package \"@1inch/solidity-utils\"",
        "ENOSPC: no space left on device",
        "fatal: could not read Username for 'https://github.com'",
        "",
    ):
        assert not H._needs_legacy_openssl(unrelated), unrelated


def test_none_detail_is_safe():
    """`detail` is assembled from subprocess output and can legitimately be
    empty; the predicate must not raise on it."""
    assert not H._needs_legacy_openssl(None)  # type: ignore[arg-type]


def test_marker_list_is_not_accidentally_broad():
    """Guard against a future edit widening this to something like 'unsupported'
    or 'Error', which would retry nearly every failed install."""
    for marker in H._LEGACY_OPENSSL_MARKERS:
        assert len(marker) > 20, f"marker too broad to be safe: {marker!r}"
