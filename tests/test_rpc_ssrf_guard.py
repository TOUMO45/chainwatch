"""SEC-L2 - a remote caller must not be able to point Chainwatch's own
outbound RPC request at internal network space.

THE REAL RISK, MEASURED. `webapp/server.py`'s `ScanRequest.rpc_url` is a
plain string field on a public HTTP API with zero validation anywhere in the
call chain before it reached `Web3.HTTPProvider(rpc_url)` (confirmed by
reading every caller: chainwatch.py's CLI flag, webapp/server.py,
src/anchor.py all pass it straight through). On a Cloud Run deployment -
this project's own included - that is a textbook SSRF primitive: a remote,
unauthenticated caller can make the service issue an HTTP request to any URL
they choose, including 169.254.169.254 (the cloud metadata endpoint, which
on GCP answers unauthenticated requests carrying the service account's own
OAuth token) or any other address the container can reach that a public
caller could not reach directly.

Run:  python -m pytest tests/test_rpc_ssrf_guard.py -q
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from src.liveness import _validate_rpc_url  # noqa: E402


def test_a_plain_public_https_url_passes(monkeypatch):
    """The common case must not be collateral damage. DNS is mocked so this
    test is hermetic (no real network dependency, no flakiness in a sandbox
    that may have no outbound network at all)."""
    import socket as socket_mod

    def fake_getaddrinfo(host, port):
        assert host == "mainnet.example-rpc.com"
        return [(socket_mod.AF_INET, socket_mod.SOCK_STREAM, 6, "",
                 ("93.184.216.34", 0))]

    monkeypatch.setattr(socket_mod, "getaddrinfo", fake_getaddrinfo)
    _validate_rpc_url("https://mainnet.example-rpc.com/v2/abc123")  # must not raise


def test_a_literal_public_ip_passes():
    """No mock needed: resolving a literal IP is a local parse, not a real
    DNS round trip, so this is hermetic even offline."""
    _validate_rpc_url("http://93.184.216.34:8545")  # must not raise


@pytest.mark.parametrize("url", [
    "http://169.254.169.254/latest/meta-data/",  # GCP/AWS/Azure metadata
    "http://169.254.169.254/computeMetadata/v1/",
    "http://127.0.0.1:8545",
    "http://localhost:8545",
    "http://10.0.0.5:8545",       # RFC1918
    "http://172.16.5.1:8545",     # RFC1918
    "http://172.31.255.1:8545",   # RFC1918 (top of the 172.16/12 range)
    "http://192.168.1.1:8545",    # RFC1918
    "http://0.0.0.0:8545",        # unspecified
    "http://[::1]:8545",          # IPv6 loopback
    "http://[fe80::1]:8545",      # IPv6 link-local
])
def test_a_metadata_or_private_range_target_is_refused(url):
    """Every one of these is a literal IP, so resolution needs no network -
    the guard must reject on the address itself, not on a mocked DNS
    answer."""
    with pytest.raises(RuntimeError, match="non-public address"):
        _validate_rpc_url(url)


@pytest.mark.parametrize("url", [
    "file:///etc/passwd",
    "gopher://127.0.0.1:8545/_GET%20/",
    "ftp://example.com/",
    "ws://example.com/",
])
def test_a_non_http_scheme_is_refused(url):
    with pytest.raises(RuntimeError, match="http"):
        _validate_rpc_url(url)


def test_a_url_with_no_host_is_refused():
    with pytest.raises(RuntimeError, match="no host"):
        _validate_rpc_url("http:///just/a/path")


def test_a_hostname_that_will_not_resolve_fails_cleanly_not_with_a_crash(monkeypatch):
    """Matches this project's honest-refusal discipline: an RPC endpoint
    that cannot even be resolved must be reported as a clear, specific
    RuntimeError - never an uncaught socket.gaierror bubbling out of a
    layer that is supposed to give the caller an actionable reason."""
    import socket as socket_mod

    def fake_getaddrinfo(host, port):
        raise socket_mod.gaierror("Name or service not known")

    monkeypatch.setattr(socket_mod, "getaddrinfo", fake_getaddrinfo)
    with pytest.raises(RuntimeError, match="could not be resolved"):
        _validate_rpc_url("https://this-host-does-not-exist.example")


def test_a_second_resolved_address_is_also_checked(monkeypatch):
    """A hostname can carry multiple A/AAAA records. An attacker controlling
    DNS for their own domain could list a public decoy first and a private
    address second - every returned address must be checked, not just the
    first."""
    import socket as socket_mod

    def fake_getaddrinfo(host, port):
        return [
            (socket_mod.AF_INET, socket_mod.SOCK_STREAM, 6, "", ("93.184.216.34", 0)),
            (socket_mod.AF_INET, socket_mod.SOCK_STREAM, 6, "", ("169.254.169.254", 0)),
        ]

    monkeypatch.setattr(socket_mod, "getaddrinfo", fake_getaddrinfo)
    with pytest.raises(RuntimeError, match="non-public address"):
        _validate_rpc_url("https://multi-homed.example")
