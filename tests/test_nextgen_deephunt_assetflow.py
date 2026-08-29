"""Deep Hunt Phase 5 - asset-flow graph + entitlement check + economic feed
(src/nextgen/deephunt/assetflow.py, spec sections 13, 14, 15).

Pure math: no fork needed for the core (measure_on_fork is gated separately).

Run:  python -m pytest tests/test_nextgen_deephunt_assetflow.py -q
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from src.nextgen.deephunt import assetflow as AF  # noqa: E402

E = 10 ** 18


def _flow(att_before, att_after, prot_before, prot_after, other=(0, 0), asset=AF.ETH):
    before = {(AF.ATTACKER, asset): att_before, (AF.PROTOCOL, asset): prot_before,
              (AF.OTHER, asset): other[0]}
    after = {(AF.ATTACKER, asset): att_after, (AF.PROTOCOL, asset): prot_after,
             (AF.OTHER, asset): other[1]}
    return AF.from_balances(before, after)


def test_deltas_and_conservation():
    fl = _flow(10 * E, 15 * E, 1000 * E, 995 * E)
    assert fl.delta(AF.ATTACKER, AF.ETH) == 5 * E
    assert fl.attacker_gain(AF.ETH) == 5 * E
    assert fl.protocol_loss(AF.ETH) == 5 * E
    assert fl.net(AF.ETH) == 0                      # pure transfer, no gas modelled
    assert fl.primary_asset() == AF.ETH


def test_flow_edges_point_protocol_to_attacker():
    fl = _flow(10 * E, 15 * E, 1000 * E, 995 * E)
    edges = fl.derive_edges()
    assert any(e.frm == AF.PROTOCOL and e.to == AF.ATTACKER and e.amount == 5 * E
               for e in edges)


def test_unearned_extraction_when_gain_exceeds_deposit():
    # attacker paid in 1 ETH, walked away with 5 ETH, protocol lost 4
    fl = _flow(10 * E, 14 * E, 1000 * E, 996 * E)
    unearned, why = AF.is_unearned_extraction(fl, deposits=[(AF.ETH, 1 * E)])
    assert unearned is True
    assert "unearned" in why


def test_legitimate_withdrawal_is_not_extraction():
    # attacker deposited 5 ETH then withdrew ~5 ETH back: entitled
    fl = _flow(10 * E, 10 * E, 1000 * E, 1000 * E)  # net zero over deposit+withdraw
    unearned, why = AF.is_unearned_extraction(fl, deposits=[(AF.ETH, 5 * E)])
    assert unearned is False


def test_gain_without_measured_loss_is_inconclusive_not_a_hit():
    fl = _flow(10 * E, 20 * E, 1000 * E, 1000 * E)
    unearned, why = AF.is_unearned_extraction(fl, deposits=[(AF.ETH, 0)])
    assert unearned is False
    assert "inconclusive" in why


def test_quantify_feeds_economics_and_flags_profitable():
    fl = _flow(10 * E, 60 * E, 1000 * E, 950 * E)   # +50 ETH to attacker
    a = AF.assess(fl, {AF.ETH: 3000.0}, gas_units=300_000)
    assert a.attacker_profit_usd is not None and a.attacker_profit_usd > 100_000
    assert a.gate == "PASS"


def test_quantify_capital_wall_rejects():
    fl = _flow(0, 1 * E, 1000 * E, 999 * E)         # +1 ETH
    a = AF.assess(fl, {AF.ETH: 3000.0},
                  required_capital_units=(AF.ETH, 20_000 * E))  # $60M capital
    assert a.gate == "FAIL"
    assert a.feasible is False


def test_multi_asset_primary_is_largest_protocol_move():
    before = {(AF.ATTACKER, "USDC"): 0, (AF.PROTOCOL, "USDC"): 1_000_000,
              (AF.ATTACKER, AF.ETH): 5 * E, (AF.PROTOCOL, AF.ETH): 10 * E}
    after = {(AF.ATTACKER, "USDC"): 900_000, (AF.PROTOCOL, "USDC"): 100_000,
             (AF.ATTACKER, AF.ETH): 5 * E, (AF.PROTOCOL, AF.ETH): 10 * E}
    fl = AF.from_balances(before, after)
    assert fl.primary_asset() == "USDC"
    assert fl.protocol_loss("USDC") == 900_000


def test_as_dict_is_json_safe():
    fl = _flow(10 * E, 15 * E, 1000 * E, 995 * E)
    d = fl.as_dict()
    import json
    json.dumps(d)                                   # must not raise
    assert d["primary_asset"] == AF.ETH


def test_measure_on_fork_returns_none_without_fork():
    class _Dead:
        available = False
    assert AF.measure_on_fork(_Dead(), [], attacker="0x1", protocol="0x2") is None
    assert AF.measure_on_fork(None, [], attacker="0x1", protocol="0x2") is None


def test_summarize_safe():
    assert "ASSET FLOW" in AF.summarize(_flow(0, 0, 0, 0))
