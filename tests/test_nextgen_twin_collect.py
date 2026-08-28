"""Counterfactual Twin - Phase 1 collection + Phase 2 fingerprints, against a
FAKE RPC (no network).

Run:  python -m pytest tests/test_nextgen_twin_collect.py -q
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from src.nextgen.twin import collect as C  # noqa: E402
from src.nextgen.twin import fingerprint as FP  # noqa: E402
from src.nextgen.twin import model as M  # noqa: E402
from src.nextgen.twin.rpc import TOPIC_TRANSFER  # noqa: E402

ADDR = "0x" + "d" * 40
OWNER = "0x" + "1" * 40
ATTACKER = "0x" + "2" * 40
TOKEN = "0x" + "e" * 40
SETRATE = "0x2f2ff15d"
DRAIN = "0xdeadbeef"


def _w(a: str) -> str:
    return "0x" + "0" * 24 + a[2:]


class FakeRpc:
    def __init__(self, *, alchemy=True):
        self.alchemy = alchemy
        self.impl = {1: "0x" + "a" * 40, 500: "0x" + "b" * 40}
        #                 blk  idx  from      to    value        input          status  logs
        self._tx = {
            "0xt1": (100, 0, OWNER, ADDR, 0, SETRATE + "00" * 32, 1,
                     [{"address": ADDR, "topics": ["0xevt"], "data": "0x"}]),
            "0xt2": (110, 1, ATTACKER, ADDR, 0, SETRATE + "00" * 32, 0, []),
            "0xt3": (120, 0, OWNER, ADDR, 5 * 10 ** 18, DRAIN, 1,
                     [{"address": TOKEN, "topics": [TOPIC_TRANSFER, _w(ADDR), _w(OWNER)],
                       "data": "0x" + "0" * 63 + "a"}]),
        }

    # generic dispatch (collect() calls rpc.call for alchemy_getAssetTransfers)
    def call(self, method, params):
        if method == "alchemy_getAssetTransfers":
            if not self.alchemy:
                return None
            direction = "toAddress" if "toAddress" in params[0] else "fromAddress"
            if direction != "toAddress":
                return {"transfers": []}
            # alchemy returns only value-moving / successful interactions
            return {"transfers": [
                {"hash": "0xt1", "blockNum": hex(100)},
                {"hash": "0xt3", "blockNum": hex(120)},
            ]}
        raise AssertionError(f"unexpected rpc.call {method}")

    def supports(self, m, p=None):
        return False

    def chain_id(self):
        return 1

    def get_logs(self, *, from_block, to_block, address=None, topics=None):
        out = []
        for h, (blk, idx, frm, to, val, inp, st, logs) in self._tx.items():
            if not (from_block <= blk <= to_block):
                continue
            for lg in logs:
                if address and lg["address"].lower() != address.lower():
                    continue
                out.append({**lg, "blockNumber": hex(blk), "transactionHash": h,
                            "logIndex": "0x0"})
        return out

    def get_block(self, n, full=True):
        n = int(n, 16) if isinstance(n, str) else n
        txs = [{"hash": h, "from": frm, "to": to, "value": hex(val),
                "input": inp, "blockNumber": hex(blk),
                "transactionIndex": hex(idx), "nonce": "0x1"}
               for h, (blk, idx, frm, to, val, inp, st, logs) in self._tx.items()
               if blk == n]
        return {"timestamp": hex(1_700_000_000 + n), "transactions": txs}

    def get_tx(self, h):
        blk, idx, frm, to, val, inp, st, logs = self._tx[h]
        return {"hash": h, "from": frm, "to": to, "value": hex(val),
                "input": inp, "blockNumber": hex(blk),
                "transactionIndex": hex(idx), "nonce": "0x1"}

    def get_receipt(self, h):
        blk, idx, frm, to, val, inp, st, logs = self._tx[h]
        return {"status": hex(st), "gasUsed": "0x5208",
                "logs": [{**lg, "blockNumber": hex(blk), "transactionHash": h,
                          "logIndex": "0x0"} for lg in logs]}

    def implementation_at(self, proxy, block="latest"):
        blk = int(block, 16) if isinstance(block, str) else block
        best = None
        for b, impl in sorted(self.impl.items()):
            if b <= blk:
                best = impl
        return best


def test_alchemy_enumeration_collects_successful_interactions():
    col = C.collect(FakeRpc(), ADDR, from_block=1, to_block=1000, max_txs=50)
    assert col.trace_capable is False
    assert any("alchemy_getAssetTransfers" in n for n in col.notes)
    by = {t.hash: t for t in col.txs}
    assert set(by) == {"0xt1", "0xt3"}                 # the two successful ones
    assert by["0xt1"].status is True
    assert by["0xt3"].value == 5 * 10 ** 18
    outs = [t for t in col.transfers if t.frm == ADDR.lower()]
    assert outs and outs[0].standard == M.ERC20 and outs[0].amount == 10


def test_deep_block_scan_catches_a_reverted_silent_call():
    col = C.collect(FakeRpc(), ADDR, from_block=1, to_block=1000, max_txs=50,
                    deep_blocks=(110, 110))
    by = {t.hash: t for t in col.txs}
    assert "0xt2" in by
    assert by["0xt2"].status is False and by["0xt2"].sender == ATTACKER


def test_getlogs_fallback_when_no_alchemy():
    col = C.collect(FakeRpc(alchemy=False), ADDR, from_block=1, to_block=1000)
    assert any("eth_getLogs enumeration" in n for n in col.notes)
    # only 0xt1 emitted a log FROM the address
    assert {t.hash for t in col.txs} == {"0xt1"}


def test_implementation_upgrade_detected():
    col = C.collect(FakeRpc(), ADDR, from_block=1, to_block=1000)
    assert col.upgrades and col.upgrades[0][1] == "0x" + "b" * 40


def test_fingerprints_split_callers_and_flows():
    col = C.collect(FakeRpc(), ADDR, from_block=1, to_block=1000,
                    deep_blocks=(110, 110))
    fps = FP.build_fingerprints(col, traces=None)
    assert SETRATE in fps and DRAIN in fps
    fp = fps[SETRATE]
    assert fp.n_total == 2 and fp.n_success == 1 and fp.n_revert == 1
    assert fp.callers_success == {OWNER} and fp.callers_revert == {ATTACKER}
    assert fp.caller_exclusive == {OWNER}
    assert fps[DRAIN].value_buckets.get("normal") == 1
    assert fps[DRAIN].transfers_out == 1


def test_summarize_renders():
    col = C.collect(FakeRpc(), ADDR, from_block=1, to_block=1000,
                    deep_blocks=(110, 110))
    txt = FP.summarize(FP.build_fingerprints(col))
    assert "BEHAVIORAL FINGERPRINTS" in txt and "exclusive callers" in txt
