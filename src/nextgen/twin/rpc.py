"""A minimal JSON-RPC client - stdlib only, no new dependency.

Used against (a) a cheap public endpoint for Phase 1 collection and (b) a local
Anvil fork for deep traces + Phase 6 replay. The Anvil-only helpers
(`anvil_*`, `debug_trace_call_tree`, `send_tx`) are never called against a
public endpoint by the Twin.
"""

from __future__ import annotations

import json
import time
import urllib.error
import urllib.request
from typing import Any, Optional

# EIP-1967 implementation slot.
EIP1967_IMPL = "0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc"
EIP1967_ADMIN = "0xb53127684a568b3173ae13b9f8a6016e243e63b6e8ee1178d6a717850b5d6103"

# ERC-20/721 Transfer / ERC-1155 TransferSingle & TransferBatch topic0s.
TOPIC_TRANSFER = "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef"
TOPIC_TRANSFER_SINGLE = "0xc3d58168c5ae7397731d063d5bbf3d657854427343f4c083240f7aacaa2d0f62"
TOPIC_TRANSFER_BATCH = "0x4a39dc06d4c0dbc64b70af90fd698a233a518aa5d07e595d983b8c0526c8f7fb"


class RpcError(RuntimeError):
    pass


class RpcClient:
    def __init__(self, url: str, *, timeout: int = 40, max_retries: int = 4) -> None:
        if not url or "://" not in url:
            raise ValueError(f"bad rpc url: {url!r}")
        self.url = url
        self.timeout = timeout
        self.max_retries = max_retries
        self._id = 0
        self._supports: dict[str, bool] = {}

    # -- core -------------------------------------------------------------- #

    def call(self, method: str, params: list) -> Any:
        self._id += 1
        payload = json.dumps({"jsonrpc": "2.0", "id": self._id,
                              "method": method, "params": params}).encode()
        last = None
        for attempt in range(self.max_retries):
            req = urllib.request.Request(
                self.url, data=payload,
                headers={"content-type": "application/json"})
            try:
                with urllib.request.urlopen(req, timeout=self.timeout) as r:
                    body = json.load(r)
            except urllib.error.HTTPError as e:
                last = f"HTTP {e.code}"
                if e.code in (429, 503) and attempt < self.max_retries - 1:
                    time.sleep(1.5 * (attempt + 1))
                    continue
                raise RpcError(f"{method}: {last}") from e
            except Exception as e:  # noqa: BLE001
                last = f"{type(e).__name__}: {e}"
                if attempt < self.max_retries - 1:
                    time.sleep(1.0 * (attempt + 1))
                    continue
                raise RpcError(f"{method}: {last}") from e
            if "error" in body and body["error"] is not None:
                raise RpcError(f"{method}: {body['error']}")
            return body.get("result")
        raise RpcError(f"{method}: exhausted retries ({last})")

    def batch(self, calls: list[tuple[str, list]], *, chunk: int = 50) -> list:
        """Run many calls with JSON-RPC batching. Returns results positionally;
        a failed sub-call yields None. Falls back to sequential on a batch
        error."""
        out: list = [None] * len(calls)
        for start in range(0, len(calls), chunk):
            sub = calls[start:start + chunk]
            payload = []
            for i, (m, p) in enumerate(sub):
                self._id += 1
                payload.append({"jsonrpc": "2.0", "id": self._id,
                                "method": m, "params": p, "_pos": start + i})
            ids = {d["id"]: d["_pos"] for d in payload}
            for d in payload:
                d.pop("_pos")
            try:
                req = urllib.request.Request(
                    self.url, data=json.dumps(payload).encode(),
                    headers={"content-type": "application/json"})
                with urllib.request.urlopen(req, timeout=self.timeout) as r:
                    body = json.load(r)
                if not isinstance(body, list):
                    raise RpcError("batch response not a list")
                for item in body:
                    pos = ids.get(item.get("id"))
                    if pos is not None:
                        out[pos] = item.get("result")
            except Exception:  # noqa: BLE001 - degrade to sequential
                for pos, (m, p) in zip(range(start, start + len(sub)), sub):
                    try:
                        out[pos] = self.call(m, p)
                    except Exception:  # noqa: BLE001
                        out[pos] = None
        return out

    def supports(self, method: str, probe_params: Optional[list] = None) -> bool:
        if method in self._supports:
            return self._supports[method]
        try:
            self.call(method, probe_params or [])
            ok = True
        except RpcError as e:
            msg = str(e).lower()
            # "method not found" / "not supported" / a 400 => unsupported;
            # a param/exec error => the method IS supported.
            ok = not any(s in msg for s in (
                "not found", "not supported", "unsupported", "http 400",
                "method not available", "does not exist"))
        self._supports[method] = ok
        return ok

    # -- reads ----------------------------------------------------------- #

    @staticmethod
    def _hx(n) -> str:
        return n if isinstance(n, str) else hex(int(n))

    def block_number(self) -> int:
        return int(self.call("eth_blockNumber", []), 16)

    def chain_id(self) -> int:
        return int(self.call("eth_chainId", []), 16)

    def get_block(self, n, full: bool = True) -> dict:
        return self.call("eth_getBlockByNumber", [self._hx(n), full]) or {}

    def get_tx(self, h: str) -> dict:
        return self.call("eth_getTransactionByHash", [h]) or {}

    def get_receipt(self, h: str) -> dict:
        return self.call("eth_getTransactionReceipt", [h]) or {}

    def get_logs(self, *, from_block, to_block, address: Optional[str] = None,
                 topics: Optional[list] = None) -> list[dict]:
        flt: dict[str, Any] = {"fromBlock": self._hx(from_block),
                               "toBlock": self._hx(to_block)}
        if address:
            flt["address"] = address
        if topics:
            flt["topics"] = topics
        return self.call("eth_getLogs", [flt]) or []

    def get_code(self, addr: str, block="latest") -> str:
        return self.call("eth_getCode", [addr, self._hx(block)]) or "0x"

    def get_storage_at(self, addr: str, slot: str, block="latest") -> str:
        return self.call("eth_getStorageAt", [addr, slot, self._hx(block)]) or \
            "0x" + "0" * 64

    def eth_call(self, tx: dict, block="latest") -> str:
        return self.call("eth_call", [tx, self._hx(block)])

    def implementation_at(self, proxy: str, block="latest") -> Optional[str]:
        raw = self.get_storage_at(proxy, EIP1967_IMPL, block)
        addr = "0x" + raw[-40:]
        return None if int(addr, 16) == 0 else addr

    # -- anvil-only (local fork) --------------------------------------- #

    def anvil_impersonate(self, addr: str) -> None:
        self.call("anvil_impersonateAccount", [addr])

    def anvil_stop_impersonate(self, addr: str) -> None:
        self.call("anvil_stopImpersonatingAccount", [addr])

    def anvil_set_storage_at(self, addr: str, slot: str, value: str) -> None:
        self.call("anvil_setStorageAt", [addr, slot, value])

    def anvil_set_balance(self, addr: str, wei: int) -> None:
        self.call("anvil_setBalance", [addr, hex(wei)])

    def anvil_mine(self, n: int = 1) -> None:
        self.call("anvil_mine", [hex(n)])

    def anvil_snapshot(self) -> str:
        return self.call("evm_snapshot", [])

    def anvil_revert(self, snap: str) -> bool:
        return bool(self.call("evm_revert", [snap]))

    def send_tx(self, tx: dict) -> str:
        """LOCAL FORK ONLY. The Twin never calls this against a public endpoint."""
        return self.call("eth_sendTransaction", [tx])

    def debug_trace_call_tree(self, tx_hash: str) -> dict:
        return self.call("debug_traceTransaction",
                         [tx_hash, {"tracer": "callTracer",
                                    "tracerConfig": {"withLog": True}}]) or {}

    def debug_prestate_diff(self, tx_hash: str) -> dict:
        return self.call("debug_traceTransaction",
                         [tx_hash, {"tracer": "prestateTracer",
                                    "tracerConfig": {"diffMode": True}}]) or {}
