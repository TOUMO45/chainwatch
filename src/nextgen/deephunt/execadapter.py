"""Phase 3 - the fork execution laboratory (spec sections 11, 12).

A thin lifecycle wrapper over `src/nextgen/execground/foundry.AnvilFork` for the
Deep Hunt use: fork a real chain at an EXACT block into an isolated local Anvil,
then read code / storage / balances, snapshot/revert, and submit impersonated
(never signed, never broadcast) transactions against it.

Everything degrades: with no Foundry toolchain, or no upstream RPC, `open_fork`
returns a `ForkContext` whose `.available` is False and whose every read returns
`None`. Callers turn that into an `UNKNOWN` gate, never a `CONFIRMED`.

`ReproState` is the spec section 12 record - chain id, fork block, target,
implementation, watched storage + balances - so a finding says exactly what
state it was reproduced against.

Reuses `execground/foundry.resolve()` + `AnvilFork` and `twin/rpc.RpcClient`
(which already speaks `eth_getCode` / `eth_getStorageAt` / `eth_call` /
`anvil_*` / `evm_snapshot`). Nothing new talks to the network.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

from src.nextgen.execground import foundry as FOUNDRY

# EIP-1967 slots
IMPL_SLOT = "0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc"
ADMIN_SLOT = "0xb53127684a568b3173ae13b9f8a6016e243e63b6e8ee1178d6a717850b5d6103"

_ETHER = 10 ** 18


@dataclass
class ReproState:
    """Spec section 12 - the exact state a finding was reproduced against."""

    chain_id: int
    fork_block: int
    target: str
    implementation: str = ""
    storage: dict = field(default_factory=dict)     # slot(hex) -> value(hex)
    balances: dict = field(default_factory=dict)    # addr -> wei (int)

    def as_dict(self) -> dict:
        return {"chain_id": self.chain_id, "fork_block": self.fork_block,
                "target": self.target, "implementation": self.implementation,
                "storage": dict(self.storage),
                "balances": {k: str(v) for k, v in self.balances.items()}}


class ForkContext:
    """`with open_fork(1, 18_000_000, target, rpc) as fx: fx.code(addr)`.

    Not a dataclass - it owns a live subprocess. `available` is False until
    `start()` (or `__enter__`) succeeds and after `stop()`.
    """

    def __init__(self, chain_id: int, fork_block: int, target: str,
                 rpc_url: str, *, timeout: int = 120) -> None:
        self.chain_id = int(chain_id or 0)
        self.fork_block = int(fork_block or 0)
        self.target = target or ""
        self.rpc_url = rpc_url or ""
        self.timeout = timeout
        self.available = False
        self.reason = ""
        self.toolchain_kind = ""
        self.fork_rpc_url = ""
        self._tc = None
        self._fork = None
        self._rpc = None

    # -- lifecycle ------------------------------------------------------------ #

    def __enter__(self) -> "ForkContext":
        self.start()
        return self

    def __exit__(self, *exc) -> None:
        self.stop()

    def start(self) -> bool:
        if self.available:
            return True
        tc = self._tc or FOUNDRY.resolve()
        if tc is None:
            self.reason = "no Foundry toolchain (forge/anvil) reachable"
            return False
        if not self.rpc_url:
            self.reason = "no upstream RPC url for the fork"
            return False
        self._tc = tc
        self.toolchain_kind = tc.kind
        try:
            self._fork = FOUNDRY.AnvilFork(
                tc, fork_url=self.rpc_url,
                fork_block=self.fork_block or None,
                chain_id=self.chain_id or None, timeout=self.timeout)
            self._fork.__enter__()
            self.fork_rpc_url = self._fork.rpc_url
            from src.nextgen.twin.rpc import RpcClient
            self._rpc = RpcClient(self.fork_rpc_url)
            self.available = True
            return True
        except Exception as exc:  # noqa: BLE001 - fork failure -> UNKNOWN
            self.reason = f"fork did not start: {type(exc).__name__}: {exc}"[:300]
            self.stop()
            return False

    def stop(self) -> None:
        self.available = False
        f, self._fork = self._fork, None
        if f is not None:
            try:
                f.stop()
            except Exception:  # noqa: BLE001
                pass
        self._rpc = None

    # -- reads (None when unavailable / on any error) ----------------------- #

    def _r(self, method: str, *a, **kw):
        if not self.available or self._rpc is None:
            return None
        try:
            return getattr(self._rpc, method)(*a, **kw)
        except Exception:  # noqa: BLE001
            return None

    def block_number(self) -> Optional[int]:
        return self._r("block_number")

    def code(self, addr: str) -> Optional[str]:
        return self._r("get_code", addr)

    def storage_at(self, addr: str, slot: str) -> Optional[str]:
        return self._r("get_storage_at", addr, slot)

    def call(self, to: str, data: str, *, frm: str = "", value: int = 0
             ) -> Optional[str]:
        tx = {"to": to, "data": data or "0x"}
        if frm:
            tx["from"] = frm
        if value:
            tx["value"] = hex(value)
        return self._r("eth_call", tx)

    def balance(self, addr: str) -> Optional[int]:
        v = self._r("call", "eth_getBalance", [addr, "latest"])
        try:
            return int(v, 16) if isinstance(v, str) else None
        except (TypeError, ValueError):
            return None

    def implementation_of(self, proxy: str = "") -> Optional[str]:
        return self._r("implementation_at", proxy or self.target)

    def has_code(self, addr: str) -> Optional[bool]:
        c = self.code(addr)
        if c is None:
            return None
        return len(c) > 2 and c != "0x"

    # -- local-fork mutations (never broadcast: this IS the node) ----------- #

    def _w(self, method: str, *a) -> bool:
        if not self.available or self._rpc is None:
            return False
        try:
            getattr(self._rpc, method)(*a)
            return True
        except Exception:  # noqa: BLE001
            return False

    def set_balance(self, addr: str, wei: int) -> bool:
        return self._w("anvil_set_balance", addr, int(wei))

    def set_storage(self, addr: str, slot: str, value: str) -> bool:
        return self._w("anvil_set_storage_at", addr, slot, value)

    def increase_time(self, seconds: int) -> bool:
        if not self.available or self._rpc is None:
            return False
        try:
            self._rpc.call("evm_increaseTime", [int(seconds)])
            self._rpc.anvil_mine(1)
            return True
        except Exception:  # noqa: BLE001
            return False

    def mine(self, n: int = 1) -> bool:
        return self._w("anvil_mine", n)

    def snapshot(self) -> Optional[str]:
        return self._r("anvil_snapshot")

    def revert(self, snap: str) -> bool:
        return bool(self._r("anvil_revert", snap))

    def impersonate_send(self, tx: dict) -> Optional[dict]:
        """Submit `tx` from `tx['from']` on the local fork and return its
        receipt dict (or None). Impersonation is lifted afterwards. Never a
        signed / broadcast transaction - the fork IS the whole network."""
        if not self.available or self._rpc is None:
            return None
        frm = tx.get("from")
        if not frm:
            return None
        try:
            self._rpc.anvil_impersonate(frm)
        except Exception:  # noqa: BLE001
            return None
        try:
            h = self._rpc.send_tx(tx)
            return self._rpc.get_receipt(h)
        except Exception:  # noqa: BLE001
            return None
        finally:
            try:
                self._rpc.anvil_stop_impersonate(frm)
            except Exception:  # noqa: BLE001
                pass

    # -- evidence ---------------------------------------------------------- #

    def repro_state(self, *, watch_addrs: tuple[str, ...] = (),
                    watch_slots: tuple[str, ...] = ()) -> ReproState:
        impl = self.implementation_of(self.target) or ""
        storage: dict = {}
        for slot in watch_slots:
            v = self.storage_at(self.target, slot)
            if v is not None:
                storage[slot] = v
        balances: dict = {}
        for a in {self.target, *watch_addrs}:
            if not a:
                continue
            b = self.balance(a)
            if b is not None:
                balances[a] = b
        return ReproState(
            chain_id=self.chain_id,
            fork_block=self.block_number() or self.fork_block,
            target=self.target, implementation=impl,
            storage=storage, balances=balances)

    def as_dict(self) -> dict:
        return {"chain_id": self.chain_id, "fork_block": self.fork_block,
                "target": self.target, "available": self.available,
                "reason": self.reason, "toolchain_kind": self.toolchain_kind,
                "fork_rpc_url": self.fork_rpc_url}


def open_fork(chain_id: int, fork_block: int, target: str, rpc_url: str, *,
              timeout: int = 120, start: bool = False) -> ForkContext:
    """Build a `ForkContext`. With `start=True` (or a `with` block) it boots the
    fork immediately; otherwise the caller starts it. Never raises - inspect
    `.available` / `.reason`."""
    fc = ForkContext(chain_id, fork_block, target, rpc_url, timeout=timeout)
    tc = FOUNDRY.resolve()
    if tc is None:
        fc.reason = "no Foundry toolchain (forge/anvil) reachable"
    else:
        fc._tc = tc
        fc.toolchain_kind = tc.kind
        if not rpc_url:
            fc.reason = "no upstream RPC url for the fork"
        elif start:
            fc.start()
    return fc


def toolchain_status() -> dict:
    return FOUNDRY.status()
