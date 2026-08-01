// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.27;

import "../interfaces/HyperCoreConstants.sol";
import "../interfaces/IHyperCore.sol";
import "./TokenMath.sol";

/// @title ActionEncoder — single encode+send path for every L1 CoreWriter action
/// @notice All write-side HyperCore interactions go through this library. Each
///         `sendX` function builds the action payload AND calls
///         `ICoreWriter.sendRawAction` in one step, so there is no
///         "half-encoded, bytes floating around" intermediate state.
/// @dev Library `internal` functions inline into the caller's bytecode, which
///      means `CoreWriter.sendRawAction`'s `msg.sender` is the Vault, not this
///      library. This preserves Vault's identity as the sole L1 account on
///      HyperCore — the very reason an earlier Gateway-as-contract design had
///      to be reverted (funds followed Gateway, not Vault).
library ActionEncoder {
    /// @dev HL LIMIT_ORDER TIF encoding: 1=ALO (post-only), 2=GTC, 3=IOC.
    ///      Caller passes raw uint8 in struct; see `lib/hyper-evm-lib/src/common/HLConstants.sol`.

    struct HedgeParams {
        uint32 spotAsset;
        uint32 perpAsset;
        uint64 size;             // 10^8 * human readable
        uint64 spotPrice;        // 10^8 * human readable
        uint64 perpPrice;        // 10^8 * human readable
        uint128 cloid;           // 0 = no cloid
        uint8 tif;               // 1=ALO, 2=GTC, 3=IOC — applies to both open legs
        bool spotReduceOnly;     // typically false for opens; keeper-controlled for edge cases
        bool perpReduceOnly;     // typically false for opens; keeper-controlled for edge cases
    }

    struct CloseParams {
        uint256 positionId;
        uint32 spotAsset;
        uint32 perpAsset;
        uint64 size;
        uint64 spotPrice;
        uint64 perpPrice;
        uint128 cloid;
        uint8 tif;               // 1=ALO, 2=GTC, 3=IOC — applies to both close legs
        bool spotReduceOnly;     // HL spot silently drops reduceOnly=true on some paths — keeper may need false
        bool perpReduceOnly;     // perp reduceOnly=true is safe (prevents flip-through)
    }

    struct RepairParams {
        uint32 asset;
        bool isPerp;       // true = repairing perp leg, false = repairing spot leg
        bool isBuy;
        bool reduceOnly;   // true = close (undo failed hedge), false = open (complete failed hedge)
        uint64 size;
        uint64 price;
        uint16 residualBps;
        uint128 cloid;
        uint8 tif;         // 1=ALO, 2=GTC, 3=IOC
    }

    // ─── Hedge ─────────────────────────────────────────────────

    /// @notice Place spot buy limit order — long leg of a hedge.
    /// @dev `p.spotReduceOnly` is forwarded; opens typically pass `false`.
    function sendBuySpot(HedgeParams memory p) internal {
        _sendLimitOrder(p.spotAsset, true, p.spotPrice, p.size, p.spotReduceOnly, p.tif, p.cloid);
    }

    /// @notice Place perp short limit order — short leg of a hedge.
    /// @dev `p.perpReduceOnly` is forwarded; opens typically pass `false`.
    function sendShortPerp(HedgeParams memory p) internal {
        _sendLimitOrder(p.perpAsset, false, p.perpPrice, p.size, p.perpReduceOnly, p.tif, p.cloid);
    }

    /// @notice Close spot leg — sell the long.
    /// @dev `p.spotReduceOnly` is forwarded as-is. Keeper should typically pass `false`
    ///      for spot (HL has been observed to silently drop spot+reduceOnly=true on some
    ///      paths — tx 0xe20964…/0x3bde5f on 2026-04-22 confirmed the asymmetry).
    function sendSellSpot(CloseParams memory p) internal {
        _sendLimitOrder(p.spotAsset, false, p.spotPrice, p.size, p.spotReduceOnly, p.tif, p.cloid);
    }

    /// @notice Close perp leg — buy back the short.
    /// @dev `p.perpReduceOnly` typically `true` to prevent accidental flip.
    function sendClosePerp(CloseParams memory p) internal {
        _sendLimitOrder(p.perpAsset, true, p.perpPrice, p.size, p.perpReduceOnly, p.tif, p.cloid);
    }

    /// @notice Residual repair order — single-leg limit order that either
    ///         completes or undoes a partially-filled hedge.
    function sendRepairAction(RepairParams memory p) internal {
        _sendLimitOrder(p.asset, p.isBuy, p.price, p.size, p.reduceOnly, p.tif, p.cloid);
    }

    /// @dev Shared LIMIT_ORDER encode+dispatch. Consolidates what was 5 copies
    ///      inlined into the Vault; compiler emits one JUMPDEST body shared by all
    ///      callers, cutting ~hundreds of bytes off Vault's runtime bytecode.
    function _sendLimitOrder(
        uint32 asset,
        bool isBuy,
        uint64 price,
        uint64 size,
        bool reduceOnly,
        uint8 tif,
        uint128 cloid
    ) private {
        bytes memory action = abi.encodePacked(
            HyperCoreConstants.ACTION_VERSION,
            HyperCoreConstants.ACTION_LIMIT_ORDER,
            abi.encode(asset, isBuy, price, size, reduceOnly, tif, cloid)
        );
        _sendRaw(action);
    }

    // ─── HLP Vault Transfer ────────────────────────────────────

    /// @notice Deposit USD into a HyperCore vault (e.g. HLP).
    /// @dev `usdAmount` is in 6-decimal perp units (NOT 8-decimal L1 wei).
    function sendVaultDeposit(address vault, uint64 usdAmount) internal {
        bytes memory action = abi.encodePacked(
            HyperCoreConstants.ACTION_VERSION,
            HyperCoreConstants.ACTION_VAULT_TRANSFER,
            abi.encode(vault, true, usdAmount)
        );
        _sendRaw(action);
    }

    /// @notice Withdraw USD from a HyperCore vault. Subject to vault lock.
    function sendVaultWithdraw(address vault, uint64 usdAmount) internal {
        bytes memory action = abi.encodePacked(
            HyperCoreConstants.ACTION_VERSION,
            HyperCoreConstants.ACTION_VAULT_TRANSFER,
            abi.encode(vault, false, usdAmount)
        );
        _sendRaw(action);
    }

    // ─── BLP (Borrow/Lend Pool, action 15) ─────────────────────

    /// @notice Supply `l1Amount` of `token` into HL's Borrow/Lend Pool (op=0).
    /// @dev `l1Amount` is L1 8-dp wei. Target token must be BLP-enabled (has `ltv`).
    function sendSupply(uint64 token, uint64 l1Amount) internal {
        bytes memory action = abi.encodePacked(
            HyperCoreConstants.ACTION_VERSION,
            HyperCoreConstants.ACTION_BORROW_LEND,
            abi.encode(uint8(0), token, l1Amount)
        );
        _sendRaw(action);
    }

    /// @notice Withdraw `l1Amount` of `token` from BLP back to spot (op=1). `l1Amount=0` means max.
    function sendWithdrawSupply(uint64 token, uint64 l1Amount) internal {
        bytes memory action = abi.encodePacked(
            HyperCoreConstants.ACTION_VERSION,
            HyperCoreConstants.ACTION_BORROW_LEND,
            abi.encode(uint8(1), token, l1Amount)
        );
        _sendRaw(action);
    }

    // ─── Spot Transfer ─────────────────────────────────────────

    /// @notice Send spot tokens on L1 to `destination`.
    /// @dev `amount` is EVM-scale uint64 USDC; converted to L1 8-dp wei via
    ///      `TokenMath.usdcEvmToL1Wei` (SafeCast, reverts on overflow).
    function sendSpotSend(address destination, uint64 token, uint64 amount) internal {
        uint64 l1Amount = TokenMath.usdcEvmToL1Wei(uint256(amount));
        bytes memory action = abi.encodePacked(
            HyperCoreConstants.ACTION_VERSION,
            HyperCoreConstants.ACTION_SPOT_SEND,
            abi.encode(destination, token, l1Amount)
        );
        _sendRaw(action);
    }

    /// @notice Bridge USDC from EVM back to L1 via ACTION_SEND_ASSET.
    /// @dev Routes cross-dex spot→spot self-transfer; caller's L1 spot USDC
    ///      decrements by `usdcEvmToL1Wei(evmAmount)`. Amount is in 6-dp EVM USDC.
    function sendBridgeToL1(uint256 evmAmount) internal {
        uint64 l1Amount = TokenMath.usdcEvmToL1Wei(evmAmount);
        bytes memory action = abi.encodePacked(
            HyperCoreConstants.ACTION_VERSION,
            HyperCoreConstants.ACTION_SEND_ASSET,
            abi.encode(
                HyperCoreConstants.USDC_SYSTEM_ADDRESS,
                address(0),
                HyperCoreConstants.SPOT_DEX,
                HyperCoreConstants.SPOT_DEX,
                uint64(HyperCoreConstants.USDC_TOKEN_INDEX),
                l1Amount
            )
        );
        _sendRaw(action);
    }

    // ─── Internal ──────────────────────────────────────────────

    function _sendRaw(bytes memory action) private {
        ICoreWriter(HyperCoreConstants.CORE_WRITER).sendRawAction(action);
    }
}
