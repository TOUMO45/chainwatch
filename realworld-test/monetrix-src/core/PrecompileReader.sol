// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.27;

import "../interfaces/HyperCoreConstants.sol";
import "./TokenMath.sol";

/// @title PrecompileReader — typed wrappers over HyperCore read precompiles
/// @notice Single read path for L1 state. Reverts on precompile failure so a
///         transient glitch can't be silently booked as a zero balance.
///         Also owns the read-side EVM↔L1 unit boundary (via `TokenMath`);
///         `ActionEncoder` owns the write side.
library PrecompileReader {
    struct SpotBalance {
        uint64 total;
        uint64 hold;
        uint64 entryNtl;
    }

    struct VaultEquity {
        uint64 equity;
        uint64 lockedUntil;
    }

    /// @dev L1 wire format — order-sensitive for abi.decode.
    struct PerpAssetInfo {
        string coin;
        uint32 marginTableId;
        uint8 szDecimals;
        uint8 maxLeverage;
        bool onlyIsolated;
    }

    /// @dev L1 wire format — order-sensitive for abi.decode.
    struct TokenInfo {
        string name;
        uint64[] spots;
        uint64 deployerTradingFeeShare;
        address deployer;
        address evmContract;
        uint8 szDecimals;
        uint8 weiDecimals;
        int8 evmExtraWeiDecimals;
    }

    /// @notice Spot token balance (0x801).
    function spotBalance(address account, uint64 token) internal view returns (SpotBalance memory) {
        (bool ok, bytes memory res) = HyperCoreConstants.PRECOMPILE_SPOT_BALANCE.staticcall(
            abi.encode(account, token)
        );
        require(ok && res.length >= 96, "PrecompileReader: spot balance read failed");
        (uint64 total, uint64 hold, uint64 entryNtl) = abi.decode(res, (uint64, uint64, uint64));
        return SpotBalance(total, hold, entryNtl);
    }

    /// @notice HLP / core-vault equity (0x802).
    function vaultEquity(address account, address vaultAddr) internal view returns (VaultEquity memory) {
        (bool ok, bytes memory res) = HyperCoreConstants.PRECOMPILE_VAULT_EQUITY.staticcall(
            abi.encode(account, vaultAddr)
        );
        require(ok && res.length >= 64, "PrecompileReader: vault equity read failed");
        (uint64 equity, uint64 lockedUntil) = abi.decode(res, (uint64, uint64));
        return VaultEquity(equity, lockedUntil);
    }

    /// @notice Perp/spot oracle price (0x807). Reverts on zero (outage signal).
    function oraclePx(uint32 assetIndex) internal view returns (uint64 price) {
        (bool ok, bytes memory res) = HyperCoreConstants.PRECOMPILE_ORACLE_PX.staticcall(
            abi.encode(assetIndex)
        );
        require(ok && res.length >= 32, "PrecompileReader: oracle px read failed");
        price = abi.decode(res, (uint64));
        require(price > 0, "PrecompileReader: oracle px zero");
    }

    /// @notice Perp account value (signed, 6-dp) from 0x80F.
    function accountValueSigned(address user) internal view returns (int64 accountValue) {
        (bool ok, bytes memory res) = HyperCoreConstants.PRECOMPILE_ACCOUNT_MARGIN_SUMMARY.staticcall(
            abi.encode(uint32(0), user)
        );
        require(ok && res.length >= 128, "PrecompileReader: perp account read failed");
        (accountValue,,,) = abi.decode(res, (int64, uint64, uint64, int64));
    }

    /// @notice PM "supplied" balance (0x811). Returned in L1 8-dp wei.
    function suppliedBalance(address account, uint64 token) internal view returns (uint64 supplied) {
        (bool ok, bytes memory res) = HyperCoreConstants.PRECOMPILE_SUPPLIED_BALANCE.staticcall(
            abi.encode(account, token)
        );
        require(ok && res.length >= 128, "PrecompileReader: supplied balance read failed");
        (,,, supplied) = abi.decode(res, (uint64, uint64, uint64, uint64));
    }

    /// @notice Spot oracle price (0x808) for an HL spot pair.
    /// @param spotAssetId HL spot asset id = 10000 + spot_pair_index (NOT token_index).
    ///                    See `MonetrixConfig.TradeableAsset.spotPairAssetId`.
    /// @dev Returned value is scaled by `10^(8 - baseSzDecimals)`.
    function spotPx(uint64 spotAssetId) internal view returns (uint64 price) {
        (bool ok, bytes memory res) = HyperCoreConstants.PRECOMPILE_SPOT_PX.staticcall(
            abi.encode(spotAssetId)
        );
        require(ok && res.length >= 32, "PrecompileReader: spot px read failed");
        price = abi.decode(res, (uint64));
        require(price > 0, "PrecompileReader: spot px zero");
    }

    /// @notice Perp asset metadata (0x80A).
    function perpAssetInfo(uint32 perpIndex) internal view returns (PerpAssetInfo memory info) {
        (bool ok, bytes memory res) = HyperCoreConstants.PRECOMPILE_PERP_ASSET_INFO.staticcall(
            abi.encode(perpIndex)
        );
        require(ok && res.length >= 160, "PrecompileReader: perp asset info read failed");
        info = abi.decode(res, (PerpAssetInfo));
    }

    /// @notice HIP-1 token metadata (0x80C).
    function tokenInfo(uint32 tokenIndex) internal view returns (TokenInfo memory info) {
        (bool ok, bytes memory res) = HyperCoreConstants.PRECOMPILE_TOKEN_INFO.staticcall(
            abi.encode(tokenIndex)
        );
        require(ok && res.length >= 256, "PrecompileReader: token info read failed");
        info = abi.decode(res, (TokenInfo));
    }

    // ─── Read-side boundary helpers (read + unit conversion) ─────

    /// @notice L1 spot USDC balance in 6-dp EVM USDC.
    function spotUsdcEvm(address account) internal view returns (uint256) {
        SpotBalance memory bal = spotBalance(account, uint64(HyperCoreConstants.USDC_TOKEN_INDEX));
        return TokenMath.usdcL1WeiToEvm(bal.total);
    }

    /// @notice PM-supplied USDC balance in 6-dp EVM USDC.
    function suppliedUsdcEvm(address account) internal view returns (uint256) {
        uint64 supplied = suppliedBalance(account, uint64(HyperCoreConstants.USDC_TOKEN_INDEX));
        return TokenMath.usdcL1WeiToEvm(supplied);
    }

    /// @notice Spot hedge balance valued in 6-dp USDC via perp oracle + live HIP-1 decimals.
    function spotNotionalUsdcFromPerp(
        uint32 spotTokenIndex,
        uint32 perpIndex,
        address account
    ) internal view returns (uint256) {
        SpotBalance memory bal = spotBalance(account, uint64(spotTokenIndex));
        if (bal.total == 0) return 0;
        uint64 price = oraclePx(perpIndex);
        (uint8 weiDec, uint8 szDec) = _assetDecimals(spotTokenIndex, perpIndex);
        return TokenMath.spotNotionalUsdcFromPerpPx(bal.total, price, weiDec, szDec);
    }

    /// @notice PM-supplied hedge balance valued in 6-dp USDC.
    function suppliedNotionalUsdcFromPerp(
        uint32 spotTokenIndex,
        uint32 perpIndex,
        address account
    ) internal view returns (uint256) {
        uint64 supplied = suppliedBalance(account, uint64(spotTokenIndex));
        if (supplied == 0) return 0;
        uint64 price = oraclePx(perpIndex);
        (uint8 weiDec, uint8 szDec) = _assetDecimals(spotTokenIndex, perpIndex);
        return TokenMath.spotNotionalUsdcFromPerpPx(supplied, price, weiDec, szDec);
    }

    function _assetDecimals(uint32 spotTokenIndex, uint32 perpIndex)
        private view returns (uint8 weiDec, uint8 perpSzDec)
    {
        TokenInfo memory ti = tokenInfo(spotTokenIndex);
        PerpAssetInfo memory pi = perpAssetInfo(perpIndex);
        weiDec = ti.weiDecimals;
        perpSzDec = pi.szDecimals;
    }
}
