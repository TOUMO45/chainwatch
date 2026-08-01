// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.27;

import {SafeCast} from "@openzeppelin/contracts/utils/math/SafeCast.sol";

/// @title TokenMath — EVM↔L1 unit conversions + L1 notional math for HyperCore
/// @notice All magic numbers (`/100`, oracle scalings, ...) live here. Every division
///         floor-rounds — backing/surplus math relies on this being the conservative
///         direction. Full derivations in `docs/invariants/precision-invariants.md`.
library TokenMath {
    using SafeCast for uint256;

    /// @dev USDC `evmExtraWeiDecimals = -2` (L1 8-dp, EVM 6-dp) → EVM→L1 × 100.
    uint256 internal constant USDC_EVM_TO_L1_FACTOR = 100;

    // ─── EVM ↔ L1 conversion ───────────────────────────────────

    /// @notice EVM 6-dp USDC → L1 spot 8-dp wei. Reverts on overflow.
    function usdcEvmToL1Wei(uint256 evm6dp) internal pure returns (uint64) {
        return SafeCast.toUint64(evm6dp * USDC_EVM_TO_L1_FACTOR);
    }

    /// @notice L1 spot 8-dp USDC wei → EVM 6-dp USDC. Floor rounding.
    function usdcL1WeiToEvm(uint64 l1_8dp) internal pure returns (uint256) {
        return uint256(l1_8dp) / USDC_EVM_TO_L1_FACTOR;
    }

    /// @notice Generic EVM → L1 conversion for any HIP-1 token.
    /// @dev `evmExtraWeiDecimals = L1 weiDecimals − EVM decimals`. Negative → multiply,
    ///      positive → divide (floor), zero → identity. Matches hyper-evm-lib convention.
    function evmToL1Wei(uint256 evmAmount, int8 evmExtraWeiDecimals) internal pure returns (uint64) {
        if (evmExtraWeiDecimals == 0) {
            return SafeCast.toUint64(evmAmount);
        } else if (evmExtraWeiDecimals < 0) {
            uint256 scaled = evmAmount * (10 ** uint8(-evmExtraWeiDecimals));
            return SafeCast.toUint64(scaled);
        } else {
            uint256 scaled = evmAmount / (10 ** uint8(evmExtraWeiDecimals));
            return SafeCast.toUint64(scaled);
        }
    }

    /// @notice Generic L1 → EVM conversion (inverse of `evmToL1Wei`).
    function l1WeiToEvm(uint64 l1Amount, int8 evmExtraWeiDecimals) internal pure returns (uint256) {
        if (evmExtraWeiDecimals == 0) {
            return uint256(l1Amount);
        } else if (evmExtraWeiDecimals < 0) {
            return uint256(l1Amount) / (10 ** uint8(-evmExtraWeiDecimals));
        } else {
            return uint256(l1Amount) * (10 ** uint8(evmExtraWeiDecimals));
        }
    }

    // ─── Asset notional → 6-dp USDC ────────────────────────────

    /// @notice Spot balance × perp oracle (0x807) → 6-dp USDC notional.
    /// @dev Formula: `balWei × rawPx / 10^(weiDecimals − perpSzDecimals)`.
    ///      0x807 format = `actualPrice × 10^(6 − szDecimals)`.
    function spotNotionalUsdcFromPerpPx(
        uint64 balWei,
        uint64 rawPerpOraclePx,
        uint8 weiDecimals,
        uint8 perpSzDecimals
    ) internal pure returns (uint256) {
        if (balWei == 0 || rawPerpOraclePx == 0) return 0;
        require(weiDecimals >= perpSzDecimals, "TokenMath: invalid decimals");
        uint256 divisor = 10 ** uint256(weiDecimals - perpSzDecimals);
        return (uint256(balWei) * uint256(rawPerpOraclePx)) / divisor;
    }

    /// @notice Spot balance × spot oracle (0x808) → 6-dp USDC notional.
    /// @dev 0x808 is 2dp more precise than 0x807 (`× 10^(8 − szDecimals)`), so the
    ///      divisor gains +2: `balWei × rawPx / 10^(weiDecimals + 2 − spotSzDecimals)`.
    function spotNotionalUsdcFromSpotPx(
        uint64 balWei,
        uint64 rawSpotPx,
        uint8 weiDecimals,
        uint8 spotSzDecimals
    ) internal pure returns (uint256) {
        if (balWei == 0 || rawSpotPx == 0) return 0;
        uint256 exp = uint256(weiDecimals) + 2;
        require(exp >= spotSzDecimals, "TokenMath: invalid decimals");
        uint256 divisor = 10 ** (exp - uint256(spotSzDecimals));
        return (uint256(balWei) * uint256(rawSpotPx)) / divisor;
    }

    // ─── L1 spot ↔ perp USDC rescale ───────────────────────────

    /// @notice L1 spot USDC (8-dp) → L1 perp accountValue (6-dp).
    function usdcSpotWeiToPerp(uint64 spotWei) internal pure returns (uint64) {
        return spotWei / 100;
    }

    /// @notice L1 perp USDC (6-dp) → L1 spot USDC (8-dp).
    function usdcPerpToSpotWei(uint64 perp6dp) internal pure returns (uint64) {
        return SafeCast.toUint64(uint256(perp6dp) * 100);
    }
}
