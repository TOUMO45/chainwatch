// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.27;

/// @title IMonetrixAccountant
/// @notice Minimal interface for peg reads + yield declaration gating. The
///         accountant holds no tokens; `settleDailyPnL` is the single yield
///         authority. Bounds: initialized + interval + distributable + annualized.
interface IMonetrixAccountant {
    function settleDailyPnL(uint256 proposedYield) external returns (uint256 distributable);
    function surplus() external view returns (int256);
    function distributableSurplus() external view returns (int256);
}
