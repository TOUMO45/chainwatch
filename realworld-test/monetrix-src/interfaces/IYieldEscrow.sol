// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.27;

/// @title IYieldEscrow
/// @notice Minimal interface for the yield escrow contract.
/// Holds USDC for yield distribution. Only the Vault can move funds
/// in (via direct safeTransfer) or out (via pullForDistribution).
interface IYieldEscrow {
    function pullForDistribution(uint256 amount) external;
    function balance() external view returns (uint256);
}
