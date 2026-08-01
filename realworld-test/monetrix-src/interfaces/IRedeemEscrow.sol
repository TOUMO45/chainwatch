// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.27;

/// @title IRedeemEscrow
/// @notice Holds USDC reserved for pending redemptions. Tracks its own
/// obligations (totalOwed) so it knows what it owes vs what it has.
interface IRedeemEscrow {
    function addObligation(uint256 amount) external;
    function payOut(address recipient, uint256 amount) external;
    function reclaimTo(address to, uint256 amount) external;
    function totalOwed() external view returns (uint256);
    function shortfall() external view returns (uint256);
    function balance() external view returns (uint256);
}
