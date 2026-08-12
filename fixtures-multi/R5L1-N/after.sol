// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;

interface IERC20 {
    function approve(address spender, uint256 amount) external returns (bool);
}

/// @notice Same approve-reset behavior as before.sol; only VERSION bumped.
/// No approval-related change. Rule 5 must stay quiet after the RC-2 fix.
contract Approver {
    uint256 public constant VERSION = 2;

    function safeApproveFallbackToMax(IERC20 tokenAddress, address spender, uint256 value) external {
        tokenAddress.approve(spender, 0);
        try tokenAddress.approve(spender, value) { } catch { }
        tokenAddress.approve(spender, type(uint256).max);
    }
}
