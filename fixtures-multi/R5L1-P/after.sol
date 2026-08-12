// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;

interface IERC20 {
    function approve(address spender, uint256 amount) external returns (bool);
}

/// @notice Middle-site try/catch REMOVED at N. All three .approve() calls are
/// now bare; a revert in the middle call propagates instead of being isolated,
/// so downstream sites never execute. This is a genuine Rule 5 try/catch-removal
/// regression. The RC-2 fix must still fire here — the middle site's position
/// key matches its N-1 counterpart, which was checked (in_try), while the N
/// counterpart is not.
contract Approver {
    function safeApproveFallbackToMax(IERC20 tokenAddress, address spender, uint256 value) external {
        tokenAddress.approve(spender, 0);
        tokenAddress.approve(spender, value);
        tokenAddress.approve(spender, type(uint256).max);
    }
}
