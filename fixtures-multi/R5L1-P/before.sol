// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;

interface IERC20 {
    function approve(address spender, uint256 amount) external returns (bool);
}

/// @notice Paired positive for RC-2. Same approve-reset idiom as R5L1-N,
/// where the middle site's try/catch will genuinely be REMOVED at N.
/// The RC-2 fix (injective site-keys) must still fire on this real removal.
contract Approver {
    function safeApproveFallbackToMax(IERC20 tokenAddress, address spender, uint256 value) external {
        tokenAddress.approve(spender, 0);
        try tokenAddress.approve(spender, value) { } catch { }
        tokenAddress.approve(spender, type(uint256).max);
    }
}
