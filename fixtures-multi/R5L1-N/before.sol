// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;

interface IERC20 {
    function approve(address spender, uint256 amount) external returns (bool);
}

/// @notice Single-file negative for RC-2 (R5-L1). The function contains three
/// same-key .approve() calls (kind=high, dest=var:tokenAddress, method=approve).
/// The middle site is inside try/catch; the other two are not. Nothing about
/// the function's approval logic changes between before/after — the only diff
/// from after.sol is a comment / version bump. Rule 5 currently fires because
/// its within-commit key collapses the three records; the RC-2 fix must make
/// the within-commit key injective (position-suffixed) so that no unchecked
/// after-record joins the retained in-try before-record.
contract Approver {
    uint256 public constant VERSION = 1;

    function safeApproveFallbackToMax(IERC20 tokenAddress, address spender, uint256 value) external {
        tokenAddress.approve(spender, 0);
        try tokenAddress.approve(spender, value) { } catch { }
        tokenAddress.approve(spender, type(uint256).max);
    }
}
