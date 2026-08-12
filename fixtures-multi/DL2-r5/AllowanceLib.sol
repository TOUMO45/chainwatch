// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;

interface IERC20 {
    function approve(address spender, uint256 amount) external returns (bool);
}

/// @notice Reserve-shape approve-reset idiom, used from a changed facet.
/// The three .approve() calls collapse to one Rule 5 key (kind=high,
/// dest=var:tokenAddress, method=approve). The middle site is inside
/// try/catch; the other two are not. This library file is byte-identical
/// in the before/after commits of this fixture — DESIGN-L2 must not
/// attribute a phantom Rule 5 fire to the changed importer file.
library AllowanceLib {
    function safeApproveFallbackToMax(IERC20 tokenAddress, address spender, uint256 value) internal {
        // 1st site: reset current allowance to 0 (not in try)
        tokenAddress.approve(spender, 0);
        // 2nd site: attempt the requested amount (isolated by try/catch)
        try tokenAddress.approve(spender, value) { } catch { }
        // 3rd site: fallback to unbounded allowance (not in try)
        tokenAddress.approve(spender, type(uint256).max);
    }
}
