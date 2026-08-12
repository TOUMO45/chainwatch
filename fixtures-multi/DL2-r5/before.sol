// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;

import "./AllowanceLib.sol";

/// @notice Changed file at commit N-1. The only diff between this file and
/// after.sol is the VERSION constant — a harmless bump. AllowanceLib.sol is
/// unchanged between the two commits. If Rule 5 fires on this pair it is
/// mis-attributing a phantom removal in unchanged library code to the
/// changed facet.
contract Facet {
    uint256 public constant VERSION = 1;

    function grant(IERC20 token, address spender, uint256 amount) external {
        AllowanceLib.safeApproveFallbackToMax(token, spender, amount);
    }
}
