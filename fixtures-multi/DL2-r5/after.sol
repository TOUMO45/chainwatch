// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;

import "./AllowanceLib.sol";

/// @notice Changed file at commit N. The only diff from before.sol is the
/// VERSION constant. AllowanceLib.sol is byte-identical between commits.
contract Facet {
    uint256 public constant VERSION = 2;

    function grant(IERC20 token, address spender, uint256 amount) external {
        AllowanceLib.safeApproveFallbackToMax(token, spender, amount);
    }
}
