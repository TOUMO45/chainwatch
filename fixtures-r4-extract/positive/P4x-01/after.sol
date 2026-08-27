// SPDX-License-Identifier: MIT
pragma solidity ^0.7.6;

contract SwapAdapter {
    mapping(address => uint256) public amounts;

    function executeOperation(address asset, uint256 amount) external {
        _swapLiquidity(asset, amount);
    }

    function _swapLiquidity(address asset, uint256 amount) internal {
        amounts[asset] = amounts[asset] + amount;
    }
}
