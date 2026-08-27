// SPDX-License-Identifier: MIT
pragma solidity ^0.7.6;

library SafeMath {
    function add(uint256 a, uint256 b) internal pure returns (uint256) {
        uint256 c = a + b;
        require(c >= a, "SafeMath: addition overflow");
        return c;
    }
}

contract SwapAdapter {
    using SafeMath for uint256;

    mapping(address => uint256) public amounts;

    function executeOperation(address asset, uint256 amount) external {
        _swapLiquidity(asset, amount);
    }

    function _swapLiquidity(address asset, uint256 amount) internal {
        amounts[asset] = amounts[asset].add(amount);
    }
}
