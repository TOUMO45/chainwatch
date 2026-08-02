// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;

contract Swapper {
    mapping(address => uint256) public balances;

    function swap(uint256 amountIn, uint256 minAmountOut) external returns (uint256 amountOut) {
        amountOut = _quote(amountIn);
        require(amountOut >= minAmountOut, "slippage");
        balances[msg.sender] += amountOut;
    }

    function _quote(uint256 amountIn) internal pure returns (uint256) {
        return (amountIn * 98) / 100;
    }
}
