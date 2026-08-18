// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;

contract Positions {
    mapping(uint256 => uint128) public liquidityOf;

    function decreaseLiquidity(uint256 tokenId, uint128 liquidity) external {
        require(liquidity > 0, "zero");
        liquidityOf[tokenId] -= liquidity;
    }
}
