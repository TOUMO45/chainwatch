// SPDX-License-Identifier: MIT
pragma solidity ^0.7.6;

library SafeMath {
    function add(uint256 a, uint256 b) internal pure returns (uint256) {
        uint256 c = a + b;
        require(c >= a, "SafeMath: addition overflow");
        return c;
    }
}

contract Vault {
    using SafeMath for uint256;

    mapping(address => uint256) public balances;

    function deposit(address to, uint256 amount) external {
        balances[to] = balances[to].add(amount);
    }
}
