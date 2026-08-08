// SPDX-License-Identifier: MIT
pragma solidity ^0.7.6;

library SafeMath {
    function add(uint256 a, uint256 b) internal pure returns (uint256) {
        uint256 c = a + b;
        require(c >= a, "SafeMath: addition overflow");
        return c;
    }

    function sub(uint256 a, uint256 b) internal pure returns (uint256) {
        require(b <= a, "SafeMath: subtraction underflow");
        return a - b;
    }
}

contract Ledger {
    using SafeMath for uint256;

    mapping(address => uint256) public balances;
    uint256 public totalSupply;

    function credit(address to, uint256 amount) external {
        balances[to] = balances[to].add(amount);
        totalSupply = totalSupply.add(amount);
    }

    function debit(address from, uint256 amount) external {
        balances[from] = balances[from].sub(amount);
        totalSupply = totalSupply.sub(amount);
    }
}
