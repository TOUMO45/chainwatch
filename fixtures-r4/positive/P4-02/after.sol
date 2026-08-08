// SPDX-License-Identifier: MIT
pragma solidity ^0.7.6;

contract Ledger {
    mapping(address => uint256) public balances;
    uint256 public totalSupply;

    function credit(address to, uint256 amount) external {
        balances[to] = balances[to] + amount;
        totalSupply = totalSupply + amount;
    }

    function debit(address from, uint256 amount) external {
        balances[from] = balances[from] - amount;
        totalSupply = totalSupply - amount;
    }
}
