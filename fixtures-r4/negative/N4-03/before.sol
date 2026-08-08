// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;

contract Escrow {
    uint256 public constant MAX_DEPOSIT = 1e27;

    mapping(address => uint256) public deposits;

    function deposit(uint256 amount) external {
        require(amount <= MAX_DEPOSIT, "amount too large");
        require(deposits[msg.sender] <= MAX_DEPOSIT, "position full");
        deposits[msg.sender] = deposits[msg.sender] + amount;
    }
}
