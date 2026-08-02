// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;

import {ReentrancyGuard} from "@openzeppelin/contracts/security/ReentrancyGuard.sol";

contract PullBank is ReentrancyGuard {
    mapping(address => uint256) public balances;
    mapping(address => uint256) public pending;

    function deposit() external payable {
        balances[msg.sender] += msg.value;
    }

    function withdraw(uint256 amount) external {
        require(balances[msg.sender] >= amount, "insufficient");
        balances[msg.sender] -= amount;
        pending[msg.sender] += amount;
    }

    function claim() external nonReentrant {
        uint256 amount = pending[msg.sender];
        pending[msg.sender] = 0;
        (bool ok, ) = msg.sender.call{value: amount}("");
        require(ok, "transfer failed");
    }
}
