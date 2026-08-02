// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;

contract FeeConfig {
    address public owner;
    uint256 public fee;

    constructor() {
        owner = msg.sender;
    }

    function setFee(uint256 newFee) external {
        fee = newFee;
    }
}
