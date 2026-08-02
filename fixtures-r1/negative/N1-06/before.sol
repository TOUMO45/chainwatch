// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;

contract Config {
    address public admin;
    uint256 public fee;

    constructor() {
        admin = msg.sender;
    }

    modifier onlyAdmin() {
        require(msg.sender == admin, "Config: not admin");
        _;
    }

    function setFee(uint256 newFee) external onlyAdmin {
        fee = newFee;
    }
}
