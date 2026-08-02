// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;

contract Config {
    address public admin;
    uint256 public fee;

    constructor() {
        admin = msg.sender;
    }

    // Modifier renamed onlyAdmin -> restricted; body AST is byte-for-byte the
    // same access check. Pure refactor, no semantic change.
    modifier restricted() {
        require(msg.sender == admin, "Config: not admin");
        _;
    }

    function setFee(uint256 newFee) external restricted {
        fee = newFee;
    }
}
