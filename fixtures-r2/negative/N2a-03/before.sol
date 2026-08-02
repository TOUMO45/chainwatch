// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;

import {ReentrancyGuard} from "@openzeppelin/contracts/security/ReentrancyGuard.sol";

contract FeeCollector is ReentrancyGuard {
    address public immutable treasury;
    uint256 public collected;

    constructor(address treasury_) {
        treasury = treasury_;
    }

    function deposit() external payable {
        collected += msg.value;
    }

    function sweep(uint256 amount) external nonReentrant {
        (bool ok, ) = treasury.call{value: amount}("");
        require(ok, "sweep failed");
        collected -= amount;
    }
}
