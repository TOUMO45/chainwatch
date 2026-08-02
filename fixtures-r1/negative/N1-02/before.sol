// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;

import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";

contract FeeManager is Ownable {
    uint256 public fee;

    function setFee(uint256 newFee) external onlyOwner {
        fee = newFee;
    }
}
