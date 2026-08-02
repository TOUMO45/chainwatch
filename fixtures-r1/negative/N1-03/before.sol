// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;

import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";

contract FeeManager is Ownable {
    uint256 public fee;
    uint256 public pokes;

    function accrue() external onlyOwner returns (uint256) {
        pokes += 1;
        return fee;
    }
}
