// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;

import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";

contract FeeManager is Ownable {
    uint256 public fee;
    uint256 public pokes;

    // Became a view accessor in the same commit: no state is written, so there
    // is nothing for an access modifier to protect.
    function accrue() external view returns (uint256) {
        return fee;
    }
}
