// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;

import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";

contract FeeManager is Ownable {
    uint256 public fee;

    // Visibility narrowed to internal in the same commit: no external caller
    // path remains, so the missing modifier is not externally reachable.
    function _setFee(uint256 newFee) internal {
        fee = newFee;
    }
}
