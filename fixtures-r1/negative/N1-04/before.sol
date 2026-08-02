// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;

// Repo-relative path when the rule runs: test/mocks/Treasury.sol
// The "test" and "mocks" path segments mark this as a test/mock helper,
// not a deployed production contract. The contract name carries no signal.

import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";

contract Treasury is Ownable {
    uint256 public fee;

    function setFee(uint256 newFee) external onlyOwner {
        fee = newFee;
    }
}
