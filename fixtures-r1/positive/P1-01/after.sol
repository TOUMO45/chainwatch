// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;

import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";

contract FeeManager is Ownable {
    uint256 public fee;
    address public feeRecipient;

    constructor(address recipient) {
        feeRecipient = recipient;
    }

    function setFee(uint256 newFee) external {
        fee = newFee;
    }

    function setFeeRecipient(address recipient) external onlyOwner {
        feeRecipient = recipient;
    }
}
