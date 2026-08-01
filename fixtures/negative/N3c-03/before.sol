// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;

import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";

contract FeeManager is Ownable {
    uint256 public totalCollected;
    address public feeRecipient;

    constructor(address feeRecipient_) {
        feeRecipient = feeRecipient_;
    }

    function collect() external payable {
        totalCollected += msg.value;
    }

    function sweep() external onlyOwner {
        uint256 amount = address(this).balance;
        (bool ok, ) = feeRecipient.call{value: amount}("");
        require(ok, "FeeManager: sweep failed");
    }

    function setFeeRecipient(address feeRecipient_) external onlyOwner {
        feeRecipient = feeRecipient_;
    }
}
