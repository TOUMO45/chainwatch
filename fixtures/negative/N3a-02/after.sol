// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;

import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";

contract Vault is Ownable {
    uint256 public totalDeposits;
    address public feeRecipient;

    constructor(address owner_, address feeRecipient_) {
        _transferOwnership(owner_);
        feeRecipient = feeRecipient_;
    }

    function deposit() external payable {
        totalDeposits += msg.value;
    }

    function withdraw(uint256 amount) external onlyOwner {
        totalDeposits -= amount;
        (bool ok, ) = msg.sender.call{value: amount}("");
        require(ok, "Vault: transfer failed");
    }
}
