// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;

contract Payouts {
    address public currentRecipient;

    function setRecipient(address recipient) external {
        require(recipient != address(0), "zero address");
        currentRecipient = recipient;
    }
}
