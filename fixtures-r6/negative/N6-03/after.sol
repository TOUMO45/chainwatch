// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;

contract Payouts {
    address public currentRecipient;

    function setRecipient() external {
        currentRecipient = msg.sender;
    }
}
