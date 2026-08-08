// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;

contract Refunder {
    receive() external payable {}

    function refund(uint256 amount) external {
        msg.sender.call{value: amount}("");
    }
}
