// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;

contract Payer {
    address public recipient;

    constructor(address r) {
        recipient = r;
    }

    receive() external payable {}

    function pay() external {
        (bool ok, ) = recipient.call{value: address(this).balance}("");
        require(ok, "call failed");
    }
}
