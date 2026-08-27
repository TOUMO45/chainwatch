// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;

contract SimpleVault {
    address public owner;
    uint256 public totalDeposits;
    bool public paused;

    constructor(address owner_) {
        owner = owner_;
    }

    modifier onlyOwner() {
        require(msg.sender == owner, "not owner");
        _;
    }

    function deposit() external payable {
        totalDeposits += msg.value;
    }

    function withdraw(uint256 amount) external onlyOwner {
        totalDeposits -= amount;
        (bool ok, ) = msg.sender.call{value: amount}("");
        require(ok, "SimpleVault: transfer failed");
    }
}
