// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;

/// Deliberately import-free. The point of this file is to isolate PLATFORM
/// selection: if it fails to compile, the cause is which platform ran, never
/// which remapping resolved.
contract Vault {
    address public owner;
    mapping(address => uint256) public balanceOf;

    constructor() {
        owner = msg.sender;
    }

    function withdraw(address to, uint256 amount) external {
        require(msg.sender == owner, "not owner");
        require(balanceOf[to] >= amount, "insufficient");
        balanceOf[to] -= amount;
    }
}
