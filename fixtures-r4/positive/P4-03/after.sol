// SPDX-License-Identifier: MIT
pragma solidity ^0.7.6;

contract Treasury {
    mapping(address => uint256) public credits;
    uint256 public issued;

    function issue(address to, uint256 amount) external {
        credits[to] = credits[to] + amount;
        issued = issued + amount;
    }

    function redeem(address from, uint256 amount) external {
        credits[from] = credits[from] - amount;
        issued = issued - amount;
    }
}
