// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;

contract Registry {
    mapping(address => bool) public registered;

    function register(address user) external {
        require(user != address(0), "zero address");
        _store(user);
    }

    function _store(address user) internal {
        registered[user] = true;
    }
}
