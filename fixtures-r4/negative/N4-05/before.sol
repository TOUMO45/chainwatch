// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;

contract RewardVaultMock {
    mapping(address => uint256) public shares;
    uint256 public totalShares;

    function deposit(address account, uint256 amount) external {
        shares[account] = shares[account] + amount;
        totalShares = totalShares + amount;
    }
}
