// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;

contract RewardVault {
    mapping(address => uint256) public shares;
    uint256 public totalShares;

    function deposit(address account, uint256 amount) external {
        unchecked {
            shares[account] = shares[account] + amount;
            totalShares = totalShares + amount;
        }
    }
}
