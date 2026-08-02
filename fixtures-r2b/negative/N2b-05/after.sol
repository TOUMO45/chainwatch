// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;

import {ReentrancyGuard} from "@openzeppelin/contracts/security/ReentrancyGuard.sol";

contract StakingPool is ReentrancyGuard {
    uint256 public totalAssets;
    uint256 public totalShares;
    mapping(address => uint256) public shares;

    function deposit() external payable {
        uint256 minted = totalShares == 0 ? msg.value : (msg.value * totalShares) / totalAssets;
        shares[msg.sender] += minted;
        totalShares += minted;
        totalAssets += msg.value;
    }

    function withdraw(uint256 shareAmount) external nonReentrant {
        require(shares[msg.sender] >= shareAmount, "insufficient");
        uint256 assets = (shareAmount * totalAssets) / totalShares;
        shares[msg.sender] -= shareAmount;
        (bool ok, ) = msg.sender.call{value: assets}("");
        require(ok, "transfer failed");
        totalShares -= shareAmount;
        totalAssets -= assets;
    }

    function pricePerShare() external view returns (uint256) {
        if (totalShares == 0) return 1e18;
        return (totalAssets * 1e18) / totalShares;
    }
}
