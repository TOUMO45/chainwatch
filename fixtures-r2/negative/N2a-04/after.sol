// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;

import {ReentrancyGuard} from "@openzeppelin/contracts/security/ReentrancyGuard.sol";

interface IPriceFeed {
    function latestPrice() external view returns (uint256);
}

contract Quoter is ReentrancyGuard {
    IPriceFeed public immutable feed;
    uint256 public lastQueried;

    constructor(address feed_) {
        feed = IPriceFeed(feed_);
    }

    function currentPrice() external view returns (uint256) {
        return feed.latestPrice();
    }
}
