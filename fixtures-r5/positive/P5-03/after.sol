// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;

interface ICallback {
    function onEvent(uint256 x) external;
}

contract Notifier {
    uint256 public lastNotified;

    function notify(ICallback cb, uint256 x) external {
        cb.onEvent(x);
        lastNotified = x;
    }
}
