// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;

interface ICallback {
    function onEvent(uint256 x) external;
}

contract Notifier {
    uint256 public lastNotified;

    function notify(ICallback cb, uint256 x) external {
        try cb.onEvent(x) {
            // success: nothing extra to do
        } catch {
            // failure isolated: swallow and continue
        }
        lastNotified = x;
    }
}
