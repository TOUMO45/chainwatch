// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;

interface IHook {
    function onFlush(uint256 amount) external;
}

contract Rewarder {
    uint256 public pending;
    IHook public hook;

    constructor(IHook h) {
        hook = h;
    }

    function flush() external {
        uint256 amount = pending;
        pending = 0;
        address(hook).call(
            abi.encodeWithSelector(IHook.onFlush.selector, amount)
        );
    }
}
