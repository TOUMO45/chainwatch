// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;

interface IPool {
    function sync() external returns (uint256);
}

contract BaseRegistry {
    uint256 public epoch;

    function refresh() public virtual {
        epoch = epoch + 1;
    }
}

contract ChildRegistry is BaseRegistry {
    uint256 public localCount;
    IPool internal feed;

    function refresh() public override {
        feed.sync();
        if (localCount == 0) {
            localCount = 2;
        }
        super.refresh();
    }
}
