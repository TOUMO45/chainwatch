// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;

interface IPool {
    function sync() external returns (uint256);
}

contract BaseLedger {
    uint256 public settled;
    IPool internal pool;

    function refresh() public virtual {
        if (settled == 0) {
            settled = 1;
        }
        pool.sync();
    }
}

contract ChildLedger is BaseLedger {
    IPool internal registry;

    function refresh() public override {
        pool.sync();
        if (settled == 0) {
            settled = 1;
        }
        registry.sync();
    }
}
