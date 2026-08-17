// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;

interface IPool {
    function sync() external returns (uint256);
}

contract BaseVault {
    uint256 public cached;
    IPool internal pool;

    function refresh() public virtual {
        if (cached == 0) {
            cached = 1;
        }
        pool.sync();
    }
}

contract ChildVault is BaseVault {
    IPool internal registry;

    function refresh() public override {
        registry.sync();
        if (cached == 0) {
            cached = 1;
        }
        pool.sync();
    }
}
