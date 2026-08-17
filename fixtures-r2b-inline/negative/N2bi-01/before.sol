// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;

interface IPool {
    function sync() external returns (uint256);
}

contract BaseCollateral {
    uint256 public exposedRef;
    uint256 public savedLow;
    IPool internal pool;

    function refresh() public virtual {
        try pool.sync() returns (uint256 v) {
            if (v < exposedRef) {
                exposedRef = v;
            }
            savedLow = v;
        } catch {}
    }
}

contract MetapoolCollateral is BaseCollateral {
    IPool internal pairedRegistry;

    function refresh() public override {
        pairedRegistry.sync();
        super.refresh();
    }
}
