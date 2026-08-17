// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;

interface IPool {
    function sync() external returns (uint256);
}

contract BaseNoWrite {
    IPool internal pool;

    function refresh() public virtual {
        pool.sync();
    }
}

contract ChildNoWrite is BaseNoWrite {
    IPool internal registry;
    bool private _locked;

    modifier nonReentrant() {
        require(!_locked, "reentrant");
        _locked = true;
        _;
        _locked = false;
    }

    function refresh() public override {
        registry.sync();
        super.refresh();
    }
}
