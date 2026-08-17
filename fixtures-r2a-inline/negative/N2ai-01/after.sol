// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;

interface IPool {
    function sync() external returns (uint256);
}

contract BaseGood {
    uint256 public tally;
    IPool internal pool;

    function refresh() public virtual {
        tally = tally + 1;
        pool.sync();
    }
}

contract ChildGood is BaseGood {
    IPool internal registry;
    bool private _locked;

    modifier nonReentrant() {
        require(!_locked, "reentrant");
        _locked = true;
        _;
        _locked = false;
    }

    function refresh() public override {
        super.refresh();
        registry.sync();
    }
}
