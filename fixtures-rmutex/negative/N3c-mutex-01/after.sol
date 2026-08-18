// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;

contract Pool {
    uint256 private _locked = 1;

    modifier lock() {
        require(_locked == 1, "reentrant");
        _locked = 0;
        _;
        _locked = 1;
    }

    address public token0;
    uint256 public reserve0;
    uint32 public blockTimestampLast;

    function sync() external lock {
        blockTimestampLast = uint32(block.timestamp);
        reserve0 = reserve0 + 1;
    }
}
