// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;

interface IPool { function sync() external returns (uint256); }

contract Quoter {
    uint256 public settled;
    uint256 private amountOutCached;
    IPool internal pool;

    function quote(uint256 v) external {
        require(settled == 0, "done");
        amountOutCached = v;
        pool.sync();
        require(amountOutCached == v, "cache changed");
        settled = v;
        amountOutCached = 0;
    }
}
