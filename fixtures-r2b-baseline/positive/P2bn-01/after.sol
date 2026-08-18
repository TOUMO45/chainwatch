// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;

interface IPool { function sync() external returns (uint256); }

contract Ledger {
    uint256 public settled;
    IPool internal pool;

    function claim(uint256 v) external {
        require(settled == 0, "done");
        pool.sync();
        settled = v;
    }
}
