// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;

interface IPool { function sync() external returns (uint256); }

contract Manager {
    uint256 public approved;
    IPool internal validator;

    function permit(uint256 v) external {
        require(approved == 0, "used");
        validator.sync();
        approved = v;
    }
}
