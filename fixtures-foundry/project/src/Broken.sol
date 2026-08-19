// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;

/// A GENUINE syntax error, not a missing import and not a bad pragma. solc
/// must be the thing that complains about it.
contract Broken {
    function oops() external pure returns (uint256) {
        uint256 x = ;
        return x;
    }
}
