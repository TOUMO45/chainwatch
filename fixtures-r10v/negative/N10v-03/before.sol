// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;

import "@openzeppelin/contracts/access/Ownable.sol";

interface IOracle {
    function price() external view returns (uint256);
}

contract Vault is Ownable {
    address public oracle;

    constructor(address oracle_) {
        oracle = oracle_;
    }

    function quote() external view returns (uint256) {
        return IOracle(oracle).price();
    }
}
