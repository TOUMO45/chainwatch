// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;

import "@openzeppelin/contracts/access/Ownable.sol";

interface IOracle {
    function price() external view returns (uint256);
}

contract Vault is Ownable {
    address public oracle;

    function init(address oracle_) external {
        oracle = oracle_;
    }

    function quote() external view returns (uint256) {
        return IOracle(oracle).price();
    }
}
