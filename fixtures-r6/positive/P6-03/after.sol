// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;

contract VaultManager {
    address public vault;

    function setVault(address _vault) external {
        vault = _vault;
    }
}
