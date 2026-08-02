// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;

contract VaultManager {
    address public vault;

    function setVault(address _vault) external {
        require(vault == address(0), "vault already set");
        vault = _vault;
    }
}
