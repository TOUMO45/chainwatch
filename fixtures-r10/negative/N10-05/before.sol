// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;

import "@openzeppelin/contracts/access/Ownable.sol";

contract Vault is Ownable {
    string internal _vaultName;
    uint256 internal _feeBps;

    constructor(string memory vaultName_) {
        _vaultName = vaultName_;
    }

    function rescueOwner(address o) external {
        _transferOwnership(o);
    }

    function setFeeBps(uint256 v) external onlyOwner {
        _feeBps = v;
    }
}
