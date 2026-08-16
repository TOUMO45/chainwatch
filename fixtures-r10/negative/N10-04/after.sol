// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;

import "@openzeppelin/contracts/access/Ownable.sol";

contract Vault is Ownable {
    string internal _vaultName;
    uint256 internal _total;

    constructor(string memory vaultName_) {
        _vaultName = vaultName_;
    }

    function totalAssets() external view returns (uint256) {
        return _total;
    }

    function setTotal(uint256 v) external onlyOwner {
        _total = v;
    }
}
