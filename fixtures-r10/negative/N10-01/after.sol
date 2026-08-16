// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;

import "@openzeppelin/contracts/access/Ownable.sol";

contract Vault is Ownable {
    string internal _vaultName;
    uint256 internal _feeBps;

    function init(address newOwner, string calldata vaultName_) external onlyOwner {
        _transferOwnership(newOwner);
        _vaultName = vaultName_;
    }

    function setFeeBps(uint256 v) external onlyOwner {
        _feeBps = v;
    }

    function vaultName() external view returns (string memory) {
        return _vaultName;
    }
}
