// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;

contract Vault {
    bool private _initialized;

    modifier initializer() {
        require(!_initialized, "already initialized");
        _initialized = true;
        _;
    }

    address public admin;
    uint256 public total;
    uint32 public lastUpdate;

    function init(address admin_) external initializer {
        admin = admin_;
    }
}
