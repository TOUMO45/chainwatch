// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;

import {Initializable} from "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import {UUPSUpgradeable} from "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import {OwnableUpgradeable} from "@openzeppelin/contracts-upgradeable/access/OwnableUpgradeable.sol";

contract Vault is Initializable, OwnableUpgradeable, UUPSUpgradeable {
    uint256 public totalDeposits;
    address public admin;

    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        _disableInitializers();
    }

    // `admin` is set exactly once, at initialization time, guarded by
    // `initializer` - a one-shot writer, the same shape OpenZeppelin's own
    // Ownable constructor uses. There is no runtime setter of any kind, so
    // nobody can become "admin" by calling anything. Must stay quiet.
    function initialize(address owner_, address admin_) external initializer {
        __Ownable_init();
        __UUPSUpgradeable_init();
        _transferOwnership(owner_);
        admin = admin_;
    }

    function deposit() external payable {
        totalDeposits += msg.value;
    }

    function _authorizeUpgrade(address newImplementation) internal override {
        require(msg.sender == admin, "Vault: not admin");
    }
}
