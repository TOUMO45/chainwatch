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

    function initialize(address owner_) external initializer {
        __Ownable_init();
        __UUPSUpgradeable_init();
        _transferOwnership(owner_);
    }

    function deposit() external payable {
        totalDeposits += msg.value;
    }

    // Looks like an access-control replacement, not a removal: msg.sender is
    // still checked. But `admin` has no protection of its own (see
    // setAdmin below) - anyone can become "admin" first, then pass this
    // check. The caller set is unrestricted in practice, same as if the
    // modifier had simply been deleted.
    function setAdmin(address _admin) external {
        admin = _admin;
    }

    function _authorizeUpgrade(address newImplementation) internal override {
        require(msg.sender == admin, "Vault: not admin");
    }
}
