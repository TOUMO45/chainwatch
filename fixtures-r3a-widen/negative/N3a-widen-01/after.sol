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

    function initialize(address owner_, address admin_) external initializer {
        __Ownable_init();
        __UUPSUpgradeable_init();
        _transferOwnership(owner_);
        admin = admin_;
    }

    function deposit() external payable {
        totalDeposits += msg.value;
    }

    // Same replacement shape as P3a-widen-01, but `admin` is NOT freely
    // settable: only the CURRENT admin can hand the role to a new one. This
    // is a legitimate, self-contained access-control mechanism - the caller
    // set never actually widens, it just no longer routes through
    // OpenZeppelin's Ownable. Must stay quiet.
    function setAdmin(address _admin) external {
        require(msg.sender == admin, "Vault: not admin");
        admin = _admin;
    }

    function _authorizeUpgrade(address newImplementation) internal override {
        require(msg.sender == admin, "Vault: not admin");
    }
}
