// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;

import {Initializable} from "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import {UUPSUpgradeable} from "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import {OwnableUpgradeable} from "@openzeppelin/contracts-upgradeable/access/OwnableUpgradeable.sol";
import {TimelockController} from "@openzeppelin/contracts/governance/TimelockController.sol";

contract Vault is Initializable, OwnableUpgradeable, UUPSUpgradeable {
    uint256 public totalDeposits;
    address public feeRecipient;
    TimelockController public upgradeTimelock;

    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        _disableInitializers();
    }

    function initialize(address owner_, address feeRecipient_, address payable timelock_) external initializer {
        __Ownable_init();
        __UUPSUpgradeable_init();
        _transferOwnership(owner_);
        feeRecipient = feeRecipient_;
        upgradeTimelock = TimelockController(timelock_);
    }

    function deposit() external payable {
        totalDeposits += msg.value;
    }

    function withdraw(uint256 amount) external onlyOwner {
        totalDeposits -= amount;
        (bool ok, ) = msg.sender.call{value: amount}("");
        require(ok, "Vault: transfer failed");
    }

    function _authorizeUpgrade(address newImplementation) internal override {
        require(msg.sender == address(upgradeTimelock), "Vault: caller is not the timelock");
    }
}
