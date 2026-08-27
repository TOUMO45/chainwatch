// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;

import {Initializable} from "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import {UUPSUpgradeable} from "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import {OwnableUpgradeable} from "@openzeppelin/contracts-upgradeable/access/OwnableUpgradeable.sol";

// A factory-deployed (never behind a proxy directly) implementation that is
// intentionally left initializable at deploy time by its own design, so its
// constructor never called _disableInitializers() in the first place -
// nothing removed here, in either version.
contract PoolTemplate is Initializable, OwnableUpgradeable, UUPSUpgradeable {
    uint256 public totalDeposits;
    address public factory;

    constructor(address factory_) {
        factory = factory_;
    }

    function initialize(address owner_) external initializer {
        __Ownable_init();
        __UUPSUpgradeable_init();
        _transferOwnership(owner_);
    }

    function deposit() external payable {
        totalDeposits += msg.value;
    }

    function withdraw(uint256 amount) external onlyOwner {
        totalDeposits -= amount;
        (bool ok, ) = msg.sender.call{value: amount}("");
        require(ok, "PoolTemplate: transfer failed");
    }

    function _authorizeUpgrade(address newImplementation) internal override onlyOwner {}
}
