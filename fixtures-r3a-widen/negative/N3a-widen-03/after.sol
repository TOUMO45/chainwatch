// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;

import {Initializable} from "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import {UUPSUpgradeable} from "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import {OwnableUpgradeable} from "@openzeppelin/contracts-upgradeable/access/OwnableUpgradeable.sol";

contract Vault is Initializable, OwnableUpgradeable, UUPSUpgradeable {
    uint256 public totalDeposits;
    uint256 public withdrawFeeBps;

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

    // Unrelated routine change (a new owner-settable fee), so this fixture
    // is not diff-identical to before.sol - but the upgrade authorization
    // itself is completely untouched: still plain `onlyOwner`, backed by
    // OpenZeppelin's own protected _transferOwnership. Baseline sanity case:
    // must stay quiet.
    function setWithdrawFeeBps(uint256 bps) external onlyOwner {
        withdrawFeeBps = bps;
    }

    function _authorizeUpgrade(address newImplementation) internal override onlyOwner {}
}
