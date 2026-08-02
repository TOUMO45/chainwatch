// SPDX-License-Identifier: MIT
pragma solidity 0.8.27;

import {Initializable} from "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import {OwnableUpgradeable} from "@openzeppelin/contracts-upgradeable/access/OwnableUpgradeable.sol";

contract FeeManager is Initializable, OwnableUpgradeable {
    uint256 public fee;
    address public feeRecipient;

    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        _disableInitializers();
    }

    function initialize(address owner_, address feeRecipient_) external initializer {
        __Ownable_init(owner_);
        feeRecipient = feeRecipient_;
    }

    function setFee(uint256 newFee) external onlyOwner {
        fee = newFee;
    }

    function setFeeRecipient(address recipient) external onlyOwner {
        feeRecipient = recipient;
    }
}
