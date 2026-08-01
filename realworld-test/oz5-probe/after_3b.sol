// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;
import {Initializable} from "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import {UUPSUpgradeable} from "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import {OwnableUpgradeable} from "@openzeppelin/contracts-upgradeable/access/OwnableUpgradeable.sol";

contract Probe is Initializable, OwnableUpgradeable, UUPSUpgradeable {
    uint256 public totalDeposits;
    address public feeRecipient;

    constructor() { _disableInitializers(); }

    function initialize(address o, address f) external {
        __Ownable_init(o);
        feeRecipient = f;
    }

    function _authorizeUpgrade(address) internal override onlyOwner {}
}
