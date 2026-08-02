// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;

import {Initializable} from "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import {UUPSUpgradeable} from "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import {OwnableUpgradeable} from "@openzeppelin/contracts-upgradeable/access/OwnableUpgradeable.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";

contract RateLimited is Initializable, OwnableUpgradeable, UUPSUpgradeable {
    address public guardian;
    uint256 public lastRotation;
    uint256 public constant ROTATION_COOLDOWN = 1 days;

    modifier onlyGuardian() {
        require(msg.sender == guardian, "not guardian");
        _;
    }

    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        _disableInitializers();
    }

    function initialize(address owner_, address guardian_) external initializer {
        __Ownable_init();
        __UUPSUpgradeable_init();
        _transferOwnership(owner_);
        guardian = guardian_;
    }

    // Rate-limited critical-config change: the guardian may be rotated at most
    // once per cooldown. The require READS lastRotation and the body WRITES
    // lastRotation = block.timestamp -- the same gate-on-and-write-same-var
    // shape as a one-shot initializer, but it REOPENS every cooldown instead of
    // closing permanently. This is NOT an initializer.
    function rotateGuardian(address newGuardian) external onlyGuardian {
        require(block.timestamp >= lastRotation + ROTATION_COOLDOWN, "too soon");
        lastRotation = block.timestamp;
        guardian = newGuardian;
    }

    function _authorizeUpgrade(address newImplementation) internal override onlyOwner {}
}

contract RateLimitedFactory {
    event Deployed(address proxy, address implementation);

    function deploy(address owner_, address guardian_) external returns (address) {
        RateLimited implementation = new RateLimited();
        ERC1967Proxy proxy = new ERC1967Proxy(
            address(implementation),
            abi.encodeCall(RateLimited.initialize, (owner_, guardian_))
        );
        emit Deployed(address(proxy), address(implementation));
        return address(proxy);
    }
}
