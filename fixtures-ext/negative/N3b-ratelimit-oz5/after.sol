// SPDX-License-Identifier: MIT
pragma solidity 0.8.27;

import {Initializable} from "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import {UUPSUpgradeable} from "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import {OwnableUpgradeable} from "@openzeppelin/contracts-upgradeable/access/OwnableUpgradeable.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";

contract RateLimited is Initializable, OwnableUpgradeable, UUPSUpgradeable {
    /// @custom:storage-location erc7201:chainwatch.storage.RateLimited
    struct RateLimitedStorage {
        address guardian;
        uint256 lastRotation;
    }

    // keccak256(abi.encode(uint256(keccak256("chainwatch.storage.RateLimited")) - 1)) & ~bytes32(uint256(0xff))
    bytes32 private constant RateLimitedStorageLocation =
        0x218b63c777a26b192afb136d7906e5241ab48950e506bf5364b61e2151943700;

    uint256 public constant ROTATION_COOLDOWN = 1 days;

    function _getRateLimitedStorage() private pure returns (RateLimitedStorage storage $) {
        assembly {
            $.slot := RateLimitedStorageLocation
        }
    }

    modifier onlyGuardian() {
        require(msg.sender == _getRateLimitedStorage().guardian, "not guardian");
        _;
    }

    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        _disableInitializers();
    }

    function initialize(address owner_, address guardian_) external initializer {
        _transferOwnership(owner_);
        _getRateLimitedStorage().guardian = guardian_;
    }

    function guardian() external view returns (address) {
        return _getRateLimitedStorage().guardian;
    }

    function lastRotation() external view returns (uint256) {
        return _getRateLimitedStorage().lastRotation;
    }

    // Rate-limited critical-config change: the guardian may be rotated at most
    // once per cooldown. The require READS $.lastRotation and the body WRITES
    // $.lastRotation = block.timestamp -- the same gate-on-and-write-same-member
    // shape as a one-shot initializer, but it REOPENS every cooldown instead of
    // closing permanently. This is NOT an initializer.
    function rotateGuardian(address newGuardian) external onlyGuardian {
        RateLimitedStorage storage $ = _getRateLimitedStorage();
        $.guardian = newGuardian;
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
