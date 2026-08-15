// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;

import {Initializable} from "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import {UUPSUpgradeable} from "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import {OwnableUpgradeable} from "@openzeppelin/contracts-upgradeable/access/OwnableUpgradeable.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";

/// @notice RC-AST1 positive #1, N-1 side. Paired with N3c-ast1-01: same
/// contract-typed storage shape, but at N the `registry` slot's declared type
/// genuinely changes identity (IRegistry -> IOracle). Rule 3c must keep firing
/// after the RC-AST1 fix: stripping the astId suffix must NOT strip the type's
/// NAME, so `t_contract(IRegistry)` and `t_contract(IOracle)` still differ.
interface IRegistry {
    function isRegistered(address who) external view returns (bool);
}

interface IOracle {
    function price() external view returns (uint256);
}

contract Vault is Initializable, OwnableUpgradeable, UUPSUpgradeable {
    IRegistry public registry;
    uint256 public totalDeposits;

    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        _disableInitializers();
    }

    function initialize(address owner_, IRegistry registry_) external initializer {
        __Ownable_init();
        __UUPSUpgradeable_init();
        _transferOwnership(owner_);
        registry = registry_;
    }

    /// Deliberately identical at N-1 and N, and deliberately free of any
    /// msg.sender constraint: the ONLY difference across this pair must be the
    /// declared TYPE of `registry`, so no other rule has anything to react to.
    function deposit() external payable {
        require(address(registry) != address(0), "registry unset");
        totalDeposits += msg.value;
    }

    function _authorizeUpgrade(address newImplementation) internal override onlyOwner {}
}

contract VaultFactory {
    event VaultDeployed(address proxy, address implementation);

    function deployVault(address owner_, IRegistry registry_) external returns (address) {
        Vault implementation = new Vault();
        ERC1967Proxy proxy = new ERC1967Proxy(
            address(implementation),
            abi.encodeCall(Vault.initialize, (owner_, registry_))
        );
        emit VaultDeployed(address(proxy), address(implementation));
        return address(proxy);
    }
}
