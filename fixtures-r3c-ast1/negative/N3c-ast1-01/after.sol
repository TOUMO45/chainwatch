// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;

import {Initializable} from "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import {UUPSUpgradeable} from "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import {OwnableUpgradeable} from "@openzeppelin/contracts-upgradeable/access/OwnableUpgradeable.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";

/// @notice RC-AST1 negative, N side. The ONLY change from before.sol is that a
/// new, unrelated `IPauser` interface is declared ahead of IRegistry/IOracle and
/// consumed by a new view helper. That shifts solc's astId numbering for every
/// declaration after it, so `registry` and `oracle` report layout type strings
/// `t_contract(IRegistry)<NEW astId>` / `t_contract(IOracle)<NEW astId>` even
/// though their slot, offset, and actual referenced type are untouched.
///
/// STORAGE IS IDENTICAL: registry / oracle / totalDeposits occupy the same slots
/// and offsets as at N-1, in the same order, with the same real types. Rule 3c
/// must be QUIET. It currently FIRES, because rule3c.py compares the raw solc
/// type string (astId included) rather than the type's identity -- RC-AST1.
interface IPauser {
    function paused() external view returns (bool);
}

interface IRegistry {
    function isRegistered(address who) external view returns (bool);
}

interface IOracle {
    function price() external view returns (uint256);
}

contract Vault is Initializable, OwnableUpgradeable, UUPSUpgradeable {
    IRegistry public registry;
    IOracle public oracle;
    uint256 public totalDeposits;

    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        _disableInitializers();
    }

    function initialize(address owner_, IRegistry registry_, IOracle oracle_) external initializer {
        __Ownable_init();
        __UUPSUpgradeable_init();
        _transferOwnership(owner_);
        registry = registry_;
        oracle = oracle_;
    }

    function deposit() external payable {
        require(registry.isRegistered(msg.sender), "not registered");
        totalDeposits += msg.value;
    }

    /// New at N: read-only helper over an externally supplied pauser. Touches no
    /// storage; exists only to make the added IPauser declaration non-dead.
    function isPaused(IPauser pauser) external view returns (bool) {
        return pauser.paused();
    }

    function _authorizeUpgrade(address newImplementation) internal override onlyOwner {}
}

contract VaultFactory {
    event VaultDeployed(address proxy, address implementation);

    function deployVault(address owner_, IRegistry registry_, IOracle oracle_)
        external
        returns (address)
    {
        Vault implementation = new Vault();
        ERC1967Proxy proxy = new ERC1967Proxy(
            address(implementation),
            abi.encodeCall(Vault.initialize, (owner_, registry_, oracle_))
        );
        emit VaultDeployed(address(proxy), address(implementation));
        return address(proxy);
    }
}
