// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;

import {Initializable} from "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import {UUPSUpgradeable} from "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import {OwnableUpgradeable} from "@openzeppelin/contracts-upgradeable/access/OwnableUpgradeable.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";

/// @notice RC-AST1 negative, N-1 side. `registry` and `oracle` are CONTRACT-typed
/// state variables, so solc emits their layout type as `t_contract(IRegistry)<astId>`
/// / `t_contract(IOracle)<astId>` -- a string carrying an astId suffix. Nothing
/// about the storage layout changes at N; only an unrelated interface is declared
/// ahead of these two, which renumbers every following astId. Rule 3c must be
/// quiet: no slot, offset, or real type changed.
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
