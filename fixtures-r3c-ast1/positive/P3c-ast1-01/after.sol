// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;

import {Initializable} from "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import {UUPSUpgradeable} from "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import {OwnableUpgradeable} from "@openzeppelin/contracts-upgradeable/access/OwnableUpgradeable.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";

/// @notice RC-AST1 positive #1, N side. The `registry` storage slot keeps its
/// position but its declared type changes identity: IRegistry -> IOracle. The
/// proxy's persisted address at that slot was written as a registry and will now
/// be called as an oracle -- a genuine upgrade hazard on live storage, and a
/// RULES.md Rule 3c trigger ("slot index or TYPE changed between commits").
///
/// This is the discriminator the RC-AST1 fix must not break. Canonicalising the
/// astId suffix away leaves `t_contract(IRegistry)` vs `t_contract(IOracle)`,
/// which still differ -- so this pair MUST still FIRE after the fix. A fix that
/// blanket-ignores type-string differences would silence this and trade the
/// RC-AST1 false positive for a silent false negative.
interface IRegistry {
    function isRegistered(address who) external view returns (bool);
}

interface IOracle {
    function price() external view returns (uint256);
}

contract Vault is Initializable, OwnableUpgradeable, UUPSUpgradeable {
    IOracle public registry;
    uint256 public totalDeposits;

    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        _disableInitializers();
    }

    function initialize(address owner_, IOracle registry_) external initializer {
        __Ownable_init();
        __UUPSUpgradeable_init();
        _transferOwnership(owner_);
        registry = registry_;
    }

    /// Byte-identical to the N-1 body. The ONLY difference across this pair is
    /// the declared TYPE of `registry`, so no rule other than 3c has anything
    /// to react to.
    function deposit() external payable {
        require(address(registry) != address(0), "registry unset");
        totalDeposits += msg.value;
    }

    function _authorizeUpgrade(address newImplementation) internal override onlyOwner {}
}

contract VaultFactory {
    event VaultDeployed(address proxy, address implementation);

    function deployVault(address owner_, IOracle registry_) external returns (address) {
        Vault implementation = new Vault();
        ERC1967Proxy proxy = new ERC1967Proxy(
            address(implementation),
            abi.encodeCall(Vault.initialize, (owner_, registry_))
        );
        emit VaultDeployed(address(proxy), address(implementation));
        return address(proxy);
    }
}
