// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;

import {Initializable} from "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import {UUPSUpgradeable} from "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import {OwnableUpgradeable} from "@openzeppelin/contracts-upgradeable/access/OwnableUpgradeable.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";

/// @notice RC-AST1 positive #2 (over-strip guard), N side. `buffer` grows from
/// uint256[10] to uint256[20] -- it now claims ten more 32-byte slots of the
/// proxy's storage that were previously unallocated. Slot and offset of the
/// declaration itself are unchanged, so the ONLY signal is the layout type
/// string: `t_array(t_uint256)10_storage` -> `t_array(t_uint256)20_storage`.
///
/// A fix that strips ALL trailing digits from type strings would collapse both
/// to `t_array(t_uint256)_storage`, compare them equal, and go silently quiet on
/// a real storage-extent change. This pair MUST still FIRE after the RC-AST1
/// fix; it is the precision lock proving the astId strip is targeted at
/// contract/struct/enum identifiers only, never at array lengths.
contract Vault is Initializable, OwnableUpgradeable, UUPSUpgradeable {
    uint256 public totalDeposits;
    uint256[20] public buffer;

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

    function record(uint256 idx, uint256 value) external onlyOwner {
        buffer[idx] = value;
    }

    function readBuffer(uint256 idx) external view returns (uint256) {
        return buffer[idx];
    }

    function _authorizeUpgrade(address newImplementation) internal override onlyOwner {}
}

contract VaultFactory {
    event VaultDeployed(address proxy, address implementation);

    function deployVault(address owner_) external returns (address) {
        Vault implementation = new Vault();
        ERC1967Proxy proxy = new ERC1967Proxy(
            address(implementation),
            abi.encodeCall(Vault.initialize, (owner_))
        );
        emit VaultDeployed(address(proxy), address(implementation));
        return address(proxy);
    }
}
