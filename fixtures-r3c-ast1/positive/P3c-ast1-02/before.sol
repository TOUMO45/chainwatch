// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;

import {Initializable} from "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import {UUPSUpgradeable} from "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import {OwnableUpgradeable} from "@openzeppelin/contracts-upgradeable/access/OwnableUpgradeable.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";

/// @notice RC-AST1 positive #2 (over-strip guard), N-1 side. `buffer` is a
/// FIXED-SIZE array declared last, and it is read/written by `record()`, so it
/// is NOT a reserved gap (exclusion 3c.2 does not apply to it).
///
/// Its layout type string is `t_array(t_uint256)10_storage`. The trailing digits
/// there are the array LENGTH, not an astId. The RC-AST1 fix strips astId
/// suffixes from contract/struct/enum type strings; it must NOT strip the digits
/// out of an array type, or a real length change becomes invisible. This pair is
/// the lock for that distinction.
contract Vault is Initializable, OwnableUpgradeable, UUPSUpgradeable {
    uint256 public totalDeposits;
    uint256[10] public buffer;

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
