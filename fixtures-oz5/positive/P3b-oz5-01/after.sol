// SPDX-License-Identifier: MIT
pragma solidity 0.8.27;

import {Initializable} from "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import {UUPSUpgradeable} from "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import {OwnableUpgradeable} from "@openzeppelin/contracts-upgradeable/access/OwnableUpgradeable.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";

contract Vault is Initializable, OwnableUpgradeable, UUPSUpgradeable {
    /// @custom:storage-location erc7201:chainwatch.storage.Vault
    struct VaultStorage {
        uint256 totalDeposits;
        address feeRecipient;
    }

    // keccak256(abi.encode(uint256(keccak256("chainwatch.storage.Vault")) - 1)) & ~bytes32(uint256(0xff))
    bytes32 private constant VaultStorageLocation =
        0x6492f3ab362457cfcad13646ddaf2a73e71136485946e5538e0920e7eb3a8600;

    function _getVaultStorage() private pure returns (VaultStorage storage $) {
        assembly {
            $.slot := VaultStorageLocation
        }
    }

    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        _disableInitializers();
    }

    function initialize(address owner_, address feeRecipient_) external {
        _transferOwnership(owner_);
        _getVaultStorage().feeRecipient = feeRecipient_;
    }

    function deposit() external payable {
        _getVaultStorage().totalDeposits += msg.value;
    }

    function withdraw(uint256 amount) external onlyOwner {
        VaultStorage storage $ = _getVaultStorage();
        $.totalDeposits -= amount;
        (bool ok, ) = msg.sender.call{value: amount}("");
        require(ok, "Vault: transfer failed");
    }

    function totalDeposits() external view returns (uint256) {
        return _getVaultStorage().totalDeposits;
    }

    function feeRecipient() external view returns (address) {
        return _getVaultStorage().feeRecipient;
    }

    function _authorizeUpgrade(address newImplementation) internal override onlyOwner {}
}

contract VaultFactory {
    event VaultDeployed(address proxy, address implementation);

    function deployVault(address owner_, address feeRecipient_) external returns (address) {
        Vault implementation = new Vault();
        ERC1967Proxy proxy = new ERC1967Proxy(
            address(implementation),
            abi.encodeCall(Vault.initialize, (owner_, feeRecipient_))
        );
        emit VaultDeployed(address(proxy), address(implementation));
        return address(proxy);
    }
}
