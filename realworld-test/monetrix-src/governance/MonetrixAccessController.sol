// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.27;

import "@openzeppelin/contracts-upgradeable/access/AccessControlUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";

import {IMonetrixAccessController} from "./IMonetrixAccessController.sol";

/// @title MonetrixAccessController
/// @notice Single source of truth for protocol permissions. All core contracts
///         defer to this registry through MonetrixGovernedUpgradeable.
/// @dev Role-holder design:
///         - DEFAULT_ADMIN_ROLE: held by the 48h TimelockController post-migration
///           (the deployer EOA only during Stage 0 bootstrap and MUST renounce
///           after the timelock has been verified).
///         - GOVERNOR:     24h TimelockController
///         - UPGRADER:     48h TimelockController
///         - GUARDIAN:     Guardian multisig
///         - OPERATOR:     bot hot wallets (multiple)
///
///         Its own upgrade is gated by DEFAULT_ADMIN_ROLE (i.e. the 48h
///         timelock), giving the registry the same 48h delay as other upgrades.
contract MonetrixAccessController is
    IMonetrixAccessController,
    AccessControlUpgradeable,
    UUPSUpgradeable
{
    bytes32 public constant GUARDIAN = keccak256("MONETRIX_GUARDIAN");
    bytes32 public constant GOVERNOR = keccak256("MONETRIX_GOVERNOR");
    bytes32 public constant UPGRADER = keccak256("MONETRIX_UPGRADER");
    bytes32 public constant OPERATOR = keccak256("MONETRIX_OPERATOR");

    error NotAuthorized(bytes32 role, address account);
    error ZeroAddress();

    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        _disableInitializers();
    }

    /// @param admin Bootstrap admin. Normally the deployer EOA; MUST be
    ///              transferred to the 48h timelock and renounced after
    ///              wiring completes.
    function initialize(address admin) external initializer {
        if (admin == address(0)) revert ZeroAddress();
        __AccessControl_init();
        _grantRole(DEFAULT_ADMIN_ROLE, admin);
    }

    /// @inheritdoc IMonetrixAccessController
    function checkRole(bytes32 role, address account) external view {
        if (!hasRole(role, account)) revert NotAuthorized(role, account);
    }

    /// @dev Resolves ambiguity between IMonetrixAccessController.hasRole and
    ///      AccessControlUpgradeable.hasRole. Both signatures match; we
    ///      forward to the parent implementation.
    function hasRole(bytes32 role, address account)
        public
        view
        override(IMonetrixAccessController, AccessControlUpgradeable)
        returns (bool)
    {
        return super.hasRole(role, account);
    }

    function _authorizeUpgrade(address) internal override onlyRole(DEFAULT_ADMIN_ROLE) {}

    uint256[50] private __gap;
}
