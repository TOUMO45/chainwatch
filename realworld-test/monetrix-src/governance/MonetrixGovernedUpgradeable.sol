// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.27;

import "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";

import {IMonetrixAccessController} from "./IMonetrixAccessController.sol";

/// @title MonetrixGovernedUpgradeable
/// @notice Abstract base class for every upgradeable Monetrix contract.
///         Replaces AccessControlUpgradeable usage across the protocol —
///         instead of each contract maintaining its own role registry, every
///         check defers to the shared MonetrixAccessController ("ACL").
/// @dev Inheritors must:
///         1. Call `__Governed_init(acl)` from their own `initialize()`.
///         2. Use the `onlyGuardian / onlyGovernor / onlyUpgrader /
///            onlyOperator` modifiers in place of `onlyRole(...)`.
///         3. NOT override `_authorizeUpgrade` — it is already wired to
///            `onlyUpgrader` (the 48h timelock path).
abstract contract MonetrixGovernedUpgradeable is Initializable, UUPSUpgradeable {
    IMonetrixAccessController public acl;

    error NotAuthorized(bytes32 role, address caller);
    error ZeroAccessController();

    // ─── Modifiers ─────────────────────────────────────────────
    modifier onlyGuardian() {
        _check(acl.GUARDIAN(), msg.sender);
        _;
    }

    modifier onlyGovernor() {
        _check(acl.GOVERNOR(), msg.sender);
        _;
    }

    modifier onlyUpgrader() {
        _check(acl.UPGRADER(), msg.sender);
        _;
    }

    modifier onlyOperator() {
        _check(acl.OPERATOR(), msg.sender);
        _;
    }

    // ─── Init ──────────────────────────────────────────────────
    /// @dev Idempotent wrt reinitializer: child contracts may call this from
    ///      either `initialize()` (fresh deployment) or a `reinitialize(n)`
    ///      during migration of an existing proxy.
    function __Governed_init(address _acl) internal onlyInitializing {
        if (_acl == address(0)) revert ZeroAccessController();
        acl = IMonetrixAccessController(_acl);
    }

    // ─── Upgrade authorization ────────────────────────────────
    /// @dev Gated by the UPGRADER role — in production this is the 48h
    ///      TimelockController, so every implementation swap inherits the
    ///      48h delay automatically.
    function _authorizeUpgrade(address) internal view override {
        _check(acl.UPGRADER(), msg.sender);
    }

    // ─── Internal ──────────────────────────────────────────────
    function _check(bytes32 role, address caller) private view {
        if (!acl.hasRole(role, caller)) revert NotAuthorized(role, caller);
    }

    uint256[49] private __gap;
}
