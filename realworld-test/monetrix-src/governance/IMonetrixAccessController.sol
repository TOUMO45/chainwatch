// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.27;

/// @title IMonetrixAccessController
/// @notice Centralized ACL registry interface consumed by all Monetrix
///         contracts via MonetrixGovernedUpgradeable. Exposes the canonical
///         role identifiers and the revert-on-fail `checkRole` helper used by
///         modifiers.
interface IMonetrixAccessController {
    // ─── Canonical role identifiers ────────────────────────────
    // Held by Guardian multisig.
    function GUARDIAN() external view returns (bytes32);
    // Held by the 24h TimelockController.
    function GOVERNOR() external view returns (bytes32);
    // Held by the 48h TimelockController.
    function UPGRADER() external view returns (bytes32);
    // Held by bot hot wallets (supports multiple addresses).
    function OPERATOR() external view returns (bytes32);

    // ─── Role queries ──────────────────────────────────────────
    function hasRole(bytes32 role, address account) external view returns (bool);

    /// @notice Reverts with NotAuthorized(role, account) when the account
    ///         lacks the role. Kept as a separate view so callers that want a
    ///         single external call rather than a boolean check-then-revert
    ///         can use it (slightly cheaper than two calls).
    function checkRole(bytes32 role, address account) external view;
}
