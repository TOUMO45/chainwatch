// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;

interface IAccessControl {
    function hasRole(bytes32 role, address account) external view returns (bool);
}

interface IUpgradeHook {
    function onUpgrade(address target) external;
}

/// @notice RC-ROLE negative, N-1 side. Faithful reproduction of Reserve's
/// Upgrade4_2_0.castSpell at 6481e75d, down to the mechanism that actually
/// drives the fire:
///
///   * the access gate is a ROLE-CHECK CALL, `acl.hasRole(OWNER_ROLE,
///     msg.sender)`, NOT a `msg.sender == owner` equality comparison; and
///   * two mappings share the one-shot bookkeeping -- `supported` is only READ
///     here, while `cast` carries the write.
///
/// At N the `cast` mapping is deleted and `supported` absorbs its write, so
/// Rule 2b sees a variable that was previously read-only in this function become
/// written-after-a-call. Note the role check is itself an external call, so
/// every later write is "after a call" on BOTH sides; the fire comes from the
/// consolidation, not from a write physically moving.
contract UpgradeSpell {
    IAccessControl public acl;
    IUpgradeHook public hook;
    bytes32 public constant OWNER_ROLE = keccak256("OWNER_ROLE");

    mapping(address => bool) public supported;
    mapping(address => bool) public cast;

    constructor(IAccessControl _acl, IUpgradeHook _hook) {
        acl = _acl;
        hook = _hook;
    }

    function addSupported(address target) external {
        require(acl.hasRole(OWNER_ROLE, msg.sender), "not owner");
        supported[target] = true;
    }

    /// Can only be cast once per supported target, and only by the role holder.
    function castSpell(address target) external {
        require(acl.hasRole(OWNER_ROLE, msg.sender), "not owner");
        require(supported[target] && !cast[target], "unsupported or already cast");

        cast[target] = true;
        hook.onUpgrade(target);
    }
}
