// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;

interface IAccessControl {
    function hasRole(bytes32 role, address account) external view returns (bool);
}

interface IUpgradeHook {
    function onUpgrade(address target) external;
}

/// @notice RC-ROLE negative, N side. Mirrors the real Reserve castSpell diff at
/// 6481e75d..92ff272f: the `cast` mapping is DELETED and its one-shot duty is
/// folded into `supported`, which now flips to false instead.
///
/// Rule 2b therefore computes moved={supported}: at N-1 `supported` was only
/// read by this function, at N it is written after an external call. `supported`
/// is read by the function's own require guard, so moved & own_guard_state_reads
/// is non-empty -> FIRE.
///
/// It SHOULD be suppressed for exactly the reason R2B-SPELL-N is: every caller
/// already holds OWNER_ROLE, so the only re-entry vector is the governance role
/// holder, who gains nothing from a stale read of a flag it controls outright.
/// STEP 4's `_admin_gated_by_state_addr` misses it because the gate is a
/// `hasRole(...)` CALL rather than a `msg.sender == owner` equality -- which is
/// precisely why this pair exists and why R2B-SPELL-N did not catch the gap.
///
/// EXPECTED: quiet once the discriminator also recognises an authority call --
/// one taking msg.sender as an argument and returning BOOL -- as an admin gate.
/// Paired with P2b-role-01, whose guard call takes msg.sender but returns
/// uint256 and must NOT be read as an authority check.
contract UpgradeSpell {
    IAccessControl public acl;
    IUpgradeHook public hook;
    bytes32 public constant OWNER_ROLE = keccak256("OWNER_ROLE");

    mapping(address => bool) public supported;

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
        require(supported[target], "unsupported or already cast");

        hook.onUpgrade(target);
        supported[target] = false;
    }
}
