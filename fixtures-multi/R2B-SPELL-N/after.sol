// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;

interface IAssetHook {
    function onEnable(address asset) external;
}

/// @notice Same governance-only enableAsset at commit N. The ONLY change from
/// before.sol is that the write to `supported[a]` moved to AFTER the external
/// hook.onEnable call. Rule 2b currently fires — moved = {supported},
/// own_guard_state_reads includes supported (via require(!supported[a])), so
/// moved & guards = {supported}. But onlyOwner + msg.sender-based re-entry
/// gating make this practically unexploitable: any re-entrant caller has
/// msg.sender = hook, which the onlyOwner modifier rejects before the guard
/// runs. The CAUSE-3 admin-exclusion fix must silence this pair.
contract SpellVault {
    address public owner;
    mapping(address => bool) public supported;
    IAssetHook public hook;

    modifier onlyOwner() { require(msg.sender == owner, "not owner"); _; }

    constructor(address _owner, IAssetHook _hook) {
        owner = _owner;
        hook  = _hook;
    }

    function enableAsset(address a) external onlyOwner {
        require(!supported[a], "already enabled");
        hook.onEnable(a);
        supported[a] = true;
    }
}
