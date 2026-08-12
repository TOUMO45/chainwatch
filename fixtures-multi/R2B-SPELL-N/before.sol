// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;

interface IAssetHook {
    function onEnable(address asset) external;
}

/// @notice Governance-only asset-enable at commit N-1. onlyOwner-guarded; the
/// require reads `supported[a]` directly (a real revert guard, not a loop-skip
/// continue). The state write to `supported[a]` precedes the external hook
/// call at N-1. Reserve's Upgrade4_2_0.castSpell is the real-world instance
/// this fixture mirrors: admin-only mutation whose guard reads the same var
/// that will move across the call between commits.
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
        supported[a] = true;
        hook.onEnable(a);
    }
}
