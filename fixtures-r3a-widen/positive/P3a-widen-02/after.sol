// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;

/// @notice Same shape as before.sol, but `changeAdmin`'s guard now compares
/// msg.sender against `pendingController` instead of `admin` itself -
/// looks like a routine refactor (a check survives), but `pendingController`
/// has an unguarded setter anyone can call. Reachability-complete: unlike
/// P3a-widen-01's UUPS `_authorizeUpgrade` (always internal by design), this
/// target function is directly external and state-changing, so this fixture
/// proves the caller-set-widened trigger can reach CONFIRMED, not just fire.
contract ProxyAdmin {
    address public implementation;
    address public admin;
    address public pendingController;

    constructor(address admin_, address implementation_) {
        admin = admin_;
        implementation = implementation_;
    }

    function setPendingController(address controller) external {
        pendingController = controller;
    }

    function changeAdmin(address newAdmin) external {
        require(msg.sender == pendingController, "ProxyAdmin: not authorized");
        admin = newAdmin;
    }

    function upgradeTo(address newImplementation) external {
        require(msg.sender == admin, "ProxyAdmin: not admin");
        implementation = newImplementation;
    }
}
