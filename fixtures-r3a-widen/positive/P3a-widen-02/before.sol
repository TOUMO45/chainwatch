// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;

/// @notice A hand-rolled transparent-proxy-style admin setter - direct
/// external target function (not routed through UUPS's internal
/// _authorizeUpgrade hook), so this fixture also exercises reachability for
/// the caller-set-widened trigger on a genuinely external function.
contract ProxyAdmin {
    address public implementation;
    address public admin;

    constructor(address admin_, address implementation_) {
        admin = admin_;
        implementation = implementation_;
    }

    // `admin`'s only writer is this function, and it is self-guarded: only
    // the CURRENT admin can hand the role to a new one. Genuinely protected.
    function changeAdmin(address newAdmin) external {
        require(msg.sender == admin, "ProxyAdmin: not admin");
        admin = newAdmin;
    }

    function upgradeTo(address newImplementation) external {
        require(msg.sender == admin, "ProxyAdmin: not admin");
        implementation = newImplementation;
    }
}
