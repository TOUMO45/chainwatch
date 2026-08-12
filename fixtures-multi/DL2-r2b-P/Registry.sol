// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;

interface IHook {
    function notify(uint256 amount) external;
}

/// @notice Unchanged utility file imported by the changed Vault. Byte-identical
/// in the before/after commits of this fixture. Exists to prove that the RC-1
/// (DESIGN-L2) fix does not over-suppress a real Rule 2b fire whose declaration
/// lives in the changed file.
library Registry {
    function isHookRegistered(IHook /*h*/) internal pure returns (bool) {
        return true;
    }
}
