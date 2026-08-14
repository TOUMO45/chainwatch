// SPDX-License-Identifier: MIT
pragma solidity 0.8.27;

/// @notice N version: the rate-limit require is removed. The parameter
/// newGuardian was never actually read in the removed guard's condition
/// (only block.timestamp + $.lastRotation, a namespaced state member reached
/// through an assembly-assigned pointer). Removing this guard is a
/// rate-limit relaxation, not an input-validation loss. Rule 6 must stay
/// quiet after the RC-OZ5-R6 fix.
contract RateLimited {
    struct RLStorage {
        uint256 lastRotation;
        address guardian;
    }

    bytes32 private constant RL_SLOT =
        0x218b63c777a26b192afb136d7906e5241ab48950e506bf5364b61e2151943700;

    uint256 public constant ROTATION_COOLDOWN = 1 days;

    function _getStore() private pure returns (RLStorage storage $) {
        assembly { $.slot := RL_SLOT }
    }

    function rotateGuardian(address newGuardian) external {
        RLStorage storage $ = _getStore();
        $.lastRotation = block.timestamp;
        $.guardian = newGuardian;
    }
}
