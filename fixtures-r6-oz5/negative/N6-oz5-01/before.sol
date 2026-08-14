// SPDX-License-Identifier: MIT
pragma solidity 0.8.27;

/// @notice Rule 6 OZ5-namespace negative for RC-OZ5-R6. The require condition
/// reads block.timestamp and $.lastRotation only; newGuardian never appears
/// in the guard's variables_read. But `$` is an assembly-assigned local
/// storage pointer, and Slither's is_dependent($, newGuardian, contract)
/// spuriously returns True, so Rule 6 today accepts newGuardian as guarded
/// at N-1 and unguarded at N -> FIRE. The fix must require a REAL read
/// path from the guard's condition to the parameter (parameter itself, or a
/// direct-storage read of a state variable the parameter was written into)
/// before accepting Slither's is_dependent verdict on the assembly-assigned
/// local. Once the fix lands, this pair goes QUIET.
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
        require(block.timestamp >= $.lastRotation + ROTATION_COOLDOWN, "too soon");
        $.lastRotation = block.timestamp;
        $.guardian = newGuardian;
    }
}
