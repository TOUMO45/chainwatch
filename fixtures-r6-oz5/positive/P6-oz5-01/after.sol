// SPDX-License-Identifier: MIT
pragma solidity 0.8.27;

/// @notice N version: the parameter-validation require is removed. newAmount
/// is now written to $.currentAmount without any bound check against
/// $.maxAmount -- a caller can set a value exceeding the intended cap. This
/// is a textbook RULES.md Rule 6 (SC05) input-validation regression on a
/// state-changing function. The RC-OZ5-R6 fix must NOT silence this pair:
/// newAmount appeared DIRECTLY in the removed guard's read set (not only
/// via is_dependent on the assembly-assigned $ pointer), so the tightened
/// discriminator still accepts newAmount as guarded at N-1 and unguarded
/// at N -> FIRE.
contract Cap {
    struct CapStorage {
        uint256 maxAmount;
        uint256 currentAmount;
    }

    bytes32 private constant CAP_SLOT =
        0x51b8b1f42c1b3c8d16e2f1b8e0a1d6b3c8e2f5b7d1a3c5e7f9b1d3f5a7c9e100;

    function _getStore() private pure returns (CapStorage storage $) {
        assembly { $.slot := CAP_SLOT }
    }

    function setAmount(uint256 newAmount) external {
        CapStorage storage $ = _getStore();
        $.currentAmount = newAmount;
    }
}
