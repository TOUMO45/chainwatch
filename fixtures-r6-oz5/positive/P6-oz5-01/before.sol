// SPDX-License-Identifier: MIT
pragma solidity 0.8.27;

/// @notice Rule 6 OZ5-namespace positive paired with N6-oz5-01. setAmount
/// takes newAmount, and the guard `require(newAmount <= $.maxAmount)` reads
/// newAmount DIRECTLY (as well as $.maxAmount via the assembly-assigned
/// storage pointer). This is a real parameter-validation gate through an
/// ERC-7201 namespaced storage pointer. Rule 6 fires today, and MUST STILL
/// FIRE after the RC-OZ5-R6 fix -- newAmount is in the guard's transitive
/// read set, so no over-approximation is being relied on.
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
        require(newAmount <= $.maxAmount, "over cap");
        $.currentAmount = newAmount;
    }
}
