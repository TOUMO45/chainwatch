// SPDX-License-Identifier: MIT
pragma solidity 0.8.27;

import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";

contract FeeManager is Ownable {
    /// @custom:storage-location erc7201:chainwatch.storage.FeeManager
    struct FeeManagerStorage {
        uint256 totalCollected;
        address feeRecipient;
    }

    // keccak256(abi.encode(uint256(keccak256("chainwatch.storage.FeeManager")) - 1)) & ~bytes32(uint256(0xff))
    bytes32 private constant FeeManagerStorageLocation =
        0xb9d3ee8af223778d36922fdcee6837e5a3507faf3a8b9f8a5a33d2a58e0db500;

    function _getFeeManagerStorage() private pure returns (FeeManagerStorage storage $) {
        assembly {
            $.slot := FeeManagerStorageLocation
        }
    }

    constructor(address initialOwner, address feeRecipient_) Ownable(initialOwner) {
        _getFeeManagerStorage().feeRecipient = feeRecipient_;
    }

    function collect() external payable {
        _getFeeManagerStorage().totalCollected += msg.value;
    }

    function sweep() external onlyOwner {
        uint256 amount = address(this).balance;
        (bool ok, ) = _getFeeManagerStorage().feeRecipient.call{value: amount}("");
        require(ok, "FeeManager: sweep failed");
    }

    function setFeeRecipient(address feeRecipient_) external onlyOwner {
        _getFeeManagerStorage().feeRecipient = feeRecipient_;
    }

    function totalCollected() external view returns (uint256) {
        return _getFeeManagerStorage().totalCollected;
    }

    function feeRecipient() external view returns (address) {
        return _getFeeManagerStorage().feeRecipient;
    }
}
