// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;

contract Registry {
    address public beneficiary;

    error ZeroAddress();

    function setBeneficiary(address newBeneficiary) external {
        if (newBeneficiary == address(0)) revert ZeroAddress();
        beneficiary = newBeneficiary;
    }
}
