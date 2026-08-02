// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;

contract Registry {
    address public beneficiary;

    function setBeneficiary(address newBeneficiary) external {
        require(newBeneficiary != address(0), "zero address");
        beneficiary = newBeneficiary;
    }
}
