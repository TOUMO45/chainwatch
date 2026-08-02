// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;

contract Registry {
    address public beneficiary;

    modifier notZero(address a) {
        require(a != address(0), "zero address");
        _;
    }

    function setBeneficiary(address newBeneficiary) external notZero(newBeneficiary) {
        beneficiary = newBeneficiary;
    }
}
