// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;

contract WeightRegistry {
    uint256[10] private weights;

    function setWeight(uint256 index, uint256 value) external {
        weights[index] = value;
    }

    function weightSum() external view returns (uint256 sum) {
        for (uint256 i = 0; i < 10; i++) {
            sum = sum + weights[i];
        }
    }
}
