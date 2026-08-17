// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;

import "@openzeppelin/contracts/access/Ownable.sol";

interface IOracle {
    function price() external view returns (uint256);
}

contract Vault is Ownable {
    address payable public treasury;

    constructor(address payable treasury_) {
        treasury = treasury_;
    }

    function rotateTreasury(address payable t) external onlyOwner {
        treasury = t;
    }

    function payout(uint256 amount) external onlyOwner {
        treasury.transfer(amount);
    }
}
