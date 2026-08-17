// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;

import "@openzeppelin/contracts/access/Ownable.sol";

interface IOracle {
    function price() external view returns (uint256);
}

contract Vault is Ownable {
    address payable public treasury;

    function init(address payable treasury_) external onlyOwner {
        treasury = treasury_;
    }

    function payout(uint256 amount) external onlyOwner {
        treasury.transfer(amount);
    }
}
