// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;

import "@openzeppelin/contracts/access/Ownable.sol";

interface IOracle {
    function price() external view returns (uint256);
}

contract Vault is Ownable {
    address payable public treasury;
    uint256 internal _feeBps;

    function init(address payable treasury_) external {
        treasury = treasury_;
    }

    function setTreasury(address payable t) external onlyOwner {
        treasury = t;
    }

    function payout(uint256 amount) external onlyOwner {
        treasury.transfer(amount);
    }
}
