// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;

import "@openzeppelin/contracts/access/Ownable.sol";

interface IERC20 {
    function transfer(address to, uint256 amount) external returns (bool);
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
    function approve(address spender, uint256 amount) external returns (bool);
    function balanceOf(address who) external view returns (uint256);
}

contract Collector is Ownable {
    address public payer;
    address public vault;
    IERC20 internal token;

    function init(address payer_) external {
        payer = payer_;
    }

    function collect(uint256 amount) external onlyOwner {
        token.transferFrom(payer, vault, amount);
    }
}
