// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;

import "@openzeppelin/contracts/access/Ownable.sol";

interface IERC20 {
    function transfer(address to, uint256 amount) external returns (bool);
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
    function approve(address spender, uint256 amount) external returns (bool);
    function balanceOf(address who) external view returns (uint256);
}

contract Watcher is Ownable {
    address public observed;
    IERC20 internal token;

    function init(address observed_) external {
        observed = observed_;
    }

    function seen() external view returns (uint256) {
        return token.balanceOf(observed);
    }
}
