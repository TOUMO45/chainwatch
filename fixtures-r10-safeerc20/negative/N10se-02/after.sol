// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;

import "@openzeppelin/contracts/access/Ownable.sol";

interface IERC20 {
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
}

library SafeERC20 {
    function safeTransferFrom(IERC20 token, address from, address to, uint256 value) internal {
        require(token.transferFrom(from, to, value), "SafeERC20: transferFrom failed");
    }
}

contract Collector is Ownable {
    using SafeERC20 for IERC20;

    address public payer;
    address public vault;
    IERC20 internal token;

    function init(address payer_) external {
        payer = payer_;
    }

    function collect(uint256 amount) external onlyOwner {
        token.safeTransferFrom(payer, vault, amount);
    }
}
