// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;

import "@openzeppelin/contracts/access/Ownable.sol";

interface IERC20 {
    function transfer(address to, uint256 amount) external returns (bool);
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
}

library SafeERC20 {
    function safeTransfer(IERC20 token, address to, uint256 value) internal {
        require(token.transfer(to, value), "SafeERC20: transfer failed");
    }

    function safeTransferFrom(IERC20 token, address from, address to, uint256 value) internal {
        require(token.transferFrom(from, to, value), "SafeERC20: transferFrom failed");
    }
}

contract Fees is Ownable {
    using SafeERC20 for IERC20;

    address public feeRecipient;
    IERC20 internal token;

    constructor(address feeRecipient_) {
        feeRecipient = feeRecipient_;
    }

    function payout(uint256 amount) external onlyOwner {
        token.safeTransfer(feeRecipient, amount);
    }
}
