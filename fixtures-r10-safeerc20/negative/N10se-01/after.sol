// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;

import "@openzeppelin/contracts/access/Ownable.sol";

interface IERC20 {
    function approve(address spender, uint256 amount) external returns (bool);
}

library SafeERC20 {
    function safeApprove(IERC20 token, address spender, uint256 value) internal {
        require(token.approve(spender, value), "SafeERC20: approve failed");
    }
}

contract Swapper is Ownable {
    using SafeERC20 for IERC20;

    address public router;
    IERC20 internal token;

    function init(address router_) external {
        router = router_;
    }

    function approveRouter(uint256 amount) external onlyOwner {
        token.safeApprove(router, amount);
    }
}
