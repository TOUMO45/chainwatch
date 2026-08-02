// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;

import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";

contract Disburser {
    IERC20 public token;
    address public to;
    uint256 public amt;

    constructor(IERC20 t, address to_, uint256 amt_) {
        token = t;
        to = to_;
        amt = amt_;
    }

    function disburse() external {
        require(token.transfer(to, amt), "transfer failed");
    }
}
