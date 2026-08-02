// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;

import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";

contract Disburser {
    IERC20 public token;

    constructor(IERC20 t) {
        token = t;
    }

    function disburse(address to, uint256 amt) external {
        token.transfer(to, amt);
    }
}
