// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;

import {AccessControl} from "@openzeppelin/contracts/access/AccessControl.sol";

contract Treasury is AccessControl {
    bytes32 public constant TREASURER_ROLE = keccak256("TREASURER_ROLE");

    constructor(address admin, address treasurer) {
        _grantRole(DEFAULT_ADMIN_ROLE, admin);
        _grantRole(TREASURER_ROLE, treasurer);
    }

    receive() external payable {}

    function withdraw(address payable to, uint256 amount) external {
        (bool ok, ) = to.call{value: amount}("");
        require(ok, "Treasury: transfer failed");
    }
}
