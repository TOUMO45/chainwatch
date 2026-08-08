// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;

contract Bank {
    mapping(address => uint256) public balanceOf;

    function deposit() external payable {
        balanceOf[msg.sender] = balanceOf[msg.sender] + msg.value;
    }

    function transfer(address to, uint256 amount) external {
        uint256 bal = balanceOf[msg.sender];
        require(bal >= amount, "insufficient balance");
        unchecked {
            balanceOf[msg.sender] = bal - amount;
        }
        balanceOf[to] = balanceOf[to] + amount;
    }
}
