// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;

import "./Registry.sol";

/// @notice Vault at commit N-1. CEI-correct: balance is decremented BEFORE the
/// external hook call. Guarded by a plain mutex (no OZ dependency).
contract Vault {
    mapping(address => uint256) public balances;
    IHook public hook;
    bool internal _entered;

    modifier nonReentrant() {
        require(!_entered, "reentrant");
        _entered = true;
        _;
        _entered = false;
    }

    function deposit() external payable {
        balances[msg.sender] += msg.value;
    }

    function withdraw(uint256 amount) external nonReentrant {
        require(Registry.isHookRegistered(hook), "hook missing");
        require(balances[msg.sender] >= amount, "insufficient");
        balances[msg.sender] -= amount;
        hook.notify(amount);
    }
}
