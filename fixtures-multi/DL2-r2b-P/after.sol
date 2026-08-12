// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;

import "./Registry.sol";

/// @notice Vault at commit N. The ONLY change from before.sol is that the
/// balances write moved to AFTER the external hook call. Guard is unchanged.
/// Registry.sol is byte-identical between commits. Rule 2b MUST still fire
/// on Vault.withdraw — the regression is in the changed file — even after the
/// RC-1 fix scopes rules to the changed set.
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
        hook.notify(amount);
        balances[msg.sender] -= amount;
    }
}
