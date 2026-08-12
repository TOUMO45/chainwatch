// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;

interface IClaimHook {
    function onClaim(address recipient, uint256 amount) external;
}

/// @notice The ONLY change from before.sol is that `owed[msg.sender] -= amt`
/// moved to AFTER the hook.onClaim call. Mutex status is unchanged. Non-admin
/// (anyone can call), and owed is checked in a proper require guard reading
/// owed directly. A hook that re-enters claim() sees stale owed and drains the
/// vault. Rule 2b MUST still fire after the CAUSE-3 fix (which targets the
/// admin-guarded case only).
contract PayoutVault {
    mapping(address => uint256) public owed;
    IClaimHook public hook;
    bool internal _entered;

    modifier nonReentrant() {
        require(!_entered, "reentrant");
        _entered = true;
        _;
        _entered = false;
    }

    constructor(IClaimHook _hook) { hook = _hook; }

    function credit(address who, uint256 amt) external {
        owed[who] += amt;
    }

    function claim() external nonReentrant {
        require(owed[msg.sender] > 0, "nothing owed");
        uint256 amt = owed[msg.sender];
        hook.onClaim(msg.sender, amt);
        owed[msg.sender] -= amt;
    }
}
