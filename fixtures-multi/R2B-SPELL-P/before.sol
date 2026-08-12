// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;

interface IClaimHook {
    function onClaim(address recipient, uint256 amount) external;
}

/// @notice Paired positive for CAUSE 3. Non-admin claim() — anyone can call.
/// The require reads `owed[msg.sender]` directly (not through a local), so
/// own_guard_state_reads sees `owed`. At N-1 the balance is decremented BEFORE
/// the external hook.onClaim call. Guarded by a plain mutex (nonReentrant).
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
        owed[msg.sender] -= amt;
        hook.onClaim(msg.sender, amt);
    }
}
