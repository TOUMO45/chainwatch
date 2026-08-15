// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;

interface IERC20 {
    function balanceOf(address account) external view returns (uint256);
}

interface IClaimHook {
    function onClaim(address recipient, uint256 amount) external;
}

/// @notice RC-ROLE positive (over-broad guard), N side. Same consolidation as
/// the negative's N side: `claimedOnce` is deleted and `redeemed` absorbs the
/// write, landing after the external hook.onClaim call.
///
/// This is a genuine exploit. `redeemed[msg.sender]` is what the cap guard
/// reads, and it is now written only AFTER the hook runs, so a hook that
/// re-enters redeem() sees a stale `redeemed` and can draw repeatedly past the
/// 1000-ether CAP. The function is anyone-callable: there is no authority gate,
/// only a balance lookup and a cap check.
///
/// MUST STILL FIRE after the RC-ROLE widening. Measured necessity: without the
/// bool-return restriction on authority calls, the widened discriminator returns
/// True for `balanceOf(msg.sender)` and silences this pair -- trading the
/// RC-ROLE false positive for a silent false negative on a real re-entrancy.
contract ShareVault {
    IERC20 public shareToken;
    IClaimHook public hook;
    uint256 public constant CAP = 1000 ether;

    mapping(address => uint256) public redeemed;

    constructor(IERC20 _shareToken, IClaimHook _hook) {
        shareToken = _shareToken;
        hook = _hook;
    }

    /// Anyone may call. No authority gate of any kind.
    function redeem(uint256 amount) external {
        require(shareToken.balanceOf(msg.sender) >= amount, "insufficient shares");
        require(redeemed[msg.sender] + amount <= CAP, "cap exceeded");

        hook.onClaim(msg.sender, amount);
        redeemed[msg.sender] += amount;
    }
}
