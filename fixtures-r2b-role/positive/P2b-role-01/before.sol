// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;

interface IERC20 {
    function balanceOf(address account) external view returns (uint256);
}

interface IClaimHook {
    function onClaim(address recipient, uint256 amount) external;
}

/// @notice RC-ROLE positive (over-broad guard), N-1 side. Structurally IDENTICAL
/// to N2b-role-01 -- same consolidation mechanism, same guard-call-then-write
/// ordering -- with exactly one difference: the guard call
/// `shareToken.balanceOf(msg.sender)` returns uint256, not bool.
///
/// That single difference is what the pair isolates. A discriminator that treats
/// "any call taking msg.sender whose result reaches a guard" as access control
/// would classify this balance lookup as an admin gate and silence a real
/// exploit. Only a BOOL return means "is this caller authorised"; a numeric
/// lookup constrains how much, not whether.
///
/// `redeemed` is read by the cap guard but written nowhere in this function at
/// N-1; `claimedOnce` carries the write.
contract ShareVault {
    IERC20 public shareToken;
    IClaimHook public hook;
    uint256 public constant CAP = 1000 ether;

    mapping(address => uint256) public redeemed;
    mapping(address => bool) public claimedOnce;

    constructor(IERC20 _shareToken, IClaimHook _hook) {
        shareToken = _shareToken;
        hook = _hook;
    }

    /// Anyone may call. No authority gate of any kind.
    function redeem(uint256 amount) external {
        require(shareToken.balanceOf(msg.sender) >= amount, "insufficient shares");
        require(redeemed[msg.sender] + amount <= CAP, "cap exceeded");

        claimedOnce[msg.sender] = true;
        hook.onClaim(msg.sender, amount);
    }
}
