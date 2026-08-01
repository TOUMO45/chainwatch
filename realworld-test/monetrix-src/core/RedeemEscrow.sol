// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.27;

import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";

import "../interfaces/IRedeemEscrow.sol";
import {MonetrixGovernedUpgradeable} from "../governance/MonetrixGovernedUpgradeable.sol";

/// @title RedeemEscrow
/// @notice Holds USDC reserved for pending redemptions. Only the Vault
///         contract can move funds out (payOut to users, reclaimTo vault).
/// @dev `onlyVault` (msg.sender-based) is kept as a cheap hot-path check —
///      funds here flow exclusively through the Vault. Upgrades are gated by
///      the 48h timelock via the inherited `_authorizeUpgrade` hook.
contract RedeemEscrow is IRedeemEscrow, MonetrixGovernedUpgradeable {
    using SafeERC20 for IERC20;

    IERC20 public usdc;
    address public vault;
    uint256 public totalOwed;

    event ObligationAdded(uint256 amount, uint256 totalOwed);
    event PaidOut(address indexed recipient, uint256 amount);
    event Reclaimed(address indexed to, uint256 amount);

    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        _disableInitializers();
    }

    function initialize(address _usdc, address _vault, address _acl) external initializer {
        require(_usdc != address(0) && _vault != address(0), "zero addr");
        __Governed_init(_acl);
        usdc = IERC20(_usdc);
        vault = _vault;
    }


    /// @notice Record a new redemption obligation. Called by Vault during requestRedeem.
    function addObligation(uint256 amount) external onlyVault {
        totalOwed += amount;
        emit ObligationAdded(amount, totalOwed);
    }

    /// @notice Pay USDC to a redeem claimant and reduce obligation.
    function payOut(address recipient, uint256 amount) external onlyVault {
        require(amount > 0, "RedeemEscrow: zero amount");
        require(usdc.balanceOf(address(this)) >= amount, "RedeemEscrow: insufficient liquidity");
        totalOwed -= amount;
        usdc.safeTransfer(recipient, amount);
        emit PaidOut(recipient, amount);
    }

    /// @notice Reclaim excess USDC back to a target address (typically vault).
    /// @dev Enforces that pending redemption obligations stay fully collateralized —
    ///      callers cannot drain below `totalOwed`, preventing operator compromise from
    ///      freezing pending `claimRedeem` calls.
    function reclaimTo(address to, uint256 amount) external onlyVault {
        require(amount > 0, "RedeemEscrow: zero amount");
        uint256 bal = usdc.balanceOf(address(this));
        require(bal >= amount + totalOwed, "RedeemEscrow: would underfund obligations");
        usdc.safeTransfer(to, amount);
        emit Reclaimed(to, amount);
    }

    function shortfall() external view returns (uint256) {
        uint256 bal = usdc.balanceOf(address(this));
        return totalOwed > bal ? totalOwed - bal : 0;
    }

    function balance() external view returns (uint256) {
        return usdc.balanceOf(address(this));
    }

    modifier onlyVault() {
        require(msg.sender == vault, "RedeemEscrow: caller is not vault");
        _;
    }

    uint256[50] private __gap;
}
