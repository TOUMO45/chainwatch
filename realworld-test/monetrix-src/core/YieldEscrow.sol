// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.27;

import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";

import "../interfaces/IYieldEscrow.sol";
import {MonetrixGovernedUpgradeable} from "../governance/MonetrixGovernedUpgradeable.sol";

/// @title YieldEscrow
/// @notice Holds USDC for yield distribution. Only the Vault contract can
///         pull funds out. Funds are pushed in by the Vault.
/// @dev `onlyVault` is preserved as the hot-path guard. Upgrades are gated
///      by the 48h timelock via the inherited `_authorizeUpgrade` hook.
contract YieldEscrow is IYieldEscrow, MonetrixGovernedUpgradeable {
    using SafeERC20 for IERC20;

    IERC20 public usdc;
    address public vault;

    event DistributionPulled(uint256 amount);

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


    /// @notice Transfer USDC to Vault for yield distribution.
    function pullForDistribution(uint256 amount) external onlyVault {
        require(amount > 0, "YieldEscrow: zero amount");
        require(usdc.balanceOf(address(this)) >= amount, "YieldEscrow: insufficient balance");
        usdc.safeTransfer(vault, amount);
        emit DistributionPulled(amount);
    }

    function balance() external view returns (uint256) {
        return usdc.balanceOf(address(this));
    }

    modifier onlyVault() {
        require(msg.sender == vault, "YieldEscrow: caller is not vault");
        _;
    }

    uint256[50] private __gap;
}
