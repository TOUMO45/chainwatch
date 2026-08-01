// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.27;

import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";

import {MonetrixGovernedUpgradeable} from "../governance/MonetrixGovernedUpgradeable.sol";

/// @title InsuranceFund - Monetrix protocol insurance reserve
/// @notice Accumulates USDC from yield splits. Anyone can deposit, withdrawals
///         require the 24h timelock (GOVERNOR).
contract InsuranceFund is MonetrixGovernedUpgradeable {
    using SafeERC20 for IERC20;

    IERC20 public usdc;
    uint256 public totalDeposited;
    uint256 public totalWithdrawn;

    event Deposited(address indexed from, uint256 amount);
    event Withdrawn(address indexed to, uint256 amount, string reason);

    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        _disableInitializers();
    }

    function initialize(address _usdc, address _acl) external initializer {
        require(_usdc != address(0), "IF: zero usdc");
        __Governed_init(_acl);
        usdc = IERC20(_usdc);
    }


    function balance() external view returns (uint256) {
        return usdc.balanceOf(address(this));
    }

    function deposit(uint256 amount) external {
        require(amount > 0, "IF: zero amount");
        usdc.safeTransferFrom(msg.sender, address(this), amount);
        totalDeposited += amount;
        emit Deposited(msg.sender, amount);
    }

    function withdraw(address to, uint256 amount, string calldata reason) external onlyGovernor {
        require(amount > 0, "IF: zero amount");
        require(to != address(0), "IF: zero address");
        require(amount <= usdc.balanceOf(address(this)), "IF: insufficient balance");
        totalWithdrawn += amount;
        usdc.safeTransfer(to, amount);
        emit Withdrawn(to, amount, reason);
    }

    uint256[50] private __gap;
}
