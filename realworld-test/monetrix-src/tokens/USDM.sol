// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.27;

import "@openzeppelin/contracts-upgradeable/token/ERC20/ERC20Upgradeable.sol";
import "@openzeppelin/contracts-upgradeable/utils/PausableUpgradeable.sol";

import {MonetrixGovernedUpgradeable} from "../governance/MonetrixGovernedUpgradeable.sol";

/// @title USDM - Monetrix Delta-Neutral Stablecoin
/// @notice 1:1 USDC-backed stablecoin, 6 decimals. Pure token, no business logic.
/// @dev `mint` / `burn` restricted to `vault` (bound once via `setVault`).
///      `pause` / `unpause` are held by GUARDIAN.
contract USDM is ERC20Upgradeable, PausableUpgradeable, MonetrixGovernedUpgradeable {
    address public vault;

    event VaultSet(address indexed vault);

    error VaultAlreadySet();
    error NotVault();
    error ZeroVault();

    modifier onlyVault() {
        if (msg.sender != vault) revert NotVault();
        _;
    }

    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        _disableInitializers();
    }

    function initialize(address _acl) external initializer {
        __ERC20_init("Monetrix USD", "USDM");
        __Pausable_init();
        __Governed_init(_acl);
    }

    /// @notice One-time binding of the Vault address. Irreversible.
    function setVault(address _vault) external onlyGovernor {
        if (_vault == address(0)) revert ZeroVault();
        if (vault != address(0)) revert VaultAlreadySet();
        vault = _vault;
        emit VaultSet(_vault);
    }

    function mint(address to, uint256 amount) external onlyVault {
        _mint(to, amount);
    }

    /// @notice Burn USDM from the caller's own balance.
    /// @dev Vault.claimRedeem holds the USDM to be burned in its own balance
    ///      (transferred in during requestRedeem), so self-burn is sufficient.
    function burn(uint256 amount) external onlyVault {
        _burn(msg.sender, amount);
    }

    function pause() external onlyGuardian {
        _pause();
    }

    function unpause() external onlyGuardian {
        _unpause();
    }

    function decimals() public pure override returns (uint8) {
        return 6;
    }

    function _update(address from, address to, uint256 value) internal override whenNotPaused {
        super._update(from, to, value);
    }

    uint256[49] private __gap;
}
