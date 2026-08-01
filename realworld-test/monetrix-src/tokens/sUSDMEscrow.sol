// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.27;

import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";

/// @title sUSDMEscrow
/// @notice Dumb escrow that holds USDM for sUSDM unstake cooldowns.
///         No business logic — sUSDM decides when to deposit and release.
///         Non-upgradeable with immutable bindings so neither admin nor a
///         compromised sUSDM upgrade can redirect the asset address.
contract sUSDMEscrow {
    using SafeERC20 for IERC20;

    IERC20 public immutable usdm;
    address public immutable sUSDM;

    error NotSUSDM();
    error ZeroAddress();

    modifier onlySUSDM() {
        if (msg.sender != sUSDM) revert NotSUSDM();
        _;
    }

    constructor(address _usdm, address _sUSDM) {
        if (_usdm == address(0) || _sUSDM == address(0)) revert ZeroAddress();
        usdm = IERC20(_usdm);
        sUSDM = _sUSDM;
    }

    /// @notice Pull USDM from sUSDM into escrow. Requires prior approval.
    function deposit(uint256 amount) external onlySUSDM {
        usdm.safeTransferFrom(sUSDM, address(this), amount);
    }

    /// @notice Send USDM from escrow to recipient.
    function release(address to, uint256 amount) external onlySUSDM {
        usdm.safeTransfer(to, amount);
    }
}
