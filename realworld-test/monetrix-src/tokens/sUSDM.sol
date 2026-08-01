// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.27;

import "@openzeppelin/contracts-upgradeable/token/ERC20/extensions/ERC4626Upgradeable.sol";
import "@openzeppelin/contracts-upgradeable/utils/PausableUpgradeable.sol";
import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import "@openzeppelin/contracts/token/ERC20/IERC20.sol";

import "../core/MonetrixConfig.sol";
import {MonetrixGovernedUpgradeable} from "../governance/MonetrixGovernedUpgradeable.sol";
import {sUSDMEscrow} from "./sUSDMEscrow.sol";

/// @title sUSDM - Staked USDM (Yield-bearing ERC-4626 vault token)
/// @notice wstETH-style appreciation model. Exchange rate rises as yield is
///         injected. Unstake cooldown physically isolates USDM into
///         `sUSDMEscrow` at burn time — all queue logic stays here.
/// @dev `injectYield` gated on `vault` (bound once via `setVault`).
///      `pause` / `unpause` are `onlyGuardian`.
///      `setConfig` / `setEscrow` / `setVault` are `onlyGovernor` (24h timelock).
contract sUSDM is
    ERC4626Upgradeable,
    PausableUpgradeable,
    ReentrancyGuard,
    MonetrixGovernedUpgradeable
{
    using SafeERC20 for IERC20;

    struct UnstakeRequest {
        address owner;
        uint256 sharesAmount;
        uint256 usdmAmount;
        uint256 exchangeRate;
        uint256 cooldownEnd;
    }

    uint256 public nextRequestId;
    uint256 public totalPendingClaims;
    mapping(uint256 => UnstakeRequest) public unstakeRequests;

    MonetrixConfig public config;

    // Yield tracking
    uint256 public totalYieldInjected;
    uint256 public lastCumulativeYield;

    // ─── User Unstake Request Tracking ───
    mapping(address => uint256[]) private _userUnstakeIds;

    // ─── Physical isolation escrow ───
    sUSDMEscrow public escrow;

    address public vault;

    event UnstakeRequested(
        uint256 indexed requestId,
        address indexed owner,
        uint256 shares,
        uint256 usdmAmount,
        uint256 exchangeRate,
        uint256 cooldownEnd
    );
    event UnstakeClaimed(uint256 indexed requestId, address indexed owner, uint256 usdmAmount);
    event YieldInjected(uint256 amount, uint256 totalAssets, uint256 totalSupply);
    event EscrowSet(address indexed escrow);
    event VaultSet(address indexed vault);

    error CooldownNotExpired(uint256 requestId, uint256 cooldownEnd);
    error NotRequestOwner(uint256 requestId, address caller, address owner);
    error AlreadyClaimed(uint256 requestId);
    error UseCooldownFunctions();
    error EscrowNotSet();
    error EscrowAlreadySet();
    error EscrowMismatch();
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

    function initialize(address _usdm, address _config, address _acl) external initializer {
        require(_usdm != address(0), "sUSDM: zero usdm");
        require(_config != address(0), "sUSDM: zero config");
        __ERC4626_init(IERC20(_usdm));
        __ERC20_init("Staked USDM", "sUSDM");
        __Pausable_init();
        __Governed_init(_acl);
        config = MonetrixConfig(_config);
    }


    // --- ERC-4626 Overrides ---

    function totalAssets() public view override returns (uint256) {
        return IERC20(asset()).balanceOf(address(this));
    }

    function _decimalsOffset() internal pure override returns (uint8) {
        return 6;
    }

    function decimals() public pure override returns (uint8) {
        return 6;
    }

    function withdraw(uint256, address, address) public pure override returns (uint256) {
        revert UseCooldownFunctions();
    }

    function redeem(uint256, address, address) public pure override returns (uint256) {
        revert UseCooldownFunctions();
    }

    function deposit(uint256 assets, address receiver) public override nonReentrant whenNotPaused returns (uint256) {
        return super.deposit(assets, receiver);
    }

    function mint(uint256 shares, address receiver) public override nonReentrant whenNotPaused returns (uint256) {
        return super.mint(shares, receiver);
    }

    // --- ERC-4626 max* overrides ---
    //
    // The default OZ implementations return `type(uint256).max` (for deposit/mint)
    // or user-balance-derived values (for withdraw/redeem), which would mislead
    // integrators because our `deposit`/`mint` revert under pause, and our
    // `withdraw`/`redeem` always revert (unstake is async via the cooldown flow).
    // Per EIP-4626: "max* MUST return ... [a value that would] not cause a revert."

    /// @notice 0 when paused (deposits revert), else uncapped.
    function maxDeposit(address) public view override returns (uint256) {
        return paused() ? 0 : type(uint256).max;
    }

    /// @notice 0 when paused (mints revert), else uncapped.
    function maxMint(address) public view override returns (uint256) {
        return paused() ? 0 : type(uint256).max;
    }

    /// @notice Always 0 — `withdraw` always reverts. Use `cooldownAssets` + `claimUnstake`.
    function maxWithdraw(address) public pure override returns (uint256) {
        return 0;
    }

    /// @notice Always 0 — `redeem` always reverts. Use `cooldownShares` + `claimUnstake`.
    function maxRedeem(address) public pure override returns (uint256) {
        return 0;
    }

    // --- Unstake Cooldown ---

    function cooldownShares(uint256 shares) external nonReentrant whenNotPaused returns (uint256 requestId) {
        require(shares > 0, "sUSDM: zero shares");
        require(balanceOf(msg.sender) >= shares, "sUSDM: insufficient balance");
        if (address(escrow) == address(0)) revert EscrowNotSet();

        uint256 supply = totalSupply();
        uint256 currentRate = supply > 0 ? (totalAssets() * 1e18) / supply : 1e18;
        uint256 assets = convertToAssets(shares);
        require(assets > 0, "sUSDM: zero assets");

        _burn(msg.sender, shares);
        totalPendingClaims += assets;
        escrow.deposit(assets);

        requestId = nextRequestId++;
        unstakeRequests[requestId] = UnstakeRequest({
            owner: msg.sender,
            sharesAmount: shares,
            usdmAmount: assets,
            exchangeRate: currentRate,
            cooldownEnd: block.timestamp + config.unstakeCooldown()
        });
        _userUnstakeIds[msg.sender].push(requestId);
        emit UnstakeRequested(
            requestId, msg.sender, shares, assets, currentRate, block.timestamp + config.unstakeCooldown()
        );
    }

    /// @notice Unstake by exact USDM amount (ERC-4626 `withdraw` semantics:
    ///         shares rounded up in vault's favor). For "unstake all" use
    ///         `cooldownShares` to avoid 1-wei-per-request rounding drag.
    function cooldownAssets(uint256 assets) external nonReentrant whenNotPaused returns (uint256 requestId) {
        require(assets > 0, "sUSDM: zero assets");
        uint256 shares = previewWithdraw(assets);
        require(shares > 0, "sUSDM: zero shares");
        require(balanceOf(msg.sender) >= shares, "sUSDM: insufficient balance");
        if (address(escrow) == address(0)) revert EscrowNotSet();

        uint256 supply = totalSupply();
        uint256 currentRate = supply > 0 ? (totalAssets() * 1e18) / supply : 1e18;

        _burn(msg.sender, shares);
        totalPendingClaims += assets;
        escrow.deposit(assets);

        requestId = nextRequestId++;
        unstakeRequests[requestId] = UnstakeRequest({
            owner: msg.sender,
            sharesAmount: shares,
            usdmAmount: assets,
            exchangeRate: currentRate,
            cooldownEnd: block.timestamp + config.unstakeCooldown()
        });
        _userUnstakeIds[msg.sender].push(requestId);
        emit UnstakeRequested(
            requestId, msg.sender, shares, assets, currentRate, block.timestamp + config.unstakeCooldown()
        );
    }

    function claimUnstake(uint256 requestId) external nonReentrant whenNotPaused {
        UnstakeRequest memory req = unstakeRequests[requestId];
        if (req.usdmAmount == 0) revert AlreadyClaimed(requestId);
        if (msg.sender != req.owner) revert NotRequestOwner(requestId, msg.sender, req.owner);
        if (block.timestamp < req.cooldownEnd) revert CooldownNotExpired(requestId, req.cooldownEnd);

        delete unstakeRequests[requestId];
        _removeUserUnstakeId(req.owner, requestId);
        totalPendingClaims -= req.usdmAmount;
        escrow.release(msg.sender, req.usdmAmount);
        emit UnstakeClaimed(requestId, msg.sender, req.usdmAmount);
    }

    // --- Yield Injection ---

    function injectYield(uint256 usdmAmount) external onlyVault nonReentrant {
        require(usdmAmount > 0, "sUSDM: zero yield");
        require(usdmAmount <= config.maxYieldPerInjection(), "sUSDM: yield exceeds max");
        // Empty-vault yield would be captured by next depositor (L1-H1).
        require(totalSupply() > 0, "sUSDM: no stakers");

        IERC20(asset()).safeTransferFrom(msg.sender, address(this), usdmAmount);

        totalYieldInjected += usdmAmount;
        lastCumulativeYield = (totalAssets() * 1e18) / totalSupply();

        emit YieldInjected(usdmAmount, totalAssets(), totalSupply());
    }

    // --- Admin ---

    function setConfig(address _config) external onlyGovernor {
        require(_config != address(0), "sUSDM: zero config");
        config = MonetrixConfig(_config);
    }

    /// @notice One-time wiring of the physically-isolated escrow.
    ///         Grants infinite USDM allowance so `escrow.deposit()` can pull.
    function setEscrow(address _escrow) external onlyGovernor {
        require(_escrow != address(0), "sUSDM: zero escrow");
        if (address(escrow) != address(0)) revert EscrowAlreadySet();
        if (sUSDMEscrow(_escrow).sUSDM() != address(this)) revert EscrowMismatch();
        if (address(sUSDMEscrow(_escrow).usdm()) != asset()) revert EscrowMismatch();
        escrow = sUSDMEscrow(_escrow);
        IERC20(asset()).forceApprove(_escrow, type(uint256).max);
        emit EscrowSet(_escrow);
    }

    /// @notice One-time binding of the Vault address. Irreversible.
    function setVault(address _vault) external onlyGovernor {
        if (_vault == address(0)) revert ZeroVault();
        if (vault != address(0)) revert VaultAlreadySet();
        vault = _vault;
        emit VaultSet(_vault);
    }

    function pause() external onlyGuardian {
        _pause();
    }

    function unpause() external onlyGuardian {
        _unpause();
    }

    function _update(address from, address to, uint256 value) internal override whenNotPaused {
        super._update(from, to, value);
    }

    // --- User Unstake Query ---

    struct UnstakeRequestDetail {
        uint256 requestId;
        uint256 sharesAmount;
        uint256 usdmAmount;
        uint256 exchangeRate;
        uint256 cooldownEnd;
    }

    function getUserUnstakeIds(address user) external view returns (uint256[] memory) {
        return _userUnstakeIds[user];
    }

    function getUserUnstakeRequests(address user) external view returns (UnstakeRequestDetail[] memory) {
        uint256[] memory ids = _userUnstakeIds[user];
        UnstakeRequestDetail[] memory details = new UnstakeRequestDetail[](ids.length);
        for (uint256 i = 0; i < ids.length; i++) {
            UnstakeRequest memory req = unstakeRequests[ids[i]];
            details[i] = UnstakeRequestDetail({
                requestId: ids[i],
                sharesAmount: req.sharesAmount,
                usdmAmount: req.usdmAmount,
                exchangeRate: req.exchangeRate,
                cooldownEnd: req.cooldownEnd
            });
        }
        return details;
    }

    function _removeUserUnstakeId(address user, uint256 requestId) private {
        uint256[] storage ids = _userUnstakeIds[user];
        uint256 len = ids.length;
        for (uint256 i = 0; i < len; i++) {
            if (ids[i] == requestId) {
                ids[i] = ids[len - 1];
                ids.pop();
                return;
            }
        }
    }

    uint256[45] private __gap;
}
