// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.27;

import "@openzeppelin/contracts-upgradeable/utils/PausableUpgradeable.sol";
import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import "@openzeppelin/contracts/utils/math/SafeCast.sol";
import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import "../tokens/USDM.sol";
import "../tokens/sUSDM.sol";
import "./MonetrixConfig.sol";
import "./InsuranceFund.sol";
import "../interfaces/IHyperCore.sol";
import "../interfaces/HyperCoreConstants.sol";
import "../interfaces/IMonetrixAccountant.sol";
import "../interfaces/IRedeemEscrow.sol";
import "../interfaces/IYieldEscrow.sol";
import "./ActionEncoder.sol";
import "./PrecompileReader.sol";
import "./TokenMath.sol";
import "./MonetrixAccountant.sol";
import {MonetrixGovernedUpgradeable} from "../governance/MonetrixGovernedUpgradeable.sol";

/// @title MonetrixVault - Core vault managing USDC deposits, USDM minting, redemption queue, and L1 hedge execution
/// @dev Role mapping (via shared MonetrixAccessController):
///      - GUARDIAN: pause / unpause / pauseOperator / unpauseOperator (delay=0)
///      - OPERATOR: bridge / hedge / HLP / yield-distribution (delay=0)
///      - GOVERNOR: set* / emergency* (24h timelock)
///      - UPGRADER: _authorizeUpgrade (48h timelock, inherited from base)
/// @dev Two-dimensional pause:
///      - `paused` (OZ Pausable): user fund I/O — deposit, redeem claim, outflow paths.
///      - `operatorPaused` (custom):    all operator-driven mutations (hedge/HLP/BLP/bridges/yield).
///      Outflow functions (`keeperBridge`, `settle`, `distributeYield`) are gated by BOTH.
contract MonetrixVault is PausableUpgradeable, ReentrancyGuard, MonetrixGovernedUpgradeable {
    using SafeERC20 for IERC20;

    enum BridgeTarget { Vault, Multisig }

    // ═══════════════════════════════════════════════════════════
    //                      STATE
    // ═══════════════════════════════════════════════════════════

    // ─── Core references ────────────────────────────────────
    IERC20 public usdc;
    USDM public usdm;
    sUSDM public susdm;
    MonetrixConfig public config;
    address public coreDepositWallet;
    address public accountant;
    address public multisigVault;
    address public redeemEscrow;
    address public yieldEscrow;

    // ─── Operational state ──────────────────────────────────
    bool public hlpDepositEnabled;
    bool public multisigVaultEnabled;
    uint256 public lastBridgeTimestamp;

    // ─── L1 principal tracking ───────────────────────────────
    uint256 public outstandingL1Principal;
    uint256 public bridgeRetentionAmount;

    // ─── Redeem queue ───────────────────────────────────────
    /// @dev 2-slot layout without exotic bit widths. `owner` (160 bits) +
    ///      `cooldownEnd` (64 bits) packs into slot 0 (224/256 used); amount
    ///      takes the full uint256 slot 1 — same storage cost as the former
    ///      uint152/uint104 packing, but no truncation risk on usdmAmount.
    struct RedeemRequest {
        address owner;        // slot 0 ┐
        uint64  cooldownEnd;  // slot 0 ┘
        uint256 usdmAmount;   // slot 1
    }

    uint256 public nextRedeemId;
    mapping(uint256 => RedeemRequest) public redeemRequests;
    mapping(address => uint256[]) private _userRedeemIds;

    /// @notice PM activation flag for Vault's L1 account; when true, `_sendL1Bridge` counts 0x811 supplied.
    bool public pmEnabled;

    /// @notice Operator-side pause (independent of `paused`). When true, blocks every operator-driven
    ///         mutation (hedge/HLP/BLP/bridges/yield/escrow routing). User-facing functions keep
    ///         their own `whenNotPaused` gate and are unaffected.
    bool public operatorPaused;

    uint256[50] private __gap;

    // ─── Events ─────────────────────────────────────────────
    event Deposited(address indexed user, uint256 amount);
    event RedeemRequested(uint256 indexed requestId, address indexed owner, uint256 usdmAmount, uint256 cooldownEnd);
    event RedeemClaimed(uint256 indexed requestId, address indexed owner, uint256 usdmAmount);
    event BridgedToL1(uint256 amount);
    event PrincipalBridgedFromL1(uint256 amount);
    event YieldBridgedFromL1(uint256 amount);
    event YieldCollected(uint256 amount);
    event YieldDistributed(uint256 totalYield, uint256 userShare, uint256 insuranceShare, uint256 foundationShare);
    event HedgeExecuted(uint256 indexed batchId, uint32 spotAsset, uint32 perpAsset, uint64 size);
    event HedgeClosed(uint256 indexed positionId, uint32 spotAsset, uint64 size);
    event HedgeRepaired(uint256 indexed positionId, uint16 residualBps);
    event HlpDeposited(uint64 usdAmount);
    event HlpWithdrawn(uint64 usdAmount);
    event HlpDepositEnabledUpdated(bool enabled);
    event RedemptionsFunded(uint256 amount);
    event RedeemEscrowReclaimed(uint256 amount);
    event EmergencyActionSent(address indexed sender, bytes32 dataHash);
    event AccountantUpdated(address newAccountant);
    event MultisigVaultUpdated(address newMultisigVault);
    event RedeemEscrowUpdated(address redeemEscrow);
    event YieldEscrowUpdated(address yieldEscrow);
    event BridgeRetentionAmountUpdated(uint256 amount);
    event PmEnabledUpdated(bool enabled);
    event BlpSupplied(uint64 indexed token, uint64 l1Amount);
    event BlpWithdrawn(uint64 indexed token, uint64 l1Amount);
    event OperatorPaused(address indexed by);
    event OperatorUnpaused(address indexed by);



    // ═══════════════════════════════════════════════════════════
    //                    INITIALIZER
    // ═══════════════════════════════════════════════════════════

    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        _disableInitializers();
    }

    function initialize(
        address _usdc,
        address _usdm,
        address _susdm,
        address _config,
        address _coreDepositWallet,
        address _acl
    ) external initializer {
        require(_usdc != address(0) && _usdm != address(0) && _susdm != address(0), "zero token");
        require(_config != address(0) && _coreDepositWallet != address(0), "zero dep");

        __Pausable_init();
        __Governed_init(_acl);

        usdc = IERC20(_usdc);
        usdm = USDM(_usdm);
        susdm = sUSDM(_susdm);
        config = MonetrixConfig(_config);
        coreDepositWallet = _coreDepositWallet;
        hlpDepositEnabled = true;
    }

    
    // ═══════════════════════════════════════════════════════════
    //                      MODIFIER
    // ═══════════════════════════════════════════════════════════

    modifier requireWired() {
        require(accountant != address(0) && redeemEscrow != address(0) && yieldEscrow != address(0), "not wired");
        _;
    }

    modifier whenOperatorNotPaused() {
        require(!operatorPaused, "operator paused");
        _;
    }

    // ═══════════════════════════════════════════════════════════
    //                   USER OPERATIONS
    // ═══════════════════════════════════════════════════════════

    function deposit(uint256 amount) external nonReentrant whenNotPaused {
        require(
            amount >= config.minDepositAmount() && amount <= config.maxDepositAmount(),
            "deposit out of range"
        );
        uint256 maxTVL = config.maxTVL();
        if (maxTVL > 0) {
            require(usdm.totalSupply() + amount <= maxTVL, "TVL cap exceeded");
        }
        usdc.safeTransferFrom(msg.sender, address(this), amount);
        usdm.mint(msg.sender, amount);
        emit Deposited(msg.sender, amount);
    }

    function requestRedeem(uint256 usdmAmount) external nonReentrant whenNotPaused requireWired returns (uint256 requestId) {
        require(usdmAmount > 0, "zero amount");
        IERC20(address(usdm)).safeTransferFrom(msg.sender, address(this), usdmAmount);
        IRedeemEscrow(redeemEscrow).addObligation(usdmAmount);

        requestId = nextRedeemId++;
        redeemRequests[requestId] = RedeemRequest({
            owner: msg.sender,
            cooldownEnd: SafeCast.toUint64(block.timestamp + config.redeemCooldown()),
            usdmAmount: usdmAmount
        });
        _userRedeemIds[msg.sender].push(requestId);
        emit RedeemRequested(requestId, msg.sender, usdmAmount, block.timestamp + config.redeemCooldown());
    }

    function claimRedeem(uint256 requestId) external nonReentrant whenNotPaused requireWired {
        RedeemRequest memory req = redeemRequests[requestId];
        require(
            req.usdmAmount > 0
                && msg.sender == req.owner
                && block.timestamp >= req.cooldownEnd,
            "invalid claim"
        );
        uint256 amount = req.usdmAmount;
        delete redeemRequests[requestId];
        _removeUserRedeemId(req.owner, requestId);

        usdm.burn(amount);
        IRedeemEscrow(redeemEscrow).payOut(msg.sender, amount);
        emit RedeemClaimed(requestId, msg.sender, amount);
    }

    // ═══════════════════════════════════════════════════════════
    //                 OPERATOR OPERATIONS
    // ═══════════════════════════════════════════════════════════

    // ─── Bridge (EVM ↔ L1) ──────────────────────────────────
    // NOTE: Once the vault contract account supports Portfolio Margin,
    // all positions will be held by the vault directly and multisigVault
    // will be disabled.
    function keeperBridge(BridgeTarget target) external onlyOperator requireWired whenNotPaused whenOperatorNotPaused {
        require(block.timestamp >= lastBridgeTimestamp + config.bridgeInterval(), "too early");
        uint256 amount = netBridgeable();
        require(amount > 0, "nothing to bridge");
        address recipient = (target == BridgeTarget.Multisig && multisigVaultEnabled && multisigVault != address(0))
            ? multisigVault
            : address(this);
        outstandingL1Principal += amount;
        lastBridgeTimestamp = block.timestamp;
        usdc.forceApprove(coreDepositWallet, amount);
        ICoreDepositWallet(coreDepositWallet).depositFor(recipient, amount, HyperCoreConstants.SPOT_DEX);
        emit BridgedToL1(amount);
    }

    function bridgePrincipalFromL1(uint256 amount) external onlyOperator requireWired whenOperatorNotPaused {
        require(
            amount > 0 && amount <= redemptionShortfall() && amount <= outstandingL1Principal,
            "invalid bridge amount"
        );
        outstandingL1Principal -= amount;
        _sendL1Bridge(amount);
        emit PrincipalBridgedFromL1(amount);
    }

    function bridgeYieldFromL1(uint256 amount) external onlyOperator requireWired whenOperatorNotPaused {
        require(amount > 0, "zero amount");
        require(amount <= yieldShortfall(), "yield shortfall");
        _sendL1Bridge(amount);
        emit YieldBridgedFromL1(amount);
    }

    // ─── Hedge execution ────────────────────────────────────

    function executeHedge(uint256 batchId, ActionEncoder.HedgeParams calldata params)
        external
        onlyOperator
        whenOperatorNotPaused
    {
        require(params.size > 0, "zero size");
        _requireHedgePair(params.perpAsset, params.spotAsset);

        ActionEncoder.sendBuySpot(params);
        ActionEncoder.sendShortPerp(params);

        // Under PM, Vault's new spot balance auto-supplies into 0x811 → register
        // so Accountant's strict supplied reads don't revert. Notify with HL token_index
        // (from Config), NOT `params.spotAsset` (which is pair_asset_id).
        if (pmEnabled && accountant != address(0)) {
            uint64 spotToken = uint64(config.perpToSpot(params.perpAsset));
            MonetrixAccountant(accountant).notifyVaultSupply(spotToken, params.perpAsset);
        }

        emit HedgeExecuted(batchId, params.spotAsset, params.perpAsset, params.size);
    }

    function closeHedge(ActionEncoder.CloseParams calldata params) external onlyOperator whenOperatorNotPaused {
        _requireHedgePair(params.perpAsset, params.spotAsset);

        ActionEncoder.sendSellSpot(params);
        ActionEncoder.sendClosePerp(params);

        emit HedgeClosed(params.positionId, params.spotAsset, params.size);
    }

    function repairHedge(uint256 positionId, ActionEncoder.RepairParams calldata params)
        external
        onlyOperator
        whenOperatorNotPaused
    {
        _requireRepairAsset(params.asset, params.isPerp);

        ActionEncoder.sendRepairAction(params);

        emit HedgeRepaired(positionId, params.residualBps);
    }

    // ─── HLP strategy ───────────────────────────────────────

    function depositToHLP(uint64 usdAmount) external onlyOperator whenOperatorNotPaused {
        require(usdAmount > 0, "zero amount");
        require(hlpDepositEnabled, "HLP deposit frozen");

        ActionEncoder.sendVaultDeposit(HyperCoreConstants.HLP_VAULT, usdAmount);
        emit HlpDeposited(usdAmount);
    }

    function setHlpDepositEnabled(bool enabled) external onlyOperator whenOperatorNotPaused {
        hlpDepositEnabled = enabled;
        emit HlpDepositEnabledUpdated(enabled);
    }

    function withdrawFromHLP(uint64 usdAmount) external onlyOperator whenOperatorNotPaused {
        require(usdAmount > 0, "zero amount");

        PrecompileReader.VaultEquity memory eq =
            PrecompileReader.vaultEquity(address(this), HyperCoreConstants.HLP_VAULT);
        require(uint256(usdAmount) <= uint256(eq.equity), "exceeds hlp equity");
        // `lockedUntil` is ms-epoch; L1 silently drops withdraws during lock.
        require(
            block.timestamp * 1000 >= uint256(eq.lockedUntil),
            "HLP still locked"
        );

        ActionEncoder.sendVaultWithdraw(HyperCoreConstants.HLP_VAULT, usdAmount);
        emit HlpWithdrawn(usdAmount);
    }

    // ─── BLP (Borrow/Lend Pool) ─────────────────────────────

    /// @notice Supply `l1Amount` of `token` into HL's BLP (action 15 op=0). L1 8-dp wei.
    function supplyToBlp(uint64 token, uint64 l1Amount) external onlyOperator whenOperatorNotPaused {
        require(l1Amount > 0, "zero amount");
        ActionEncoder.sendSupply(token, l1Amount);
        if (accountant != address(0)) {
            uint32 perpIndex = 0;
            if (token != uint64(HyperCoreConstants.USDC_TOKEN_INDEX)) {
                // Whitelist map is authoritative — BTC-PERP is index 0.
                require(config.isSpotWhitelisted(uint32(token)), "spot not whitelisted");
                perpIndex = config.spotToPerp(uint32(token));
            }
            MonetrixAccountant(accountant).notifyVaultSupply(token, perpIndex);
        }
        emit BlpSupplied(token, l1Amount);
    }

    /// @notice Withdraw from BLP back to spot (action 15 op=1). `l1Amount=0` means max.
    function withdrawFromBlp(uint64 token, uint64 l1Amount) external onlyOperator whenOperatorNotPaused {
        ActionEncoder.sendWithdrawSupply(token, l1Amount);
        emit BlpWithdrawn(token, l1Amount);
    }

    // ─── Settlement + Yield ─────────────────────────────────

    /// @notice Atomic all-or-nothing settle. Keeper submits `proposedYield`
    ///         (phantom-excluded off-chain); Accountant enforces 4 gates
    ///         (initialized / interval / distributable / annualized) and Vault
    ///         enforces EVM USDC sufficiency. On success the full
    ///         `proposedYield` moves to YieldEscrow; otherwise tx reverts.
    /// @dev Only `shortfall` is reserved here. `bridgeRetentionAmount` is a
    ///      bridge-to-L1 working balance (see `netBridgeable`); it is NOT a
    ///      solvency invariant and must not block yield routing.
    function settle(uint256 proposedYield) external onlyOperator requireWired nonReentrant whenNotPaused whenOperatorNotPaused {
        require(proposedYield > 0, "zero yield");

        uint256 vaultBal = usdc.balanceOf(address(this));
        uint256 shortfall_ = IRedeemEscrow(redeemEscrow).shortfall();
        uint256 available = vaultBal > shortfall_ ? vaultBal - shortfall_ : 0;
        require(available >= proposedYield, "insufficient EVM USDC");

        IMonetrixAccountant(accountant).settleDailyPnL(proposedYield);
        usdc.safeTransfer(yieldEscrow, proposedYield);
        emit YieldCollected(proposedYield);
    }

    function distributeYield() external nonReentrant onlyOperator requireWired whenNotPaused whenOperatorNotPaused {
        uint256 totalYield = IYieldEscrow(yieldEscrow).balance();
        require(totalYield > 0, "no yield");

        uint256 balBefore = usdc.balanceOf(address(this));
        IYieldEscrow(yieldEscrow).pullForDistribution(totalYield);
        require(usdc.balanceOf(address(this)) >= balBefore + totalYield, "pull");

        uint256 userShare = (totalYield * config.userYieldBps()) / 10000;
        uint256 insuranceShare = (totalYield * config.insuranceYieldBps()) / 10000;

        // Empty-vault yield would be captured by next depositor (L1-H1); reroute to foundation.
        if (userShare > 0 && susdm.totalSupply() == 0) {
            userShare = 0;
        }

        uint256 foundationShare = totalYield - userShare - insuranceShare;

        if (userShare > 0) {
            usdm.mint(address(this), userShare);
            IERC20(address(usdm)).forceApprove(address(susdm), userShare);
            susdm.injectYield(userShare);
        }

        if (insuranceShare > 0) {
            address insuranceFundAddr = config.insuranceFund();
            require(insuranceFundAddr != address(0), "zero if");
            InsuranceFund _insuranceFund = InsuranceFund(insuranceFundAddr);
            usdc.forceApprove(address(_insuranceFund), insuranceShare);
            _insuranceFund.deposit(insuranceShare);
        }
        if (foundationShare > 0) {
            address foundationAddr = config.foundation();
            require(foundationAddr != address(0), "zero fdn");
            usdc.safeTransfer(foundationAddr, foundationShare);
        }

        emit YieldDistributed(totalYield, userShare, insuranceShare, foundationShare);
    }

    // ─── Fund routing (Vault ↔ RedeemEscrow) ────────────────

    function fundRedemptions(uint256 amount) external onlyOperator requireWired whenOperatorNotPaused {
        uint256 sf = IRedeemEscrow(redeemEscrow).shortfall();
        if (sf == 0) return;
        uint256 toFund = amount == 0 ? sf : amount;
        require(toFund <= sf, "exceeds shortfall");
        uint256 vaultBal = usdc.balanceOf(address(this));
        uint256 toTransfer = toFund < vaultBal ? toFund : vaultBal;
        require(toTransfer > 0, "nothing to fund");
        usdc.safeTransfer(redeemEscrow, toTransfer);
        emit RedemptionsFunded(toTransfer);
    }

    function reclaimFromRedeemEscrow(uint256 amount) external onlyOperator requireWired whenOperatorNotPaused {
        require(amount > 0, "zero amount");
        IRedeemEscrow(redeemEscrow).reclaimTo(address(this), amount);
        emit RedeemEscrowReclaimed(amount);
    }

    // ═══════════════════════════════════════════════════════════
    //                  GUARDIAN OPERATIONS
    // ═══════════════════════════════════════════════════════════

    function pause() external onlyGuardian {
        _pause();
    }

    function unpause() external onlyGuardian {
        _unpause();
    }

    /// @notice Halt every operator-driven mutation (hedge/HLP/BLP/bridges/yield/escrow).
    ///         User fund I/O stays on the independent `paused` flag.
    function pauseOperator() external onlyGuardian {
        operatorPaused = true;
        emit OperatorPaused(msg.sender);
    }

    function unpauseOperator() external onlyGuardian {
        operatorPaused = false;
        emit OperatorUnpaused(msg.sender);
    }

    // ═══════════════════════════════════════════════════════════
    //                  GOVERNOR OPERATIONS
    // ═══════════════════════════════════════════════════════════

    /// @dev Emergency escape hatches DO NOT check either pause flag. They exist precisely
    ///      to recover from states where the operator pipeline is suspect / halted —
    ///      gating them by pause would defeat their purpose. Governor 24h timelock is
    ///      the guard.
    function emergencyRawAction(bytes calldata data) external onlyGovernor {
        ICoreWriter(HyperCoreConstants.CORE_WRITER).sendRawAction(data);
        emit EmergencyActionSent(msg.sender, keccak256(data));
    }

    function emergencyBridgePrincipalFromL1(uint256 amount) external onlyGovernor {
        require(amount > 0 && amount <= outstandingL1Principal, "invalid bridge amount");
        outstandingL1Principal -= amount;
        _sendL1Bridge(amount);
        emit PrincipalBridgedFromL1(amount);
    }

    function setAccountant(address _accountant) external onlyGovernor {
        require(_accountant != address(0), "zero acc");
        accountant = _accountant;
        emit AccountantUpdated(_accountant);
    }

    function setMultisigVault(address _multisig) external onlyGovernor {
        if (_multisig == address(0)) {
            require(!multisigVaultEnabled, "multi on");
        }
        multisigVault = _multisig;
        emit MultisigVaultUpdated(_multisig);
    }

    function setMultisigVaultEnabled(bool _enabled) external onlyGovernor {
        if (_enabled) {
            require(multisigVault != address(0), "no multi");
        }
        multisigVaultEnabled = _enabled;
    }

    function setRedeemEscrow(address _escrow) external onlyGovernor {
        require(_escrow != address(0), "zero address");
        redeemEscrow = _escrow;
        emit RedeemEscrowUpdated(_escrow);
    }

    function setYieldEscrow(address _escrow) external onlyGovernor {
        require(_escrow != address(0), "zero address");
        yieldEscrow = _escrow;
        emit YieldEscrowUpdated(_escrow);
    }

    function setBridgeRetentionAmount(uint256 amount) external onlyGovernor {
        bridgeRetentionAmount = amount;
        emit BridgeRetentionAmountUpdated(amount);
    }

    /// @notice Flip after PM is activated on Vault's L1 account; gates the 0x811 read in `_sendL1Bridge`.
    function setPmEnabled(bool enabled) external onlyGovernor {
        pmEnabled = enabled;
        emit PmEnabledUpdated(enabled);
    }

    // ═══════════════════════════════════════════════════════════
    //                      INTERNAL
    // ═══════════════════════════════════════════════════════════

    /// @dev Checks L1 USDC (spot + supplied when PM on) covers `amount` before SEND_ASSET; avoids silent L1 drop when hedge is still locked.
    function _sendL1Bridge(uint256 amount) internal {
        uint64 usdcToken = uint64(HyperCoreConstants.USDC_TOKEN_INDEX);
        uint256 l1Available = uint256(PrecompileReader.spotBalance(address(this), usdcToken).total);
        if (pmEnabled) {
            l1Available += uint256(PrecompileReader.suppliedBalance(address(this), usdcToken));
        }
        require(
            l1Available >= TokenMath.usdcEvmToL1Wei(amount),
            "L1 USDC insufficient (unwind hedge or wait for settlement)"
        );
        ActionEncoder.sendBridgeToL1(amount);
    }

    /// @dev `spotAsset` is the HL limit-order asset for the spot leg (= 10000 + pair_index),
    ///      NOT the token_index. See `MonetrixConfig.TradeableAsset` for the distinction.
    function _requireHedgePair(uint32 perpAsset, uint32 spotAsset) internal view {
        require(config.isPerpWhitelisted(perpAsset), "perp not whitelisted");
        require(config.perpToSpotPairAssetId(perpAsset) == spotAsset, "spot/perp mismatch");
    }

    /// @dev For `isPerp=false`, `asset` is the HL pair_asset_id (= 10000 + pair_index).
    function _requireRepairAsset(uint32 asset, bool isPerp) internal view {
        if (isPerp) {
            require(config.isPerpWhitelisted(asset), "perp not whitelisted");
        } else {
            require(config.isSpotPairAssetIdWhitelisted(asset), "spot pair not wl");
        }
    }

    function _removeUserRedeemId(address user, uint256 requestId) private {
        uint256[] storage ids = _userRedeemIds[user];
        uint256 len = ids.length;
        for (uint256 i = 0; i < len; i++) {
            if (ids[i] == requestId) {
                ids[i] = ids[len - 1];
                ids.pop();
                return;
            }
        }
    }

    // ═══════════════════════════════════════════════════════════
    //                       VIEW
    // ═══════════════════════════════════════════════════════════

    function netBridgeable() public view returns (uint256) {
        uint256 bal = usdc.balanceOf(address(this));
        uint256 sf = IRedeemEscrow(redeemEscrow).shortfall();
        uint256 reserved = sf + bridgeRetentionAmount;
        return bal > reserved ? bal - reserved : 0;
    }

    function redemptionShortfall() public view returns (uint256) {
        if (redeemEscrow == address(0)) return 0;
        return IRedeemEscrow(redeemEscrow).shortfall();
    }

    function yieldShortfall() public view returns (uint256) {
        if (accountant == address(0)) return 0;
        int256 s = IMonetrixAccountant(accountant).surplus();
        if (s <= 0) return 0;
        uint256 yield = uint256(s);
        uint256 vaultBal = usdc.balanceOf(address(this));
        uint256 res = IRedeemEscrow(redeemEscrow).shortfall() + bridgeRetentionAmount;
        uint256 available = vaultBal > res ? vaultBal - res : 0;
        return yield > available ? yield - available : 0;
    }



    function canKeeperBridge() external view returns (bool) {
        if (redeemEscrow == address(0)) return false;
        return block.timestamp >= lastBridgeTimestamp + config.bridgeInterval()
            && netBridgeable() > 0;
    }

    struct RedeemRequestDetail {
        uint256 requestId;
        uint256 usdmAmount;
        uint256 cooldownEnd;
    }

    function getUserRedeemIds(address user) external view returns (uint256[] memory) {
        return _userRedeemIds[user];
    }

    function getUserRedeemRequests(address user) external view returns (RedeemRequestDetail[] memory) {
        uint256[] memory ids = _userRedeemIds[user];
        RedeemRequestDetail[] memory details = new RedeemRequestDetail[](ids.length);
        for (uint256 i = 0; i < ids.length; i++) {
            RedeemRequest memory req = redeemRequests[ids[i]];
            details[i] =
                RedeemRequestDetail({requestId: ids[i], usdmAmount: req.usdmAmount, cooldownEnd: req.cooldownEnd});
        }
        return details;
    }

}
