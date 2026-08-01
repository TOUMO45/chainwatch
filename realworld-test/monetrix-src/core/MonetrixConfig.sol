// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.27;

import {MonetrixGovernedUpgradeable} from "../governance/MonetrixGovernedUpgradeable.sol";

/// @title MonetrixConfig - Centralized protocol parameter registry
/// @notice Holds operational parameters: yield split ratios, deposit/TVL
///         limits, cooldowns, and the recipient addresses (insurance fund,
///         foundation) that the yield split targets.
/// @dev All parameter mutations are gated by the 24h timelock via
///      `onlyGovernor`. Upgrades are gated by the 48h timelock via the
///      inherited `_authorizeUpgrade` hook.
contract MonetrixConfig is MonetrixGovernedUpgradeable {
    uint256 public userYieldBps;
    uint256 public insuranceYieldBps;
    uint256 public minDepositAmount;
    uint256 public maxDepositAmount;
    uint256 public maxTVL;
    uint256 public bridgeInterval;
    address public insuranceFund;
    address public foundation;
    uint256 public redeemCooldown;
    uint256 public unstakeCooldown;

    // ─── Tradeable asset whitelist ──────────────────────────
    /// @dev HL has three independent index spaces. This struct binds them into one tuple:
    ///        - `perpIndex`       — HL perp identifier (oracle key, info key, limit-order asset for perp leg)
    ///        - `spotIndex`       — HL token index (0x801/0x811 balance key, action-15 BLP token)
    ///        - `spotPairAssetId` — HL limit-order asset for the spot leg (= 10000 + HL spot pair_index)
    ///      `spotIndex` and `spotPairAssetId` are NOT the same number — one token can back many
    ///      pairs, so the pair must be chosen explicitly per whitelisted asset.
    struct TradeableAsset {
        uint32 perpIndex;
        uint32 spotIndex;
        uint32 spotPairAssetId;
    }

    TradeableAsset[] public tradeableAssets;
    mapping(uint32 => uint32) public perpToSpot;
    mapping(uint32 => uint32) public spotToPerp;
    mapping(uint32 => uint32) public perpToSpotPairAssetId;
    mapping(uint32 => bool) public isPerpWhitelisted;
    mapping(uint32 => bool) public isSpotWhitelisted;           // keyed by HL token_index
    mapping(uint32 => bool) public isSpotPairAssetIdWhitelisted; // keyed by HL pair_asset_id (= 10000 + pair_index)

    /// @notice Per-injection cap on sUSDM.injectYield. Governor-tunable defense-in-depth
    ///         against off-chain yield input errors (yield is derived on-chain from
    ///         backing − supply, but the cap bounds a single injection amount).
    uint256 public maxYieldPerInjection;

    /// @notice Annualized cap (bps of USDM supply) for a single settle proposal.
    ///         Enforced by Accountant: `proposedYield ≤ supply × bps × Δt / (10000 × 1y)`.
    /// @dev Hard upper-bound at `MAX_ANNUAL_YIELD_BPS_CAP` (currently 15% APR).
    uint256 public maxAnnualYieldBps;

    uint256 public constant MAX_ANNUAL_YIELD_BPS_CAP = 1500;

    event YieldBpsUpdated(uint256 userBps, uint256 insuranceBps, uint256 foundationBps);
    event DepositLimitsUpdated(uint256 minAmount, uint256 maxAmount);
    event MaxTVLUpdated(uint256 newCap);
    event BridgeIntervalUpdated(uint256 interval);
    event CooldownsUpdated(uint256 redeemCooldown, uint256 unstakeCooldown);
    event AddressUpdated(string name, address addr);
    event TradeableAssetsUpdated(uint256 count);
    event MaxYieldPerInjectionUpdated(uint256 amount);
    event MaxAnnualYieldBpsUpdated(uint256 bps);

    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        _disableInitializers();
    }

    function initialize(address _insuranceFund, address _foundation, address _acl) external initializer {
        require(_insuranceFund != address(0), "Config: zero insuranceFund");
        require(_foundation != address(0), "Config: zero foundation");
        __Governed_init(_acl);
        insuranceFund = _insuranceFund;
        foundation = _foundation;
        userYieldBps = 7000;
        insuranceYieldBps = 1000;
        minDepositAmount = 100e6;
        maxDepositAmount = 1_000_000e6;
        maxTVL = 10_000_000e6;
        bridgeInterval = 6 hours;
        redeemCooldown = 3 days;
        unstakeCooldown = 3 days;
        maxYieldPerInjection = 1_000_000e6;
        maxAnnualYieldBps = 1200;
    }

    /// @notice Foundation share = 10000 - userYieldBps - insuranceYieldBps.
    function foundationYieldBps() external view returns (uint256) {
        return 10000 - userYieldBps - insuranceYieldBps;
    }

    function setYieldBps(uint256 _userBps, uint256 _insuranceBps) external onlyGovernor {
        require(_userBps + _insuranceBps <= 10000, "Config: bps exceed 10000");
        userYieldBps = _userBps;
        insuranceYieldBps = _insuranceBps;
        emit YieldBpsUpdated(_userBps, _insuranceBps, 10000 - _userBps - _insuranceBps);
    }

    function setDepositLimits(uint256 _min, uint256 _max) external onlyGovernor {
        require(_min > 0, "Config: zero min");
        require(_min < _max, "Config: min >= max");
        minDepositAmount = _min;
        maxDepositAmount = _max;
        emit DepositLimitsUpdated(_min, _max);
    }

    function setMaxTVL(uint256 _maxTVL) external onlyGovernor {
        maxTVL = _maxTVL;
        emit MaxTVLUpdated(_maxTVL);
    }

    function setBridgeInterval(uint256 _interval) external onlyGovernor {
        require(_interval > 0, "Config: zero interval");
        require(_interval <= 1 days, "Config: interval too long");
        bridgeInterval = _interval;
        emit BridgeIntervalUpdated(_interval);
    }

    function setCooldowns(uint256 _redeemCooldown, uint256 _unstakeCooldown) external onlyGovernor {
        require(_redeemCooldown >= 1 minutes, "Config: redeem cooldown too short");
        require(_unstakeCooldown >= 1 minutes, "Config: unstake cooldown too short");
        require(_redeemCooldown <= 30 days, "Config: redeem cooldown too long");
        require(_unstakeCooldown <= 30 days, "Config: unstake cooldown too long");
        redeemCooldown = _redeemCooldown;
        unstakeCooldown = _unstakeCooldown;
        emit CooldownsUpdated(_redeemCooldown, _unstakeCooldown);
    }

    function setInsuranceFund(address _addr) external onlyGovernor {
        require(_addr != address(0), "Config: zero address");
        insuranceFund = _addr;
        emit AddressUpdated("insuranceFund", _addr);
    }

    function setFoundation(address _addr) external onlyGovernor {
        require(_addr != address(0), "Config: zero address");
        foundation = _addr;
        emit AddressUpdated("foundation", _addr);
    }

    function setMaxYieldPerInjection(uint256 _amount) external onlyGovernor {
        require(_amount > 0, "Config: zero max");
        maxYieldPerInjection = _amount;
        emit MaxYieldPerInjectionUpdated(_amount);
    }

    function setMaxAnnualYieldBps(uint256 _bps) external onlyGovernor {
        require(_bps > 0, "Config: zero bps");
        require(_bps <= MAX_ANNUAL_YIELD_BPS_CAP, "Config: exceeds hard cap");
        maxAnnualYieldBps = _bps;
        emit MaxAnnualYieldBpsUpdated(_bps);
    }

    // ─── Tradeable asset whitelist management ──────────────

    function addTradeableAsset(TradeableAsset calldata asset) external onlyGovernor {
        _addAsset(asset);
        emit TradeableAssetsUpdated(tradeableAssets.length);
    }

    function addTradeableAssets(TradeableAsset[] calldata assets) external onlyGovernor {
        for (uint256 i = 0; i < assets.length; i++) {
            _addAsset(assets[i]);
        }
        emit TradeableAssetsUpdated(tradeableAssets.length);
    }

    function _addAsset(TradeableAsset calldata asset) internal {
        // spotIndex 0 = USDC (base currency, never a hedge). perpIndex 0 allowed (BTC-PERP).
        require(asset.spotIndex != 0, "Config: zero spotIndex");
        require(asset.spotPairAssetId >= 10000, "Config: pair asset_id must be >= 10000");
        require(!isPerpWhitelisted[asset.perpIndex], "Config: perp already listed");
        require(!isSpotWhitelisted[asset.spotIndex], "Config: spot already listed");
        require(!isSpotPairAssetIdWhitelisted[asset.spotPairAssetId], "Config: pair already listed");
        tradeableAssets.push(asset);
        perpToSpot[asset.perpIndex] = asset.spotIndex;
        spotToPerp[asset.spotIndex] = asset.perpIndex;
        perpToSpotPairAssetId[asset.perpIndex] = asset.spotPairAssetId;
        isPerpWhitelisted[asset.perpIndex] = true;
        isSpotWhitelisted[asset.spotIndex] = true;
        isSpotPairAssetIdWhitelisted[asset.spotPairAssetId] = true;
    }

    function removeTradeableAsset(uint32 perpIndex) external onlyGovernor {
        require(isPerpWhitelisted[perpIndex], "Config: perp not listed");
        uint32 spotIdx = perpToSpot[perpIndex];
        uint32 pairAssetId = perpToSpotPairAssetId[perpIndex];

        // Swap-and-pop from the array
        uint256 len = tradeableAssets.length;
        for (uint256 i = 0; i < len; i++) {
            if (tradeableAssets[i].perpIndex == perpIndex) {
                tradeableAssets[i] = tradeableAssets[len - 1];
                tradeableAssets.pop();
                break;
            }
        }

        delete perpToSpot[perpIndex];
        delete spotToPerp[spotIdx];
        delete perpToSpotPairAssetId[perpIndex];
        delete isPerpWhitelisted[perpIndex];
        delete isSpotWhitelisted[spotIdx];
        delete isSpotPairAssetIdWhitelisted[pairAssetId];
        emit TradeableAssetsUpdated(tradeableAssets.length);
    }

    function tradeableAssetsLength() external view returns (uint256) {
        return tradeableAssets.length;
    }

    /// @dev Reduced from 50 → 49 (V2 `maxYieldPerInjection`) → 48 (V3 `maxAnnualYieldBps`)
    ///      → 46 (V4 `perpToSpotPairAssetId` + `isSpotPairAssetIdWhitelisted`).
    uint256[46] private __gap;
}
