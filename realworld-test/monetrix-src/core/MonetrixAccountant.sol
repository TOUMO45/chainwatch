// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.27;

import "@openzeppelin/contracts/token/ERC20/IERC20.sol";

import "../tokens/USDM.sol";
import "../interfaces/HyperCoreConstants.sol";
import "../interfaces/IMonetrixAccountant.sol";
import "../interfaces/IRedeemEscrow.sol";
import "./PrecompileReader.sol";
import {MonetrixGovernedUpgradeable} from "../governance/MonetrixGovernedUpgradeable.sol";

/// @notice Minimal reader interfaces to avoid circular imports.
interface IMonetrixVaultReader {
    function multisigVault() external view returns (address);
    function redeemEscrow() external view returns (address);
}

interface IMonetrixConfigReader {
    function tradeableAssets(uint256 index)
        external view returns (uint32 perpIndex, uint32 spotIndex, uint32 spotPairAssetId);
    function tradeableAssetsLength() external view returns (uint256);
    function maxAnnualYieldBps() external view returns (uint256);
    function spotToPerp(uint32 spotIndex) external view returns (uint32);
    function isSpotWhitelisted(uint32 spotIndex) external view returns (bool);
}

/// @title MonetrixAccountant — Peg guardian & yield gate for Monetrix V1
/// @notice Peg defense + yield declaration authority. Holds no tokens; state is
///         strictly accounting metadata (interval, totals, timestamps).
/// @dev `settleDailyPnL` is the single yield declaration entry, gated on
///      `onlyVault`. Governance (24h timelock) owns parameter tuning.
///
///      Safety invariants enforced in `settleDailyPnL`:
///        1. Initialization gate — `lastSettlementTime > 0` (set via `initializeSettlement`)
///        2. Interval gate       — `block.timestamp ≥ lastSettlementTime + minSettlementInterval`
///        3. Distributable gate  — `proposedYield ≤ distributableSurplus()` (F1: redemption window)
///        4. Annualized gate     — `proposedYield ≤ supply × bps × Δt / (10000 × 1y)` (F8: typo + phantom rate limit)
contract MonetrixAccountant is IMonetrixAccountant, MonetrixGovernedUpgradeable {

    error NotVault();
    error SpotNotWhitelisted(uint64 spotToken);
    error SuppliedIndexOutOfBounds(uint256 index, uint256 length);
    error ConfigNotSet();

    modifier onlyVault() {
        if (msg.sender != vault) revert NotVault();
        _;
    }

    address public vault;
    IERC20 public usdc;
    USDM public usdm;
    address public config;

    /// @custom:deprecated Unused from V3 onward; retained for storage layout stability.
    int256 public lastSurplusSnapshot;
    uint256 public lastSettlementTime;
    uint256 public minSettlementInterval;

    // V3 additions
    uint256 public totalSettledYield;

    // ─── Supply-slot registries (HL 0x811 activation tracking) ──
 
    struct SuppliedAsset {
        uint64 spotToken;
        uint32 perpIndex; // ignored when spotToken == USDC_TOKEN_INDEX
    }
    SuppliedAsset[] public vaultSupplied;
    SuppliedAsset[] public multisigSupplied;
    mapping(uint64 => bool) internal _vaultSupplyKnown;
    mapping(uint64 => bool) internal _multisigSupplyKnown;

    // ─── Events ──────────────────────────────────────────────

    event YieldSettled(
        uint256 indexed day,
        uint256 proposedYield,
        uint256 distributable,
        uint256 cumulative
    );
    event MinSettlementIntervalUpdated(uint256 interval);
    event ConfigUpdated(address config);
    event SettlementInitialized(uint256 timestamp);
    event VaultSuppliedRegistered(uint64 indexed spotToken, uint32 perpIndex);
    event MultisigSuppliedRegistered(uint64 indexed spotToken, uint32 perpIndex);
    event VaultSuppliedRemoved(uint64 indexed spotToken);
    event MultisigSuppliedRemoved(uint64 indexed spotToken);

    uint256[46] private __gap;

    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        _disableInitializers();
    }

    function initialize(address _vault, address _usdc, address _usdm, address _acl) external initializer {
        require(_vault != address(0), "Accountant: zero vault");
        require(_usdc != address(0), "Accountant: zero usdc");
        require(_usdm != address(0), "Accountant: zero usdm");

        __Governed_init(_acl);

        vault = _vault;
        usdc = IERC20(_usdc);
        usdm = USDM(_usdm);
        minSettlementInterval = 20 hours;
    }


    // ─── View: backing + surplus ─────────────────────────────

    /// @notice Signed per-USDM backing. YieldEscrow (in-transit yield) and
    ///         InsuranceFund (ring-fenced reserve) are excluded by design.
    /// @dev Mark-to-market; signed so a liquidated perp account reduces backing.
    function totalBackingSigned() public view returns (int256 total) {
        // EVM USDC — Vault + RedeemEscrow (not YieldEscrow: undistributed yield is not backing)
        total = int256(usdc.balanceOf(vault));
        address re = IMonetrixVaultReader(vault).redeemEscrow();
        if (re != address(0)) {
            total += int256(usdc.balanceOf(re));
        }

        // L1 state — vault reads the Vault-side registry; multisigVault reads
        // its own registry. Strict 0x811 on every entry: if an entry is listed
        // but the slot was never actually activated on HL, backing reverts —
        // forcing a keeper/operator registration fix rather than silently
        // under-counting.
        total += _readL1Backing(vault, vaultSupplied);
        address _multisigVault = IMonetrixVaultReader(vault).multisigVault();
        if (_multisigVault != address(0)) {
            total += _readL1Backing(_multisigVault, multisigSupplied);
        }
    }

    /// @dev Sum perp + spot USDC + spot hedge tokens + supplied (registered) + HLP for a single L1 account.
    function _readL1Backing(address account, SuppliedAsset[] storage suppliedList)
        internal view returns (int256 total)
    {
        total = _readPerpAccountValueSigned(account);

        // L1 spot USDC (idle cash not yet deployed to perp/hedge)
        total += int256(_readSpotUsdcBalance(account));

        // Supplied (0x811) — iterate only registered slots; strict reads.
        uint256 slen = suppliedList.length;
        for (uint256 i = 0; i < slen; i++) {
            SuppliedAsset storage a = suppliedList[i];
            if (a.spotToken == uint64(HyperCoreConstants.USDC_TOKEN_INDEX)) {
                total += int256(PrecompileReader.suppliedUsdcEvm(account));
            } else {
                total += int256(
                    PrecompileReader.suppliedNotionalUsdcFromPerp(uint32(a.spotToken), a.perpIndex, account)
                );
            }
        }

        // Spot hedge tokens (0x801) — unchanged; 0x801 returns 0 for unheld tokens rather than reverting.
        if (config != address(0)) {
            IMonetrixConfigReader cfg = IMonetrixConfigReader(config);
            uint256 len = cfg.tradeableAssetsLength();
            for (uint256 i = 0; i < len; i++) {
                (uint32 perpIndex, uint32 spotIndex, ) = cfg.tradeableAssets(i);
                total += int256(_readSpotAssetUsdc(spotIndex, perpIndex, account));
            }
        }

        // HLP equity counted at full mark value (no principal cap).
        // multisigVault-held HLP is recognized on the same basis as Vault-held HLP.
        total += int256(_readHlpEquity(account));
    }

    /// @notice Unsigned view, clamped at 0. Internal math must use `totalBackingSigned()`.
    function totalBacking() public view returns (uint256) {
        int256 signed = totalBackingSigned();
        return signed > 0 ? uint256(signed) : 0;
    }

    function surplus() public view returns (int256) {
        return totalBackingSigned() - int256(usdm.totalSupply());
    }

    /// @notice Yield-declarable surplus. Subtracts pending redemption shortfall
    ///         from `surplus()` so `usdm.burn` at request time cannot inflate a
    ///         phantom-yield window before `claimRedeem` drains the USDC.
    function distributableSurplus() public view returns (int256) {
        int256 s = surplus();
        address re = IMonetrixVaultReader(vault).redeemEscrow();
        uint256 sf = re == address(0) ? 0 : IRedeemEscrow(re).shortfall();
        return s - int256(sf);
    }

    // ─── Daily settlement ────────────────────────────────────

    /// @notice Keeper-asserted daily yield declaration. On-chain bounds keep the
    ///         keeper's off-chain claim within safe distributable + annualized caps.
    /// @param proposedYield keeper-computed period yield (phantom-excluded off-chain)
    /// @return distributable the gate-2 bound at the time of call (audit only)
    function settleDailyPnL(uint256 proposedYield)
        external
        onlyVault
        returns (uint256 distributable)
    {
        // Gate 1 — Initialization
        require(lastSettlementTime > 0, "Accountant: not initialized");
        // Gate 2 — Interval
        require(
            block.timestamp >= lastSettlementTime + minSettlementInterval,
            "Accountant: settlement too early"
        );
        // Gate 3 — Distributable surplus bound (F1 fix: redeem-window safe)
        int256 ds = distributableSurplus();
        require(ds > 0, "Accountant: no distributable surplus");
        distributable = uint256(ds);
        require(proposedYield <= distributable, "Accountant: exceeds distributable");
        // Gate 4 — Annualized APR bound (F8 fix: typo + phantom rate limit)
        uint256 elapsed = block.timestamp - lastSettlementTime;
        uint256 cap = (usdm.totalSupply() * IMonetrixConfigReader(config).maxAnnualYieldBps() * elapsed)
            / (10_000 * 365 days);
        require(proposedYield <= cap, "Accountant: exceeds annualized cap");

        lastSettlementTime = block.timestamp;
        totalSettledYield += proposedYield;

        emit YieldSettled(_currentDay(), proposedYield, distributable, totalSettledYield);
    }

    // ─── Admin: config ───────────────────────────────────────

    function setConfig(address _config) external onlyGovernor {
        require(_config != address(0), "Accountant: zero config");
        config = _config;
        emit ConfigUpdated(_config);
    }

    function setMinSettlementInterval(uint256 interval) external onlyGovernor {
        require(interval >= 1 hours, "Accountant: interval too short");
        require(interval <= 2 days, "Accountant: interval too long");
        minSettlementInterval = interval;
        emit MinSettlementIntervalUpdated(interval);
    }

    // ─── Supply registrations (0x811 activation tracking) ────

    /// @notice Register a Vault-side supplied slot. Called automatically by
    ///         the Vault in paths that activate 0x811 (`supplyToBlp`, and
    ///         `executeHedge` when `pmEnabled` is true). Idempotent — a
    ///         second call with the same `spotToken` is a no-op.
    function notifyVaultSupply(uint64 spotToken, uint32 perpIndex) external onlyVault {
        if (!_vaultSupplyKnown[spotToken]) {
            _vaultSupplyKnown[spotToken] = true;
            vaultSupplied.push(SuppliedAsset({spotToken: spotToken, perpIndex: perpIndex}));
            emit VaultSuppliedRegistered(spotToken, perpIndex);
        }
    }

    /// @notice Register a multisigVault-side supplied slot; perp derived from `config.spotToPerp`.
    function addMultisigSupplyToken(uint64 spotToken) external onlyOperator {
        if (_multisigSupplyKnown[spotToken]) return;
        uint32 perpIndex = _resolvePerp(spotToken);
        _multisigSupplyKnown[spotToken] = true;
        multisigSupplied.push(SuppliedAsset({spotToken: spotToken, perpIndex: perpIndex}));
        emit MultisigSuppliedRegistered(spotToken, perpIndex);
    }

    /// @notice Operator removal of a supplied-registry entry; swap-and-pop, re-add via the normal path.
    /// @dev Operator-gated to match `addMultisigSupplyToken`. Removing an entry can only reduce
    ///      measured backing (never inflate it), so worst case is a more conservative settle —
    ///      no drain vector, doesn't warrant the 24h governor timelock.
    function removeSuppliedEntry(bool isMultisig, uint256 index) external onlyOperator {
        SuppliedAsset[] storage list = isMultisig ? multisigSupplied : vaultSupplied;
        mapping(uint64 => bool) storage known = isMultisig ? _multisigSupplyKnown : _vaultSupplyKnown;

        uint256 len = list.length;
        if (index >= len) revert SuppliedIndexOutOfBounds(index, len);

        uint64 removedToken = list[index].spotToken;
        uint256 last = len - 1;
        if (index != last) list[index] = list[last];
        list.pop();
        known[removedToken] = false;

        if (isMultisig) emit MultisigSuppliedRemoved(removedToken);
        else            emit VaultSuppliedRemoved(removedToken);
    }

    function _resolvePerp(uint64 spotToken) internal view returns (uint32) {
        if (spotToken == uint64(HyperCoreConstants.USDC_TOKEN_INDEX)) return 0;
        if (config == address(0)) revert ConfigNotSet();
        IMonetrixConfigReader cfg = IMonetrixConfigReader(config);
        // Registration check via map, not `spotToPerp != 0` — BTC-PERP is index 0.
        if (!cfg.isSpotWhitelisted(uint32(spotToken))) revert SpotNotWhitelisted(spotToken);
        return cfg.spotToPerp(uint32(spotToken));
    }

    /// @notice Length of the Vault supplied-asset registry (for off-chain UIs).
    function vaultSuppliedLength() external view returns (uint256) {
        return vaultSupplied.length;
    }

    /// @notice Length of the multisig supplied-asset registry (for off-chain UIs).
    function multisigSuppliedLength() external view returns (uint256) {
        return multisigSupplied.length;
    }

    // ─── Admin: lifecycle ────────────────────────────────────

    /// @notice Opens the settlement gate. Must run once; subsequent settles are
    ///         enforced against `lastSettlementTime`. Idempotency: cannot re-run.
    function initializeSettlement() external onlyGovernor {
        require(lastSettlementTime == 0, "Accountant: already initialized");
        require(config != address(0), "Accountant: config unset");
        lastSettlementTime = block.timestamp;
        emit SettlementInitialized(block.timestamp);
    }

    // ─── Internal precompile readers ─────────────────────────
    // All reads go through PrecompileReader (fail-closed: reverts on precompile
    // glitch so a transient outage can't be silently booked as a loss). The
    // EVM↔L1 unit conversions are owned by PrecompileReader itself — this
    // contract is pure aggregation logic.

    function _readPerpAccountValueSigned(address user) internal view returns (int256) {
        return int256(PrecompileReader.accountValueSigned(user));
    }

    function _readSpotAssetUsdc(uint32 spotTokenIndex, uint32 perpIndex, address account)
        internal view returns (uint256)
    {
        return PrecompileReader.spotNotionalUsdcFromPerp(spotTokenIndex, perpIndex, account);
    }

    function _readSpotUsdcBalance(address account) internal view returns (uint256) {
        return PrecompileReader.spotUsdcEvm(account);
    }

    function _readHlpEquity(address account) internal view returns (uint256) {
        return uint256(PrecompileReader.vaultEquity(account, HyperCoreConstants.HLP_VAULT).equity);
    }

    function _currentDay() internal view returns (uint256) {
        return block.timestamp / 1 days;
    }
}
