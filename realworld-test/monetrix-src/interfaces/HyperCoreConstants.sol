// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.27;

/// @title HyperCoreConstants - Asset IDs, addresses, and protocol-level constants.
/// @notice Pure constants only. Precision / unit conversions live in `TokenMath`.
library HyperCoreConstants {
    address constant CORE_WRITER = 0x3333333333333333333333333333333333333333;
    address constant CORE_READ = 0x0000000000000000000000000000000000000800;
    address constant CORE_DEPOSIT_WALLET_MAINNET = 0x6B9E773128f453f5c2C60935Ee2DE2CBc5390A24;
    address constant CORE_DEPOSIT_WALLET_TESTNET = 0x0B80659a4076E9E93C7DbE0f10675A16a3e5C206;
    uint32 constant USDC_TOKEN_INDEX = 0;
    uint32 constant SPOT_DEX = type(uint32).max;

    // Action encoding constants
    uint8 constant ACTION_VERSION = 1;
    uint24 constant ACTION_LIMIT_ORDER = 1;
    uint24 constant ACTION_VAULT_TRANSFER = 2;
    uint24 constant ACTION_SPOT_SEND = 6;
    uint24 constant ACTION_SEND_ASSET = 13;
    uint24 constant ACTION_BORROW_LEND = 15;
    address constant USDC_SYSTEM_ADDRESS = 0x2000000000000000000000000000000000000000;
    uint256 constant EVM_TO_L1_PRECISION = 100;

    // Precompile addresses
    address constant PRECOMPILE_POSITION = 0x0000000000000000000000000000000000000800;
    address constant PRECOMPILE_SPOT_BALANCE = 0x0000000000000000000000000000000000000801;
    address constant PRECOMPILE_VAULT_EQUITY = 0x0000000000000000000000000000000000000802;
    address constant PRECOMPILE_ORACLE_PX = 0x0000000000000000000000000000000000000807;
    address constant PRECOMPILE_SPOT_PX = 0x0000000000000000000000000000000000000808;
    address constant PRECOMPILE_PERP_ASSET_INFO = 0x000000000000000000000000000000000000080a;
    address constant PRECOMPILE_TOKEN_INFO = 0x000000000000000000000000000000000000080C;
    address constant PRECOMPILE_ACCOUNT_MARGIN_SUMMARY = 0x000000000000000000000000000000000000080F;
    address constant PRECOMPILE_SUPPLIED_BALANCE = 0x0000000000000000000000000000000000000811;

    // HLP vault address (change per network before deployment)
    address constant HLP_VAULT = 0xa15099a30BBf2e68942d6F4c43d70D04FAEab0A0;
}
