// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.27;

interface ICoreWriter {
    function sendRawAction(bytes calldata data) external;
}

interface ICoreDepositWallet {
    function deposit(uint256 amount, uint32 destination) external;
    /// @notice Deposit USDC on behalf of `recipient` — credits recipient's L1 account
    function depositFor(address recipient, uint256 amount, uint32 destination) external;
}

interface IHyperCoreRead {
    struct SpotBalance {
        uint64 total;
        uint64 hold;
    }

    struct PerpPosition {
        int64 szi;
        uint32 leverage;
        uint64 entryNtl;
    }

    function readSpotBalance(address user, uint32 token) external view returns (SpotBalance memory);
    function readPerpPosition(address user, uint32 perp) external view returns (PerpPosition memory);
}
