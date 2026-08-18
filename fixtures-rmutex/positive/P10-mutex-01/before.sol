// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;

import "@openzeppelin/contracts/access/Ownable.sol";

contract Registry is Ownable {
    uint256 private _locked = 1;

    modifier lock() {
        require(_locked == 1, "reentrant");
        _locked = 0;
        _;
        _locked = 1;
    }

    string internal _label;

    constructor(string memory label_) {
        _label = label_;
    }

    function setLabel(string calldata l) external onlyOwner {
        _label = l;
    }
}
