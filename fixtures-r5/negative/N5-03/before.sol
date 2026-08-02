// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;

contract Hasher {
    bytes32 public last;
    bytes public payload;

    constructor(bytes memory p) {
        payload = p;
    }

    function compute() external {
        // address(0x04) is the identity precompile: it echoes its input and
        // never reverts.
        (bool ok, bytes memory out) = address(0x04).staticcall(payload);
        require(ok, "precompile failed");
        last = keccak256(out);
    }
}
