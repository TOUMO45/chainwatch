Every other tool reports whether a contract is vulnerable now. Chainwatch reports **which commit made it vulnerable, and whether that commit is live on-chain.**

## Known limitations

Each shipped rule has documented cases where it is known to give the wrong
answer, recorded per rule and tagged as a false-negative or false-positive
risk. Two are worth knowing before reading any result:

- Rule 3c's proxy check proves a contract was *written* to sit behind a proxy,
  not that it *does*. Capability 11 (on-chain liveness) is what closes that gap.
- Rule 3c is silent on ERC-7201 namespaced storage, the OpenZeppelin 5.x
  default. On such repos a quiet result means *unmeasured*, not *safe*.

See **[LIMITATIONS.md](LIMITATIONS.md)** for the full list.
