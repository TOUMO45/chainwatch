# fixtures-foundry — ground truth for the Foundry-detection gap (COMP-L1)

NOT a scorer set. There is no `manifest.json` here and no rule is scored
against these files: nothing in this directory is about detection. It is
ground truth for a **compilation** question, which is why it is frozen by
`guard.sh` alongside the detection fixtures — the same reason applies. If a
future change makes the fallback fire more widely, these files are what
notices.

What each file is for, and what would be untrue if it changed:

| path | must be | pays for |
|---|---|---|
| `project/foundry.toml` | present, minimal | it is the ONLY thing that makes crytic-compile route `project/src/*.sol` to the Foundry platform. Delete it and every test here passes vacuously. |
| `project/src/Vault.sol` | valid Solidity, **no imports**, exact pin `0.8.20` | the positive: bare solc must be able to compile it, so a failure after the fallback is the fallback's fault and nothing else's. No imports means no remapping can be blamed. |
| `project/src/Broken.sol` | a **genuine syntax error** | the guard against masking. Inside a Foundry tree, the error a caller sees must be solc's own diagnostic, not "forge is not installed". |
| `plain/Broken.sol` | **byte-identical** to `project/src/Broken.sol` | the control. Same source outside any Foundry project must produce the same genuine error, which is how "not masked" is stated as an equality rather than as a vibe. |

`plain/` deliberately has no `foundry.toml` at or above it *within this
directory*. The tests assert that directly rather than assuming it, because
a `foundry.toml` added anywhere in a parent would silently change what the
control controls for.
