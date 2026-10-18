# solidity-canary — fast iteration target (Solidity/Foundry)

A deliberately vulnerable Foundry project with three planted bugs, one per
contract. Exists so pipeline changes to the Solidity/Foundry port can be
verified quickly instead of against a real audited protocol.

**This is not a real-world target.** No CVE, no disclosure, no upstream. The
bugs are planted and documented here; `known_bugs` in `config.yaml` is left
empty on purpose — this file, not the config, is the answer key.

## The three bugs

| Contract | Function | Bug | Class |
|---|---|---|---|
| `ReentrancyVault` | `withdraw(uint256)` | External call before an `unchecked` balance debit | Reentrancy |
| `FeeManager` | `setFeeRecipient(address)` | No access-control check (contrast: `pause()` is correctly owner-gated) | Missing access control |
| `ShareVault` | `deposit()` / `receive()` | Share price derived from `address(this).balance`, which a direct ETH donation can inflate without minting shares | First-depositor / share-price manipulation |

Three distinct vulnerability classes, each reachable by any external caller
with no privileged setup.

## Quick start

```bash
vuln-pipeline run solidity-canary --runs 3 --parallel --stream --model <model>
```

## Regression suite

`test/Normal.t.sol` proves legitimate single-user usage works for all three
contracts (deposit/withdraw round-trips, owner-only `pause()`), so T2
patch-grading has something to check after a fix is applied. It does not
exercise or spoil any of the three bugs above.
