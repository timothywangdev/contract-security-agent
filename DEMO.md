# vuln-pipeline demo: solidity-canary

End-to-end walkthrough on the `solidity-canary` target — three deliberately
planted Solidity bugs, one per contract, in a local-only Foundry project
(no CVE, no upstream, no disclosure; see
[`targets/solidity-canary/README.md`](targets/solidity-canary/README.md)
for the answer key).

| Contract | Function | Class | Expected time to first find |
|---|---|---|---|
| `ReentrancyVault` | `withdraw(uint256)` | Reentrancy (external call before an unchecked debit) | ~5–10 min |
| `FeeManager` | `setFeeRecipient(address)` | Missing access control | ~5–10 min |
| `ShareVault` | `deposit()` / `receive()` | First-depositor / share-price manipulation | ~10–20 min |

Full target details: [`targets/solidity-canary/README.md`](targets/solidity-canary/README.md).

## 0. Prerequisites

- Linux host with Docker.
- A model to drive the agents. The pipeline reads `VULN_PIPELINE_MODEL` from
  the environment (or `--model` per command); it is never read from target
  config. This walkthrough exports it once in step 2.

## 1. One-time setup

Installs the venv + pipeline, registers the gVisor `runsc` runtime, and starts
the egress-allowlist proxy on the `vp-internal` network. Safe to re-run.

```bash
scripts/setup_sandbox.sh
```

`bin/vp-sandboxed` is the entry point from here on — it checks the sandbox is
up, exports the runtime/proxy env, and execs `.venv/bin/vuln-pipeline`.

## 2. Auth

Pick one, per [`docs/agent-sandbox.md`](docs/agent-sandbox.md):

```bash
# Local dev / laptop (recommended for the demo)
claude setup-token                       # prints CLAUDE_CODE_OAUTH_TOKEN
export CLAUDE_CODE_OAUTH_TOKEN=<token>

# or: an API key
export ANTHROPIC_API_KEY=sk-ant-...

# or: Amazon Bedrock (see docs/agent-sandbox.md for the full setup)
export CLAUDE_CODE_USE_BEDROCK=1
export AWS_REGION=us-east-1
export AWS_BEARER_TOKEN_BEDROCK=...
```

Set the model once for the session — every `vuln-pipeline` subcommand reads it:

```bash
export VULN_PIPELINE_MODEL=<model-id>
```

## 3. Recon (read-only, ~2 min)

Runs a single agent that reads the source tree and proposes `focus_areas`.
Prints YAML to stdout — review before launching finds.

```bash
bin/vp-sandboxed recon solidity-canary
```

Expect 3 areas, one per contract: `ReentrancyVault`'s accounting, `FeeManager`'s
privileged functions, and `ShareVault`'s share-price math.

## 4. Small first wave (calibration)

First-time use on a target: 3 parallel finds, capped turns, streaming reports.
Gives a feel for token burn and whether prompts are landing before scaling up.

```bash
bin/vp-sandboxed run solidity-canary \
    --auto-focus --runs 3 --parallel --stream --max-turns 50
```

The pipeline auto-builds `vuln-pipeline-solidity-canary:latest` from
`targets/solidity-canary/Dockerfile` on first run.

## 5. Full wave

Launch in the background so you can tail logs while it runs. All three
planted bugs are fund-loss/state-corruption findings — no `--accept-dos`
needed (there's no DoS-class bug in this target).

```bash
bin/vp-sandboxed run solidity-canary \
    --auto-focus --runs 9 --parallel --stream \
    2>&1 | tee solidity_canary_run.log &
```

`--novelty` doesn't apply here — `solidity-canary` is local-only with no
upstream `github_url`/`commit` to diff against.

## 6. Watch it

```bash
RESULTS=$(ls -td results/solidity-canary/*/ | head -1)
tail -f solidity_canary_run.log              # heartbeat + per-action progress
cat   $RESULTS/found_bugs.jsonl              # findings landed so far (test identifiers + VIOLATION reasons)
ls    $RESULTS/run_*/result.json             # graded runs
cat   $RESULTS/reports/judge_log.jsonl       # NEW / DUP_BETTER / DUP_SKIP per finding
cat   $RESULTS/reports/manifest.jsonl        # bug_NN assignments
ls    $RESULTS/reports/bug_*/report.json     # exploitability reports written so far
```

First report typically lands within ~5-10 minutes of launch. Stragglers
don't block disk writes — kill a stuck find with
`docker rm -f find_solidity-canary_<N>`.

## 7. Read the findings

```bash
RESULTS=$(command ls -td results/solidity-canary/*/ | head -1)
jq . "${RESULTS}reports/bug_00/report.json"
cat  $RESULTS/reports/bug_00/poc.bin         # the exploit/property test source (a .t.sol file, not a binary blob)
```

Each `report.json` is a structured exploitability analysis: the broken
primitive/invariant, reachability from a real entry point, state impact,
escalation path, constraints, plus an agent-judged severity.

## 8. (Optional) Patch phase

Generates a fix per unique finding and walks it through build → finding-stops
→ tests-pass → 50-turn re-attack. `targets/solidity-canary/config.yaml`
already has the required `build_command`/`test_command`
(`forge build --offline` / `forge test --offline`).

```bash
bin/vp-sandboxed patch $RESULTS
cat $RESULTS/reports/bug_00/patch.diff
jq  . $RESULTS/reports/bug_00/patch_result.json     # t0_builds .. re_attack_clean
```

The ladder verifies the finding is gone, not that the diff is safe to
upstream — review `patch.diff` by hand (see
[`docs/patching.md#reviewing-generated-patches`](docs/patching.md#reviewing-generated-patches)).

## 9. Cleanup

```bash
docker ps -a --filter name=solidity-canary                   # any leftover agent containers
docker rm -f $(docker ps -aq --filter name=solidity-canary)  # if needed
```

Results stay on disk under `results/solidity-canary/<timestamp>/`. The
target's source is copied into the image at build time, so nothing lands in
your working tree.
