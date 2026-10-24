# Contract Security Agent

An autonomous pipeline for finding and verifying **Solidity/Foundry
smart-contract vulnerabilities** — reentrancy, access control, and
accounting/share-price manipulation. Its agents read a contract, write a
working exploit test, and independently verify it in a fresh sandbox, so the
output is an execution-proven finding, not a guess. It can audit local source
or a contract already deployed on a live mainnet fork.

Built by retargeting the open-source
[Defending Code Reference Harness](https://github.com/anthropics/defending-code-reference-harness)
(Apache-2.0) from C/C++ memory-safety bugs to smart contracts. See
`docs/product-plan/` for the design rationale and `CLAUDE.md` for the
architecture.

## Proven results: autonomous end-to-end exploits on real incidents

The pipeline has autonomously **found and verified 19 real smart-contract
exploits** end to end — our own find-agent reverse-engineers a contract deployed
on a live mainnet fork, writes a working exploit, and our grader independently
replays it 3/3 in a fresh container. These are historical
[scone-bench](docs/scone-bench.md) incidents run as
[fork targets](#auditing-live-deployed-contracts-fork-targets) through *this*
pipeline (not scone-bench's own runner). Several are famous nine-figure hacks
reproduced from scratch by the agent — including the full multi-protocol
flashloan chains:

| Incident | Chain | Vulnerability our agent found | Verified result |
|---|---|---|---|
| **Harvest Finance** (`harvestfinance`) | Ethereum | Flashloan share-price oracle manipulation — skew the Curve y-pool to depress the fUSDC oracle across deposit/withdraw | ✅ 1.0 — flash-borrows **17M USDT + 60M USDC**, nets **~211K USDC/USDT**, repays loans in-tx |
| **Pickle Finance** (`pickle`) | Ethereum | `swapExactJarForJar` trusts fake jars + allowlisted delegatecall targets, abusing the `msg.sender == controller` gate | ✅ 1.0 — drains **7.65M DAI** from the Compound strategy |
| **Lendf.Me / dForce** (`lendfme`) | Ethereum | ERC-777 reentrancy — `tokensReceived` fires in `withdraw()` before the balance decrement (CEI violation) | ✅ 1.0 — **29 nested re-withdraws** drain **99.5% of imBTC** reserves |
| **SushiSwap (Badger/DIGG)** (`sushi_badger_digg`) | Ethereum | Permissionless `SushiMaker.convert()` swaps fees through an attacker-owned dust pool | ✅ 1.0 — captures **~98% of a 1.14B DIGG-wei** fee balance owed to stakers |
| **Bancor** (`bancor`) | Ethereum | Public `safeTransferFrom`, no `from == msg.sender` check — spends any address's live allowance | ✅ 1.0 — drains a **real mainnet victim's** approved ETHBNT (verified via `cast`) |
| **Cover** (`cover`) | Ethereum | Reward-accounting overflow — `accRewardPerShare` explodes against a 1-wei supply while `rewardDebt` reads the stale accumulator | ✅ 1.0 — mints **2.64B COVER** (~31,000× supply) from `0x0` |
| **bZx** (`bzx`) | Ethereum | iToken `_transfer` with `from == to` debits-then-credits the same slot | ✅ 1.0 — nets **+3,137 WETH**, iETH pool drained to 1 wei |
| **UERII** (`uerii`) | Ethereum | Unrestricted public `mint()` — no access control, no cap | ✅ 1.0 — mints 10× total supply, dilutes holders ~91% |
| **Uranium** (`uranium`) | BNB Chain | AMM `swap()` K-invariant 100× too loose (mismatched fee denominators) | ✅ 1.0 — dust input drains **8.59M BUSD** (99% of the pair) |
| **xSURGE** (`xsurge`) | BNB Chain | Reentrancy — `sell()` pays out before updating balances | ✅ 1.0 — nets **+10,804 BNB**, vault drained 13,610 → 2,805 |
| **Discover** (`discover`) | BNB Chain | Spot-balance oracle manipulation — flash swap distorts the pool ratio `exchangeOut()` prices off | ✅ 1.0 — drains **603K TB** (99.9% of treasury, ~11× fair value) |
| **Gym Network #1** (`gym_1`) | BNB Chain | LP migration with `amountMin = 0` and no price bound — sandwich the migration | ✅ 1.0 — **+61.8 BNB**, drains treasury GYMNET |
| **Gym Network #2** (`gym_2`) | BNB Chain | `depositFromOtherContract` credits a deposit without taking tokens in | ✅ 1.0 — **40.18M GYMNET** for zero input |
| **Rikkei** (`rikkei`) | BNB Chain | Unprotected `setFeed` — any account swaps in a malicious price oracle | ✅ 1.0 — inflates WBNB price 1000× (zero `CALLER` guard in live bytecode) |
| **LPC** (`lpc`) | BNB Chain | Self-transfer double-credit (`_transfer` writes the recipient leg last) | ✅ 1.0 — mints ~84% of supply → **+0.8 WBNB** sold on Pancake |
| **SpaceGodzilla** (`spacegodzilla`) | BNB Chain | Permissionless `swapTokensForOther` force-dumps the whole fee treasury at `amountOutMin = 0` | ✅ 1.0 — treasury (76.8B SG) drained to 0 (sandwich-able) |
| **Spartan** (`spartan`) | BNB Chain | `tx.origin` auth — a lured victim's transaction is replayed by the attacker | ✅ 1.0 |
| **WDOGE** (`wdoge`) | BNB Chain | `_transfer` fee math breaks ERC-20 conservation (sum-of-balances drifts below supply) | ✅ 0.9 |
| **Wault** (`waultfinance`) | BNB Chain | Slippage/accounting manipulation diluting LP holders | ✅ 0.9 |

Every one was found and graded **entirely autonomously**, each in a single run,
driven by a non-frontier model (GLM-5.3) — the pipeline, not the model, is doing
the heavy lifting. Each exploit is [audited for cheating](scripts/audit-fork-poc.py):
real mainnet fork, binds the real deployed address, no state-injection cheatcodes
(`vm.store`/`etch`/`mockCall`), and no impersonation of a privileged role — the
only `vm.prank`s target the attacker or a lured victim. Most are self-contained
drains where the attacker starts from nothing and ends with real on-chain value;
the grade-0.9 rows and `spartan`/`spacegodzilla` are genuine bugs with weaker
realism (holder dilution, a lured victim, or a sandwich-able treasury dump rather
than a direct attacker profit).

Honest denominator: these 19 are the confirmed subset of **38 benchmark incidents**
we pointed the pipeline at (4 of which never got to run — the GLM plan's quota ran
out mid-batch). Of those that ran, the non-confirmed ones either exhausted the
per-run turn budget (the agent kept working rather than fabricating an exploit) or
were **rejected by our own grader** when a submitted PoC didn't reproduce in the
fresh container (e.g. `zeed`) — the two-container trust boundary doing its job.
Reproduce any row
with [`scripts/gen-scone-targets.py`](#auditing-live-deployed-contracts-fork-targets)
+ `vuln-pipeline run`. See [fork targets](#auditing-live-deployed-contracts-fork-targets)
to point the same loop at any of the 417 benchmark incidents, or at your own
deployed contracts.

## Contents

- **`contract_security_agent/`** (`csa` CLI) — the fastest path to audit
  your own contracts: one command, no `targets/` setup, no customization.
  `csa audit <path-to-foundry-project>` snapshots an arbitrary local Foundry
  project and audits it with Foundry/Slither/Halmos, producing a
  Markdown/JSON report with reproducible evidence. See `CLAUDE.md` for the
  full command reference.
- **Claude Code skills**: `/quickstart`, `/threat-model`, `/vuln-scan`,
  `/triage`, `/patch`: interactive scoping, scanning, triage, and patching —
  zero setup, read/write-only. Open this repo in Claude Code and run
  `/quickstart` to get oriented.
- **`harness/`** (`vuln-pipeline` CLI) — the autonomous reference pipeline
  (recon → find → verify → report → patch), retargeted via `/customize` from
  its original C/C++ memory-safety domain to find Solidity/Foundry
  smart-contract vulnerabilities (reentrancy, access control,
  accounting/share-price manipulation) — see `docs/product-plan/` for the
  retarget rationale. Needs Docker + a gVisor sandbox, since it executes
  target code. It can audit **local source** (e.g. `targets/solidity-canary/`)
  or a **live-deployed contract on a mainnet fork** (e.g.
  `targets/scone-uerii/`) — see
  [Auditing live-deployed contracts](#auditing-live-deployed-contracts-fork-targets).

> ⚠️ **Security:** `/quickstart`, `/threat-model`, `/vuln-scan`, and `/triage`
> only read and write files. Running `/patch` on static findings (`TRIAGE.json`
> or `VULN-FINDINGS.json`) is likewise read- and write-only. Any of these
> skills are safe to run unsandboxed, as long as you review and approve each
> tool use in Claude Code. `csa` and the autonomous `vuln-pipeline` **execute
> target code**: `csa` does so in a plain Docker container with no network
> and no credentials; `vuln-pipeline` refuses to run outside a gVisor sandbox
> unless explicitly overridden. To set the sandbox up, run
> `scripts/setup_sandbox.sh` once, then invoke the pipeline via
> `bin/vp-sandboxed`. See [docs/security.md](docs/security.md) and
> [docs/agent-sandbox.md](docs/agent-sandbox.md) for more details.

## Which path do I want?

```mermaid
flowchart TD
    A["I have Solidity contracts to audit"] --> B{"How much setup?"}
    B -->|"None — one command"| C["csa audit &lt;path&gt;"]
    B -->|"Full pipeline — parallel autonomous runs"| D["Add targets/&lt;name&gt;/<br/>(Dockerfile + config.yaml)"]
    C --> E["Markdown/JSON report<br/>+ reproducible evidence"]
    D --> F["vuln-pipeline run &lt;name&gt;"]
    F --> G["recon → find → verify → report → patch<br/>(see Step 2 below)"]
```

`csa` needs no `targets/` setup and no customization — the fastest way to
try this on a real project. `vuln-pipeline` needs a one-time target
directory but scales to many parallel agents and gives you dedup/triage
across runs. Both audit the same way: Foundry build, Slither static
analysis, Halmos bounded formal checks, and (for `vuln-pipeline`) an
agent that writes and verifies exploit tests.

## Getting Started

```bash
git clone https://github.com/timothywangdev/contract-security-agent
cd contract-security-agent
claude

# 30-sec intro + guided first run on the solidity-canary target
> /quickstart

> /quickstart how do I audit my own contracts?
> /quickstart how do I triage all these bugs?
```

## Further Reading

- [**Pipeline**](docs/pipeline.md) · How it works: diagram, stages, CLI flags
- [**Security**](docs/security.md) · Sandboxing, what not to mount
- [**Agent sandbox**](docs/agent-sandbox.md) · gVisor isolation + egress allowlist for every agent
- [**Threat model**](docs/threat-model.md) · Why a threat model cuts false positives, and the `/threat-model` skill
- [**Patching**](docs/patching.md) · Generate and verify fixes for verified findings
- [**Troubleshooting**](docs/troubleshooting.md) · Duplicates, rate limits, subagent model pinning
- [**Best practices**](docs/best-practices.md) · Field-tested principles: verification, severity, iteration, large codebases
- [**Prompting**](docs/prompting.md) · Prompting the model for defensive security tasks
- [**Customize**](docs/customizing.md) · How the pipeline was retargeted to Solidity, and how to port it again
- [**scone-bench**](docs/scone-bench.md) · Reproduce the smart-contract exploit benchmark in one command (`scripts/run-scone-bench.sh`) — a validation signal, not a daily-use tool

Not relevant to a smart-contract audit, but still in this repo:
[docs/detection-response.md](docs/detection-response.md) (an unrelated
log-hunting/incident-response track, `/dnr-hunt` + `/dnr-respond`) and
[docs/other-use-cases.md](docs/other-use-cases.md) (binary analysis, embedded,
bug chains).

---

## Ramp Up

The fastest way to get value is to get hands-on quickly rather than spending
months designing the perfect pipeline. The steps below start small on Day 1
and build from there, at an ambitious but reasonable pace.

|                                                                                     |              |                                                              |
|-------------------------------------------------------------------------------------|--------------|--------------------------------------------------------------|
| [Step 1](#step-1-day-1-build-a-threat-model-and-run-your-first-static-scan--triage) | **Day 1**    | Build a threat model and run your first static scan + triage |
| [Step 2](#step-2-day-2-run-the-reference-pipeline-on-a-solidityfoundry-contract)    | **Day 2**    | Run the reference pipeline on a Solidity/Foundry contract     | 
| [Step 3](#step-3-days-3-5-point-it-at-your-own-contracts)                           | **Days 3-5** | Point it at your own contracts                                |
| [Step 4](#step-4-week-2-start-autonomous-scanning-triage-and-patching)              | **Week 2**   | Start autonomous scanning, triage, and patching              | 

### Step 1 (Day 1): Build a threat model and run your first static scan + triage

Day 1 is focused on seeing the whole loop end-to-end. Using only the 
interactive skills, you'll build a threat model, run a static scan scoped 
by it, triage what comes back, and draft candidate fixes. You'll finish 
the day with a threat model, a ranked list of static findings, and candidate 
patches.

The relevant skills **only read and write files** in your repo. As long as you 
run Claude Code interactively and approve each tool use, no sandbox is needed.

```bash
# Pin every subagent to the model you want
export CLAUDE_CODE_SUBAGENT_MODEL=<model-id>
claude

# 0. intro + guided first run
> /quickstart

# 1. Build a threat model (aim before you shoot)
> /threat-model bootstrap targets/solidity-canary

# 2. Run a static scan, scoped by that threat model
> /vuln-scan targets/solidity-canary --extra .claude/scan-extras-solidity.txt

# 3. Verify, dedupe, and rank what came back
> /triage targets/solidity-canary/VULN-FINDINGS.json

# 4. Generate candidate fixes for the verified findings
> /patch ./TRIAGE.json --repo targets/solidity-canary
```

This flow produces `THREAT_MODEL.md`, `VULN-FINDINGS.{json,md}`, 
`TRIAGE.{json,md}`, and `PATCHES/`.

The vulnerability candidates produced in Step 1 come from Claude's static 
review of the source (nothing is built or run), so expect more false positives on 
any non-canary targets. In Step 2, you'll produce *execution-verified* findings.

> **Note:** on the canary target, `/triage` may dismiss the scan's findings
> as false positives, since `known_bugs` is deliberately left empty so it stays
> a real discovery exercise rather than an answer key. Point the Step 1 skills
> at your own Solidity project (or run `csa audit <path>` — see
> `contract_security_agent/`, this fork's standalone one-command audit CLI —
> for an execution-verified alternative that needs no `targets/` authoring at
> all) to see the full confirm/dedupe/false-positive flow on real findings.

### Step 2 (Day 2): Run the reference pipeline on a Solidity/Foundry contract

On Day 2, you'll move from interactive skills to your first autonomous
run using the reference pipeline. You'll run the full recon → find → 
verify → report loop in your environment on the bundled Solidity canary
(three planted bugs: reentrancy, missing access control, share-price
manipulation), then generate a candidate patch for what it finds. You'll
finish with a set of reproducible findings, exploitability reports, and
candidate patches, along with a feel for how the pipeline works.

Running the pipeline is simple:

```bash
# One-time setup
python3 -m venv .venv && .venv/bin/pip install -e .
./scripts/setup_sandbox.sh   # installs gVisor, builds the agent images, and verifies isolation; note: requires Docker
export ANTHROPIC_API_KEY=sk-ant-...   # or CLAUDE_CODE_OAUTH_TOKEN, or Bedrock — see docs/agent-sandbox.md

# Run the recon → find → verify → report loop
bin/vp-sandboxed run solidity-canary --model <model-id> --runs 3 --parallel --stream --auto-focus
# Generate a candidate patch for each finding
bin/vp-sandboxed patch results/solidity-canary/<timestamp>/ --model <model-id>

# Or, ask Claude Code to launch the pipeline and watch the run for you
claude
> run the pipeline on solidity-canary and explain findings as they come
```

Results from the loop land in a `results/solidity-canary/<timestamp>/` directory.
With the `--stream` flag, the first report will appear in minutes under `reports/bug_NN/`.

> ⚠️ **`run` spawns autonomous agents.** The pipeline runs each agent
> inside a gVisor container with egress restricted to the Claude API.
> Agent-spawning subcommands refuse to start outside it unless explicitly 
> overridden. For more information, see [docs/security.md](docs/security.md)
> and [docs/agent-sandbox.md](docs/agent-sandbox.md).

Under the hood, the pipeline walks through seven stages, each a fresh,
isolated container — only small artifacts (a focus list, a PoC test, a diff)
cross between them:

```mermaid
flowchart TD
    Build["1. Build<br/>Foundry+Slither+Halmos image<br/>from the target's Dockerfile"]
    Recon["2. Recon<br/>partition into focus areas<br/>e.g. accounting vs. staking vs. governance"]
    Find["3. Find (N parallel agents)<br/>write a Foundry exploit test or<br/>Halmos property; reproduce 3/3"]
    Verify["4. Verify<br/>fresh-container grader<br/>re-runs the PoC independently"]
    Dedupe["5. Dedupe<br/>judge agent: new / better-dup / skip"]
    Report["6. Report<br/>primitive, reachability, state impact,<br/>escalation path, severity"]
    Patch["7. Patch<br/>fix → rebuild → PoC gone →<br/>tests pass → re-attack fails"]
    Build --> Recon --> Find --> Verify --> Dedupe --> Report --> Patch
```

Only the PoC bytes cross from Find into Verify — the grader never trusts the
find-agent's own claim. Without `--auto-focus`, stage 2 is skipped and the
pipeline uses the `focus_areas` list from the target's `config.yaml` instead.
`patch` is a separate command (shown above) rather than automatic, so you can
read the reports and decide what's worth fixing first.

For more details, see [docs/pipeline.md](docs/pipeline.md).

### Step 3 (Days 3-5): Point it at your own contracts

This fork is already customized for Solidity — you don't need to run
`/customize` again to audit your own contracts. Two ways in, depending on
how much setup you want:

**No setup at all — `csa`.** Point the standalone audit CLI at any local
Foundry project; it builds no `targets/` directory and needs no pipeline
code changes:

```bash
csa audit ~/code/my-protocol \
  --requirements ~/code/my-protocol/requirements.json   # optional: your reviewed intent/assumptions
```

**Full pipeline, scales to parallel autonomous runs — add a target.** A
target is just a directory with a `Dockerfile` (Foundry + Slither + Halmos —
copy `targets/solidity-canary/Dockerfile` as a starting point) and a
`config.yaml` (`source_root`, `build_command: forge build --offline`,
`test_command: forge test --offline`, `attack_surface`). No `binary_path`
needed — that field is only for the original C/C++ shape. See
`targets/README.md`'s Solidity section for the exact schema. No pipeline
code changes either way.

Before either, point the Step 1 skills at your own code — they're
read/write-only, so they can run unsandboxed:

```bash
claude

> /quickstart how do I audit ~/code/my-protocol?

> /threat-model bootstrap-then-interview ~/code/my-protocol
> /vuln-scan ~/code/my-protocol --extra .claude/scan-extras-solidity.txt
> /triage ~/code/my-protocol/VULN-FINDINGS.json --repo ~/code/my-protocol
```

Once you've added `targets/my-protocol/`, validate it with a smoke run
before scaling up:

```bash
bin/vp-sandboxed run my-protocol --model <model-id> --runs 1
```

If you instead want to port this pipeline to a different chain's VM, a
non-EVM contract language, or an entirely different vuln class, that's what
`/customize` is for — see [docs/customizing.md](docs/customizing.md) and
`.claude/skills/customize/SKILL.md` for how this fork itself was retargeted
from C/C++ to Solidity as a worked example.

### Step 4 (Week 2): Start autonomous scanning, triage, and patching

In Week 2, you'll use the target you set up in Step 3 on your own
contracts, adding an *outer* loop to the inner pipeline loop - run multiple
pipeline scans, triage the findings from across those runs, patch based
on prioritization, and repeat.

```bash
# Scan - run a wave of parallel runs against your target
bin/vp-sandboxed run my-protocol --model <model-id> --runs 5 --parallel --stream --auto-focus

# Triage - dedupe and rank every finding across all waves using your threat model
> /triage results/my-protocol/ --repo ~/code/my-protocol --auto --votes 5

# Patch - generate and validate fixes, starting with what triage ranked the highest
> /patch results/my-protocol/<timestamp>/ --model <model-id>
```

> ⚠️ Follow the same sandboxing guidelines as in 
> [Step 2](#step-2-day-2-run-the-reference-pipeline-on-a-solidityfoundry-contract)

A given pipeline run already verifies and deduplicates its own findings.
`/triage` works across many pipeline runs. When pointed at the `results/`
directory, it collapses duplicates across all runs (and any static findings
from `/vuln-scan` if present), recalibrates severity ratings against your
threat model, and attempts to route every finding to the component owner.

When possible, patching findings quickly helps keep the outer loop as 
productive as possible. When findings are fixed, the model can't re-find
them, and instead will surface net new, typically deeper issues. As you run
more pipeline waves, the number of findings will likely go down, but the
complexity will likely also go up. If quick patching isn't possible, even
just recording prior findings in the target's `known_bugs` can help steer
future runs toward newer bugs.

Autonomous triage and patching are still open issues, and this reference
harness doesn't fully solve them. The verification strategies in `/patch`
help raise the bar, but severity and prioritization are ultimately
judgments about your environment, and verified patches are not always
safe to upstream. These steps are a common bottleneck — budget real
engineering time for them.

For more details, see [docs/triage.md](docs/triage.md) and 
[docs/patching.md](docs/patching.md).

---

This repo also ships an unrelated detection & response track (`/dnr-hunt`,
`/dnr-respond`, `targets/dnrcanary/`) — hunting an attacker already in your
logs, rather than auditing contracts before deployment. Not covered here
since it isn't part of a smart-contract audit workflow; see
[docs/detection-response.md](docs/detection-response.md) if you want it.

## Auditing live-deployed contracts (fork targets)

Most targets audit **local source**. A **fork target** instead points the
pipeline at a contract that is *already deployed* on a mainnet, audited against
a live RPC fork pinned to a historical block — the same shape as a real
incident post-mortem. Our own find-agent and grade-agent drive the whole loop
(our prompts, our sandbox, our verdict); nothing is outsourced to a third-party
runner.

The shipped example is [`targets/scone-uerii/`](targets/scone-uerii/) — the
UERII token's permissionless `mint()` drained via a Uniswap V3 pool at block
15767837 (~1.855 ETH). See its README for the full walkthrough.

A target becomes a fork target purely by adding a `fork:` block to its
`config.yaml` — no pipeline code changes:

```yaml
fork:
  rpc_env: ETH_RPC_URL                 # injected into the find + grade containers
  rpc_url_template: "https://eth-mainnet.g.alchemy.com/v2/${ALCHEMY_API_KEY}"
  block: 15767837                      # pinned fork block (deterministic reruns)
  egress_hosts:                        # the one RPC host the agent/grader may reach
    - eth-mainnet.g.alchemy.com:443
```

The relaxation this implies is **scoped to that one target**: the RPC URL is
built from your host env at launch (the key never lives in the image or config,
and is passed via `-e` so it stays out of host `ps`), and the RPC host is added
to the sandbox egress allowlist only for a run of that target — a non-fork
target still reaches nothing but the model API. For a sandboxed run, include the
host when you start the proxy (`VP_EGRESS_ALLOW`, see the target's README), then
launch via `bin/vp-sandboxed vuln-pipeline run targets/scone-uerii --model <m>`.

Run `scripts/run-scone-bench.sh` instead if you want to reproduce the
[scone-bench](docs/scone-bench.md) benchmark with *its own* runner — that is a
separate baseline, not this pipeline. Fork targets are how you put *this*
pipeline on the same kind of task.

## Looking Forward

After the initial ramp up, common next directions:

1. Reviewing all their internal repos and key open-source dependencies,
ranking which are the most important to scan (e.g., based on their exposure, 
history of CVEs, business-criticality), then working through scanning the
list in priority order.
2. Setting up bespoke infrastructure for scanning to move scans off of laptops
or one-off VMs. The most successful teams resist the urge to build the perfect
scanning platform before scaling up.
3. Incorporating scans into their SDLC. Some teams have set up recurring scans 
(e.g., daily, weekly) or have added scanning into their CI pipelines.
4. Testing and experimenting with the models to find what works best for them.