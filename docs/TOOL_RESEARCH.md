# MVP tool research

Checked against primary repositories/documentation on 2026-10-07. Recommendations are design judgments. The listed versions are candidates observed in release pages, not an installed or interoperability-tested lockfile. Documentation on moving branches may differ from a release; verify behavior against the final pinned artifacts.

## 1. Execution and verification stack

| Tool | Observed license and release | Decision | Role and important limitation |
|---|---|---|---|
| [Foundry](https://github.com/foundry-rs/foundry) | MIT OR Apache-2.0; [v1.8.5](https://github.com/foundry-rs/foundry/releases/tag/v1.8.5) | Required | Forge builds/tests/fuzzes; Anvil replays local EVM transactions; Cast inspects calls/receipts. Passing tests do not prove all behaviors safe. |
| [Slither](https://github.com/crytic/slither) | AGPL-3.0; [0.11.6](https://github.com/crytic/slither/releases/tag/0.11.6) | Required | Static findings and structure to guide investigation. Successful analysis can contain findings; results still need triage. |
| [crytic-compile](https://github.com/crytic/crytic-compile) | AGPL-3.0; [0.4.2](https://github.com/crytic/crytic-compile/releases/tag/0.4.2) | Build dependency | Build-system integration and compilation artifacts. Preserve the project's native compiler/settings. |
| [Halmos](https://github.com/a16z/halmos) | AGPL-3.0; [v0.3.3](https://github.com/a16z/halmos/releases/tag/v0.3.3) | Required first formal backend; selected properties | Execute reviewed Solidity properties symbolically. Report bounds, incomplete paths, unsupported behavior, and solver failures. |
| [Gambit](https://github.com/Certora/gambit) | MIT | Evaluation tool | Mutate Solidity to assess test/property strength. Compile failures and equivalent mutants need separate accounting. |
| [Echidna](https://github.com/crytic/echidna) | AGPL-3.0; [v2.3.3](https://github.com/crytic/echidna/releases/tag/v2.3.3) | First optional stateful fuzzer | Corpus-based campaigns, shrinking, and reproducible sequences. Add when Foundry-based campaigns leave an observed gap. |
| [Medusa](https://github.com/crytic/medusa) | AGPL-3.0; [v1.5.1](https://github.com/crytic/medusa/releases/tag/v1.5.1) | Alternative optional fuzzer | Parallel coverage-guided campaigns over go-ethereum. Evaluate when worker parallelism justifies added integration. |
| [Solidity SMTChecker](https://docs.solidity.org/en/latest/smtchecker.html) | Part of GPL-3.0 Solidity compiler | Later adapter | CHC can reason about unbounded transaction sequences/loops; abstractions and unsupported targets affect outcomes. |
| [Certora AutoProver](https://github.com/Certora/AutoProver) and [Prover](https://github.com/Certora/CertoraProver) | GPL-3.0 | Competitor/reference; later integration | Existing automated specification/harness/prover pipeline. Local Prover is open source; AutoProver's convenient Docker path uses cloud credentials. |
| [Kontrol](https://github.com/runtimeverification/kontrol) | BSD-3-Clause | Later deeper-proof adapter | Foundry-oriented proof workflow over KEVM, including lemmas and loop invariants. Higher setup/specification cost; bounded mode still needs bounded claims. |

Release activity supports evaluating these tools; it does not establish a support SLA or compatibility between the listed versions.

### Adapter requirements

**Foundry:** capture structured results plus stderr/traces separately. Bind evidence to solc, optimizer settings, EVM version, dependency hashes, source commit, fuzz seed, and fork state. Use native build settings. Check the actual release output; Foundry's [output-channel document](https://github.com/foundry-rs/foundry/blob/master/docs/dev/output-channels.md) includes migration details, so avoid parsing human text as the sole interface.

**Slither:** `slither . --json report.json` is a useful integration entry point. Parse detector identity, impact, confidence, source mapping, and analysis errors. Its `success` field describes execution. See the [JSON output documentation](https://github.com/crytic/slither/wiki/JSON-output).

**Halmos:** use `--json-output PATH`, then parse per-test outcomes. Current source distinguishes pass, counterexample, timeout, stuck, all-paths-revert, and exception. Preserve models, path counts, and bounded-loop information. Current configuration includes loop bounds, invariant depth, selected dynamic-data lengths, and panic-code selection. Defaults primarily check assertion panics; additional panic codes can be requested. Treat defaults as implementation details to override and record explicitly. [Result types](https://github.com/a16z/halmos/blob/main/src/halmos/__main__.py), [configuration](https://github.com/a16z/halmos/blob/main/src/halmos/config.py)

**Echidna/Medusa:** start through stable CLI interfaces and persisted corpora. Avoid making the MVP depend on experimental agent/MCP APIs. Medusa's reporting includes coverage and experimental revert JSON; its Go API can change, and campaigns need explicit duration/test limits. [Medusa reporting](https://secure-contracts.com/program-analysis/medusa/docs/src/testing/reporting.html)

**SMTChecker/deeper provers:** distinguish properties proven, violated, unproved, unsupported, and unchecked. A compiler/prover process returning normally is insufficient. Generated assumptions can make a property vacuous; include reachability/non-vacuity checks and review assumption changes. [SMTChecker](https://docs.solidity.org/en/latest/smtchecker.html), [Certora sanity checks](https://docs.certora.com/en/latest/docs/prover/checking/sanity.html)

### Toolchain compatibility spike

Before committing release pins, run one representative supported repository through native build, baseline Forge tests, Slither, a Halmos pass, a Halmos counterexample, a timeout, and an all-paths-revert case. Repeat a known concrete replay from fresh state. Confirm equivalent outputs inside the proposed execution environment. Check invalid generated tests and dependency/build failures too.

Record a compatibility matrix with engine version, solc version, runner image digest, OS/architecture, and accepted output schema. Upgrade engines independently only after those fixtures pass. This is meaningful adapter validation, not a request to run the full target protocol audit suite on every documentation change.

## 2. Application and model layer

| Component | Choice | Why |
|---|---|---|
| Language | Python 3.12 initially | Aligns with Python tooling while staying easy to package; pin a supported patch release at implementation. |
| Dependency management | [`uv`](https://docs.astral.sh/uv/) | Locked Python environments and distribution tooling. |
| CLI | [Typer](https://github.com/fastapi/typer), MIT | Typed command interface. |
| Schemas | [Pydantic](https://github.com/pydantic/pydantic), MIT | Validate requests, results, and versioned evidence manifests. |
| Run storage | Standard-library SQLite plus artifact directory and JSONL event log | Resume finite workflows; no server database required. |
| Anthropic | [Official Python API SDK](https://github.com/anthropics/anthropic-sdk-python), MIT | Direct provider integration. |
| OpenAI | [Official Python API SDK](https://github.com/openai/openai-python), Apache-2.0 | Direct provider integration. |
| Orchestration | Explicit application state machine | Fewer implicit retries/handoffs; easier budget and evidence accounting. |

The current provider documentation supports schema-constrained/Pydantic-parsed output. Use this for formatting, then independently validate file references, commands, and claims. Handle refusal, truncation, retry, and invalid output paths. The application owns budgets even when an SDK has built-in retries. [OpenAI structured outputs](https://developers.openai.com/api/docs/guides/structured-outputs), [Anthropic structured outputs](https://platform.claude.com/docs/en/build-with-claude/structured-outputs), [OpenAI SDK retries](https://github.com/openai/openai-python#retries)

Implement one small provider interface carrying model ID, request ID, usage, stop reason, parsed response, and raw response reference. Start evaluation with one strong model from one provider, then compare a second provider after the pipeline is stable. Choose the default based on cost, accepted evidence, and latency. Do not assume which current model wins before running the same tasks.

Set application limits on total calls, tokens, expected dollar cost, CPU, memory, disk, tool count, and wall time. Reserve expected cost before concurrent requests. Count verification, retries, and unsuccessful attempts. Timed-out API requests may still incur charges; account conservatively and expose uncertainty. The policy bounds issued work rather than guaranteeing an exact invoice.

Defer agent frameworks, vector search, and multi-provider routing beyond simple adapters. The [OpenAI Agents SDK](https://github.com/openai/openai-agents-python) is an MIT-licensed option if richer workflow needs emerge. The [Claude Agent SDK](https://code.claude.com/docs/en/agent-sdk/overview) involves a Claude Code runtime and separate terms; the direct API SDK is the cleaner initial dependency for this product design.

## 3. Existing audit agents and harnesses

| Project | What to reuse or learn | Decision |
|---|---|---|
| [Pashov skills](https://github.com/pashov/skills), MIT | Threat modelling, specialist audit workflow, fuzz-harness generation | Strong specialist baseline; inspect individual skills and preserve their real structure in comparisons. |
| [Anthropic defending-code reference harness](https://github.com/anthropics/defending-code-reference-harness), Apache-2.0 | Separation of discovery, fresh reproduction, deduplication, reporting, and patch verification; selected execution utilities | Pin and selectively adapt after a port spike. It is unmaintained and centered on C/C++/ASAN; its complete runtime is not the proposed Solidity product architecture. |
| [Anthropic security-review Action](https://github.com/anthropics/claude-code-security-review), MIT | PR integration and developer presentation | Integration reference. Its documented prompt-injection limitations matter for arbitrary PRs. |
| [Certora AutoProver](https://github.com/Certora/AutoProver), GPL-3.0 | Automatic specification/harness construction and prover-feedback loops | Study to understand current capability and differentiation; do not reimplement its entire platform. |

The defending-code harness is likely the general-code project recalled in the earlier discussion. Its current README uses gVisor for autonomous execution unless overridden. Its architecture is a better reference for independent evidence checking than a report-only audit prompt. SCONE serves a separate benchmark role.

### Defending-code source inspection and reuse decision

Inspected upstream revision: [`d3bea6b5793b5f3d59a75ebe69a58efa88383145`](https://github.com/anthropics/defending-code-reference-harness/tree/d3bea6b5793b5f3d59a75ebe69a58efa88383145). This was read-only source inspection. No upstream runtime was installed, executed, or copied into our product.

**Decision:** selectively adapt vetted utilities and workflow patterns under our own provider, target, evidence, and verification contracts. Preserve upstream license/notices and commit provenance for copied material. A full fork may be useful as a research comparison, but would introduce runtime and correctness assumptions we would immediately need to change.

| Upstream source | Reuse candidate | Necessary change or constraint |
|---|---|---|
| [`docker_ops.py`](https://github.com/anthropics/defending-code-reference-harness/blob/d3bea6b5793b5f3d59a75ebe69a58efa88383145/harness/docker_ops.py), [`sandbox.py`](https://github.com/anthropics/defending-code-reference-harness/blob/d3bea6b5793b5f3d59a75ebe69a58efa88383145/harness/sandbox.py) | Container lifecycle, resource limits, mounts, transfer, cleanup, runtime checks | Test our images and separate credential-holding coordination from target execution. |
| [`recon.py`](https://github.com/anthropics/defending-code-reference-harness/blob/d3bea6b5793b5f3d59a75ebe69a58efa88383145/harness/recon.py) and stage structure | Divide investigation into meaningful focus areas; checkpoint discovery, validation, reporting, and repair | Use protocol roles/accounting/transitions; start with one discovery worker. |
| [`prompts/untrusted.py`](https://github.com/anthropics/defending-code-reference-harness/blob/d3bea6b5793b5f3d59a75ebe69a58efa88383145/harness/prompts/untrusted.py) | Delimiting and sanitizing target-derived prompt text | Prompt hygiene is useful, but does not enforce tool privileges or prevent all prompt injection. |
| [`config.py`](https://github.com/anthropics/defending-code-reference-harness/blob/d3bea6b5793b5f3d59a75ebe69a58efa88383145/harness/config.py), [`artifacts.py`](https://github.com/anthropics/defending-code-reference-harness/blob/d3bea6b5793b5f3d59a75ebe69a58efa88383145/harness/artifacts.py) | Explicit configuration and artifacts between stages | Replace binary paths and crash artifacts with source/build/fork metadata, reviewed properties, transactions, and validated state changes. |
| [`asan.py`](https://github.com/anthropics/defending-code-reference-harness/blob/d3bea6b5793b5f3d59a75ebe69a58efa88383145/harness/asan.py) and memory-corruption prompts | General principle of normalizing evidence for deduplication | Replace detector/parsing/rubrics; Solidity reverts are not inherently findings and successful transactions can violate accounting rules. |

The actual [`agent.py`](https://github.com/anthropics/defending-code-reference-harness/blob/d3bea6b5793b5f3d59a75ebe69a58efa88383145/harness/agent.py) invokes headless Claude Code through `docker exec`; it does not use the Claude Agent SDK or direct provider API. Preserve our direct Anthropic/OpenAI adapters and budgeted state machine. A Claude Code integration, if evaluated, has its own runtime dependency and should be labeled accordingly.

There is no generic detector-plugin interface to enable with a Solidity flag. The customization touches configuration, artifacts, prompts, image construction, grading, and signatures. Its [`agent_image.py`](https://github.com/anthropics/defending-code-reference-harness/blob/d3bea6b5793b5f3d59a75ebe69a58efa88383145/harness/agent_image.py) creates a GCC-based agent image and copies the target's `/work`; installing Foundry elsewhere in a target image alone would not reliably include it in the agent image. Build an explicit Solidity tool image.

**Verification differences:** [`grade.py`](https://github.com/anthropics/defending-code-reference-harness/blob/d3bea6b5793b5f3d59a75ebe69a58efa88383145/harness/grade.py) starts a fresh environment but accepts a model-generated verdict marker. Retain fresh replay; compute our execution verdict from a protected checker and validated EVM/tool outcomes. A model can interpret severity and relevance after that. An agent-authored assertion is not automatically a trusted outcome check.

In this inspected revision, [`patch_grade.py`](https://github.com/anthropics/defending-code-reference-harness/blob/d3bea6b5793b5f3d59a75ebe69a58efa88383145/harness/patch_grade.py) can classify a re-attack as clean when no crash artifact is returned without using the returned agent status to distinguish incomplete execution. `PatchVerdict.passed` also permits missing/skipped optional checks. Our adaptation must expose each required check's completion and preserve an inconclusive result on failed searches. This is a specific source-level integration concern, not a claim that the upstream pipeline always misgrades fixes.

**Isolation differences:** the reference agent and target share a container in which model credentials are available; image builds use network access. Its documented gVisor/egress controls remain useful, but do not replace our separate coordinator and restricted build/verification workers. [Pinned sandbox documentation](https://github.com/anthropics/defending-code-reference-harness/blob/d3bea6b5793b5f3d59a75ebe69a58efa88383145/docs/agent-sandbox.md), [security documentation](https://github.com/anthropics/defending-code-reference-harness/blob/d3bea6b5793b5f3d59a75ebe69a58efa88383145/docs/security.md)

**Port gate:** one pinned Solidity fixture must produce a meaningful reproduction, replay from clean state, reject fabricated privilege/state, distinguish duplicates, validate the fixed implementation without changing the requirement, and mark timeouts/failed searches incomplete. Compare implementation complexity and evidence quality with the minimal direct-API runner before retaining larger upstream modules. Timebox the spike within the first two weeks; it must not become a prerequisite to finishing the entire upstream fork.

### Intent-to-formal-verification backend choice

Use a reviewed intent record to generate Solidity properties and explicit assumptions, then run Halmos as the first backend. This keeps formal and adversarial checks close to the partner's existing Foundry workflow. Review the meaning of each property using allowed/forbidden scenarios and an independent reference model before interpreting solver outcomes.

AutoProver is a whole agent pipeline; Certora Prover is the verification backend. The former's orchestration, PostgreSQL/RAG components, model dependency, and deployment choices would enlarge the initial product. Evaluate AutoProver as a formal-task specialist baseline. Add a direct CVL/Certora adapter when a pilot requires inductive reasoning over arbitrary transaction histories or richer modeling and the selected properties can support that proof. [AutoProver documentation](https://github.com/Certora/AutoProver), [Certora invariant semantics](https://docs.certora.com/en/latest/docs/cvl/invariants.html)

The first pilot should deliver approximately five reviewed protocol-specific properties, corresponding adversarial scenarios, and durable CI results. This is a proposed scope target. Property generation, semantic acceptance, proof completion, and attack validation are separate outcomes. Certora's Aave case study illustrates this: AutoProver identified and formalized share-price monotonicity but did not complete that proof within budget, while proving a related solvency floor. [Official case study](https://www.certora.com/blog/autoprover-aave-v4-hub-formal-verification)

### Adversarial testing tools

For contracts, use Forge scenario tests and handler-based stateful invariants, guided by Slither and the discovery agent. Use Anvil block-pinned local forks when dependencies require historical chain state. Target authorization, accounting, callbacks/token behavior, lifecycle ordering, oracle assumptions, and availability under the documented conditions. The attack family must match the partner module; this list is not a coverage guarantee. [Foundry invariant testing](https://getfoundry.sh/forge/invariant-testing), [Anvil](https://www.getfoundry.sh/anvil/index.html)

Record which calls and state transitions actually occurred. An all-reverting fuzz campaign can miss meaningful behavior; a passing campaign with no useful exercised transitions is a coverage gap. Preserve sequences and seeds for deterministic replay. Scheduled deeper campaigns supplement short PR regressions.

If the requested penetration-testing scope includes surrounding applications, keep a separate adapter with the same intent/threat/evidence schema:

| Optional tool | Appropriate scope | License and decision |
|---|---|---|
| [ZAP Automation Framework](https://www.zaproxy.org/docs/automate/automation-framework/) | Authenticated staging web/API tests, including imported API descriptions | [Apache-2.0 core](https://github.com/zaproxy/zaproxy). First optional dynamic application adapter. |
| [Nuclei](https://github.com/projectdiscovery/nuclei) | Selected known-vulnerability and configuration checks against explicit assets | MIT engine. Add curated, pinned templates only when needed; avoid generated/code-executing templates in the MVP. |
| [Semgrep](https://github.com/semgrep/semgrep) | Static checks of surrounding backend/frontend source | LGPL-2.1 engine. Semgrep-maintained rules have a [separate restrictive license](https://semgrep.dev/legal/rules-license/); inspect rules separately. This is static analysis, not runtime penetration testing. |

Application testing should target explicitly authorized staging systems with synthetic accounts, test data, a request budget, and reset procedures. Use a narrow application-specific case such as cross-account authorization before broadening scope. ZAP's baseline scan is passive after crawling; API scans can perform active tests. [ZAP scan modes](https://www.zaproxy.org/docs/docker/about/)

These optional application tools do not replace contract-specific economic testing. Their outputs can share reporting and workflow infrastructure while retaining different execution semantics.

## 4. CI, execution isolation, and reporting

Package a versioned CLI and tool image. Bind Action references to full SHAs and images to digests. The controller mediates provider calls; target execution receives no API credentials, wallet keys, GitHub write token, or host Docker socket. Dependency retrieval is a separate restricted phase. A forked-chain test may need a narrowly scoped RPC proxy; ordinary local tests should not require a mainnet API key.

Use fresh workers with strict resource budgets. Validate gVisor compatibility; container packaging alone is not a complete boundary for untrusted repositories. GitHub-hosted Linux runners provide fresh VMs, but secrets still need separation from target-code execution within the job. Persistent self-hosted runners are inappropriate for arbitrary customer PRs without further isolation. [gVisor](https://gvisor.dev/docs/), [GitHub runner model](https://docs.github.com/en/actions/reference/runners/github-hosted-runners)

For the first Action, trusted in-repository changes can use the configured model; fork PRs run deterministic checks without ordinary model secrets. Later privileged scans require a fixed-commit trusted workflow and isolated worker. Load policy from the trusted base revision. The publisher validates artifact schemas, size/path constraints, and run/commit binding before rendering results. It must not execute artifact content. [GitHub workflow events](https://docs.github.com/en/actions/reference/workflows-and-actions/events-that-trigger-workflows), [secure-use guidance](https://docs.github.com/en/actions/reference/security/secure-use)

Canonical reports are JSON plus Markdown and downloadable reproduction bundles. SARIF 2.1.0 is a secondary view with stable fingerprints/rule IDs. Public GitHub repositories support code scanning; private/internal organizational repositories require appropriate GitHub Code Security access. Preserve useful reporting without SARIF. [SARIF upload documentation](https://docs.github.com/en/code-security/how-tos/find-and-fix-code-vulnerabilities/integrate-with-existing-tools/upload-sarif-file)

## 5. Data sources and permissible claims

| Source | Use | Constraint |
|---|---|---|
| [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs) | Historical reproduction patterns and candidate cases | Existing exploits are answers; withhold them from discovery. Inspect each fixture's provenance and redistribution rights. |
| [SCONE-bench](https://github.com/anthropics/scone-bench) | First external benchmark: smoke task, frozen 20-task pilot, reference-agent comparison using official grading | Historical exploit success is different from ordinary PR-review usefulness. Public tasks can be memorized; repository is unmaintained. Archive RPC and source/model access are prerequisites. |
| [EVMbench](https://github.com/paradigmxyz/evmbench) and its [introduction](https://openai.com/index/introducing-evmbench/) | Detection, repair, and exploitation evaluation practices | Distinguish the UI from its underlying evaluation harness; known-finding labels are incomplete ground truth for novel discoveries. |
| [SmartBugs Curated](https://github.com/smartbugs/smartbugs-curated) | Basic vulnerability taxonomy and smoke tests | Small curated examples do not establish protocol audit quality. |
| [Damn Vulnerable DeFi](https://github.com/theredguild/damn-vulnerable-defi) | Educational examples and setup validation | Deliberately vulnerable, widely published tasks are unsuitable as the sole customer-quality evidence. |
| Permissioned pilot PRs | Prospective workflow and reviewer evaluation | Separate operational use, publication, redistribution, and training permissions. |

Use the smallest dataset needed to reject a weak product hypothesis, then add prospective cases. Do not make collecting a giant historical exploit corpus the first product milestone.

## 6. Licensing and packaging decision

Propose Apache-2.0 for original core code, accompanied by contribution provenance and notices. Foundry is permissively licensed; several recommended analysis/proof engines are AGPL-3.0, and some later engines are GPL-3.0. Keep integrations explicit, publish a component/license inventory, and examine the actual combined distribution before releasing bundled images. Tool subprocess boundaries do not by themselves settle licensing questions.

Distribution and integration must respect dependency licenses and customer artifact permissions. Existing public code licenses and separately negotiated customer rights continue to matter. Avoid importing code with missing or noncommercial licenses into the permissive core merely because its repository is public.

## 7. Unresolved by documentation research

- Compatibility, resource consumption, and gVisor behavior of the chosen release combination.
- Which model provides the best accepted-evidence rate per dollar on these specific tasks.
- Whether generated assumptions and fixtures survive expert review on partner code.
- The installation and maintenance burden on real private repositories.
- Whether retained regression checks save enough reviewer time to sustain use.

These are the first experiments and pilot measurements. No installation, tool execution against contracts, paid model call, or benchmark result is represented as completed here.
