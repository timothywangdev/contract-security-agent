# MVP evidence and experiment plan

Date: 2026-10-07. Status: planned, not executed. Supports the [master plan](MASTER_PLAN.md). Numerical thresholds and resource limits below are proposed decision targets, not measured results or authorization to spend.

User-selected sequence: benchmarks first, then investigation of one current well-known protocol module. SCONE is the first external exploit benchmark. Formal-specification evaluation and customer-workflow evaluation remain necessary complementary tracks.

## 1. Claims to test

| ID | Primary claim | Minimum convincing evidence |
|---|---|---|
| C1 | The workflow reduces expert work needed to resolve security questions at comparable observed issue coverage. | Timed, independently adjudicated reviews, including setup, property corrections, false positives, and incomplete cases; prospective use on partner PRs. |
| C2 | The workflow produces more reliable evidence grounded in intended behavior per aggregate compute budget. | Faithful properties, realistic adversarial evidence, and correct repair discrimination against strong matched baselines; failures and costs included. |

The anti-claim: existing CI or a well-prompted general/specialist agent produces equally usable results at similar total cost, while the proposed product adds specification review, setup, and maintenance work. We should be willing to accept this result and narrow or change the product.

We are not testing claims of comprehensive security, elimination of external audits, or automatic discovery of all intended requirements. A small pilot cannot establish statistical noninferiority on rare severe vulnerabilities.

Proposed progress targets: at least 25% lower median active reviewer time in the small pilot, with no observed increase in missed adjudicated high-severity issues; and at least a 20 percentage-point increase in the primary C2 endpoint below over the strongest applicable matched baseline. Report sample sizes and uncertainty. An observed improvement below these targets can still inform a narrower product; thresholds are not scientific constants.

Preselect **accepted reproduction rate per adjudicated reproducible issue** as the primary C2 endpoint. Fix that eligible-issue set before running systems; missed issues and incomplete attempts remain in the denominator. Report accepted semantic formalizations per eligible intent task and correct repair discrimination per bug/fix pair as separate secondary rates. Do not pool them into one score. Newly discovered issues get independent adjudication and a separate supplementary result, rather than changing a system's denominator after the fact.

## 2. Tasks and datasets

Prepare **12 real bug/fix pairs plus 12 control review cases** across at least six repositories in three protocol families. That is 24 review cases and 36 primary target snapshots: vulnerable and repaired targets for each pair, plus one target per control. Base revisions needed for diff reconstruction are additional inputs. Control means no known in-scope issue after the specified review, not proof of absence of vulnerabilities.

Use two families for development and reserve one complete family for a first held-out check. Keep protocol lineages, forks, related bugs, and both sides of each repair in the same partition. Aim for eight bug/fix pairs plus eight controls in development and four pairs plus four controls held out. This is an engineering feasibility dataset; its small held-out portion cannot substantiate broad audit-quality claims.

Add **eight reviewed intent packets** drawn from those protocol families where possible. Each contains a natural-language requirement, actors, assumptions, legitimate scenarios, prohibited scenarios, and an expert reference interpretation. Use six for development and two from the held-out family. Keep some semantic checks hidden from the translation agent.

For discovery evaluation, prepare agent-visible requirements and threat models from pre-finding documents or through reviewers blinded to the target vulnerability. Keep bug-specific forbidden examples, violating variants, and post-finding clarifications evaluator-only. Record who prepared each packet and what they knew. If a requirement was tailored after seeing the bug, label the task intent-guided detection or supplied-scenario testing; do not count it as autonomous discovery.

Formalization must be scored against both allowed and forbidden behavior. Include evaluation fixtures covering wrong units/actors, weak properties, overly strong properties, vacuity, and unsupported assumptions. Deliberately broken specifications test the evaluator; generated specifications test the generator. Report these separately.

Sources: [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs) for reproduction candidates, [SCONE](https://github.com/anthropics/scone-bench) for fork/grading patterns, [EVMbench](https://openai.com/index/introducing-evmbench/) for detect/repair/exploit task design. [SmartBugs](https://github.com/smartbugs/smartbugs-curated) and [Damn Vulnerable DeFi](https://github.com/theredguild/damn-vulnerable-defi) are smoke-test material. Record per-case provenance and rights before redistribution.

Historical public tasks can be memorized. Hide future commits, repair diffs, exploit implementations, audit answers, and grader tests from discovery. Record residual leakage risk; cosmetic renaming does not remove model pretraining exposure. Prospective partner cases provide the stronger later test.

For SCONE, freeze a separate 20-task pilot manifest before tuning, with protocol lineage and task-selection rationale recorded. Designate development and held-out tasks before use and report their results separately. Exclude the smoke task from evaluation. Pin the benchmark revision, task metadata, grader, fork blocks, model, and resource limits. A selected subset is a pilot result, not a full-benchmark score. Overlap with DeFiHackLabs or other datasets must remain visible.

## 3. Baselines and controlled comparisons

Use three baseline families:

1. **Existing CI:** the repository's Foundry tests/fuzz configuration, existing human properties, and Slither. No newly generated AI properties.
2. **General coding agent:** same underlying model, reviewed intent/context, allowed tools, and aggregate budget, prompted to produce and validate findings/properties.
3. **Specialist automation:** a pinned [Pashov workflow](https://github.com/pashov/skills) for adversarial auditing and [AutoProver](https://github.com/Certora/AutoProver) for formal tasks where compatible. They are separate branch-specific comparators, not a combined super-agent.

Preserve a specialist's actual workflow within the budget. Pashov's multi-agent workflow should not be reduced to one weak prompt and presented as the full system. Document any adapter or compatibility exclusions.

Match total inference spending across discovery, formalization, verification, retries, and all agents. Set CPU, wall-time, and tool-call limits too; report actual consumption and any paid prover charges. Compare common semantic outcomes across different proof systems; do not compare unbounded proofs and bounded passes as interchangeable counts. Supplement with a common-engine comparison where practical to isolate orchestration improvements.

Start with one provider/model configuration and one stochastic repetition for debugging. Freeze configuration before evaluating the held-out tasks. Repeat the retained configuration three times if budget permits. A second provider tests robustness later; do not expand every model × tool × prompt combination.

On SCONE specifically, use its reference agent as the initial general-agent baseline, with the same model and aggregate budgets as our workflow. Existing CI is a baseline for product review tasks, not an exploit-generating SCONE competitor. Add a specialist comparison only after a compatible adapter preserves that specialist's actual behavior. Reusing the defending-code harness creates no automatic independent baseline: record exactly which orchestration, prompts, and verifiers differ.

## 4. Core experiment blocks

### E0 — Execution and evidence integrity, must run first

**Purpose:** establish that subsequent measurements are meaningful. Supports C2.

**Tasks:** eight small fixtures covering valid reproduction, invalid privileged setup, source tampering, malformed artifacts, budget exhaustion, bounded symbolic success, an actual counterexample, and vacuous/all-reverting execution. Also smoke-test fork policy and credential isolation before partner installation.

The harness adaptation spike belongs here: exercise a supplied Solidity PoC through a fresh grader, reject an invalid fixture, deduplicate equivalent reports, validate a repair, and retain transcripts and aggregate usage. This verifies the port's execution contract before its autonomous discovery is scored.

**Setup:** pinned source, compiler, tools, worker image, and protected oracle. Start with manually prepared artifacts to isolate the runner from model quality. Run concrete replay from fresh state and verify the source hash again.

**Measurements:** expected classification, replay determinism, completeness reporting, and artifact/commit binding. A realistic exploit claim must survive the allowed attacker-capability model. A property counterexample alone is a different evidence type.

**Pass gate:** every fixture receives its expected classification; no invalid setup is accepted as a validated exploit. Broken isolation, altered source, or an incomplete check reported as success stops comparative evaluation until fixed.

**Planning cost:** approximately 1–2 engineer-days once the basic runner exists; no model spend required for the manual fixtures. Record actual CPU time. Infrastructure construction is separate work in the master plan.

### E1 — Intent translation and property quality, must run

**Purpose:** test whether generated checks preserve meaning. Supports C2.

**Tasks:** eight intent packets, with reference/violating implementations and withheld semantic checks. Compare the product, general agent, and compatible formal specialist; existing properties provide a deterministic reference.

**Metrics:** expert acceptance without semantic edits, correction minutes, allowed-behavior acceptance, forbidden-behavior rejection, vacuity detected, unjustified assumptions, and unresolved requirements. Report compilation and solver completion separately. A property gets no quality credit solely for proving.

**Strength check:** use expert-prepared economic/authorization faults and selected [Gambit mutants](https://github.com/Certora/gambit). Count compile-valid relevant faults separately from compile failures, equivalent/unreachable mutants, and unresolved cases. Treat synthetic faults as specification diagnostics, not novel-vulnerability discoveries.

**Pass/failure interpretation:** useful properties preserve legitimate behavior and reject relevant violations with manageable review. Repeated expert rewrites, circular reference models, or stronger assumptions used merely to obtain green results falsify useful automation for that task class.

**Planning cost:** 8 packets × 3 generating systems × 1 repetition = 24 task runs. An illustrative $5 inference cap per full task gives a $120 initial inference ceiling. This is a proposed experimental cap, not a price estimate; CPU, expert time, and any external prover fees are additional. A cap that prevents a specialist from completing must be reported as such and may require a separately approved larger-budget experiment later.

### E2 — Threat discovery, replay, and repair discrimination, must run

**Purpose:** establish useful discovery and durable evidence. Supports C2 and supplies C1 review material.

**E2-A: SCONE pilot, first external benchmark.** Pass the benchmark smoke task, then run the frozen 20-task manifest against the reference agent and our workflow. Keep the official grading implementation unchanged; report its exploit-success outcome, actual budgets, replay results, and infrastructure/agent failures. Treat any discrepancy with our own evidence checks as a case requiring investigation. One repetition establishes integration; repeat the frozen comparison three times when justified. SCONE evaluates executable exploitation against historical local forks and requires archive RPC, source access, and a configured model provider. [SCONE repository](https://github.com/anthropics/scone-bench)

**E2-B: product discovery and repair cases.** Run the existing bug/fix and control dataset below. This measures evidence usefulness, negative cases, and repair discrimination that a successful-profit benchmark alone does not establish.

**Tasks:** 24 review cases. Discovery agents receive code, reviewed intent, and the threat model, with bug identity and repair hidden. Reveal a candidate repair only after discovery/evidence generation is frozen. Run the same safety property against both versions and legitimate-behavior checks.

**Metrics:** independently adjudicated in-scope issues found/missed; concrete attacks successfully replayed; accepted regression rate; incorrect evidence accepted; clean-control noise; correct vulnerable/repaired discrimination; cost and latency. Score supplied-finding reproduction separately from autonomous discovery.

**Validity:** a safety regression should fail on the vulnerable implementation and pass on the repaired one for the intended reason. Compilation failure, removed functionality, or weakening the property is not a valid repair. Distinguish existing failures from newly introduced issues. Investigate newly discovered findings even when absent from benchmark labels.

**Pass/failure interpretation:** compare usable evidence with the strongest equal-budget baseline. If independent validation removes almost all apparent gains, the discovery loop is producing invalid evidence. Expert-confirmed but unreproduced findings remain in the record with blocked evidence, rather than being counted as false positives automatically.

**Planning cost:** 24 cases × 3 generating systems × 1 repetition = 72 task runs, plus deterministic CI baselines. At the illustrative $5 cap, the initial inference ceiling is $360. Repair and verification model calls are included in the task budget. Record compute separately. Run development cases first; stop before spending on held-out runs if E0/E1 expose fundamental failure.

The SCONE pilot is an additional budget: 20 tasks × 2 systems = 40 full agent-task runs per repetition. At an illustrative $5 inference cap per task, that is $200 for one repetition or $600 for three, excluding the smoke run, compute, archive RPC, and other services. Calibrate feasibility on the smoke/development tasks before freezing limits; a capped-out run remains incomplete. These are arithmetic planning ceilings, not forecasts or approved spending.

**E2-C: current-protocol investigation, after the benchmark gate.** Select one module with reproducible source/dependencies, relevant requirements, and an appropriate disclosure route. Pin current source, deployment configuration, and fork state. Withhold known audit findings during discovery; compare against them only after candidate evidence is frozen. Execute locally and independently adjudicate realism, severity, and novelty. Report search coverage, cost, false positives, and no-finding outcomes; do not assign an unknown real-world bug set a fabricated recall score. Set a distinct campaign budget before execution rather than using an open-ended hunt.

### E3 — Reviewer effort and prospective adoption, must run before product claims

**Purpose:** test C1 and whether users retain the workflow.

**Setup:** two experienced reviewers, balanced assignment and randomized task order. Avoid having the same reviewer see the same underlying case assisted and unassisted. Hide tool identity where practical. Adjudicate issues independently of the system output. Follow three pilot organizations through at least four weeks with relevant changes.

**Metrics:** active minutes per intent/PR/finding, including setup, property repair, debugging, and dismissed noise; reviewer decision accuracy against adjudicated issues; retained properties; reruns on later changes; onboarding time; weekly founder support. Report denominators and missing observations.

**Pass gate:** users accept useful artifacts, save measurable work, and keep the integration active. Proposed 90-day target: three organizations active for four eligible weeks, with two documenting savings and retaining generated checks. An idle repository does not demonstrate retention.

**Planning cost:** reserve reviewer sessions first; compensation and available hours are unknown. Pilot model/compute budgets must be set per organization. No dollar estimate is justified until repository size, frequency, and model configuration are known.

### E4 — Mechanism and robustness checks, conditional

**Purpose:** determine why an improvement occurs and where it fails. Supports C2.

**Setup:** after a stable positive signal, use a small fixed development subset to ablate reviewed intent, assumption/non-vacuity checks, or fresh replay individually. Keep aggregate budgets comparable. Test one second provider; perform three repetitions of retained comparisons if affordable.

**Metrics:** semantic fidelity, invalid-evidence acceptance, accepted regression rate, time, and cost. Expect performance effects to be measured, not assumed. Removing a safety mechanism is an offline controlled experiment, not a customer configuration recommendation.

**Planning cost:** cap the number of combinations before launching. Three repetitions of E1 and the E2-B product cases would have an illustrative $1,440 inference ceiling for one provider; the three-repetition E2-A SCONE pilot adds $600, for $2,040 total at the illustrative per-task limits. The smoke test, current-protocol campaign, CPU, reviewers, and external services are additional. A second-provider comparison adds only the selected supported tasks; prefer selected comparisons over a full matrix.

## 5. Artifact and measurement rules

Persist run ID, task/split ID, source and dependency hashes, intent version, model ID/configuration, prompt/harness hashes, tool versions, seeds, requested limits, actual usage, stop reason, assumptions, proof bounds, original logs, and reviewer decisions. Never overwrite a prior result when resuming a run.

Separately report:

- Translation quality versus proof completion.
- Bounded verification versus testing without a failure.
- Property counterexample versus validated exploit.
- Tool failure or budget exhaustion versus a completed negative result.
- Expert-confirmed issue versus independently replayed evidence.
- Historical benchmark performance versus prospective customer outcomes.

The generator must not modify the protected grading oracle, target implementation, or hidden semantic checks. Accepted property changes get a versioned semantic diff. Fresh replay validates execution feasibility; independent allowed/forbidden scenarios validate the specification's meaning. Both are needed.

## 6. Order and stopping rules

Run E0, then E1 development tasks and E2-A benchmark integration. Complete the frozen SCONE pilot and review evidence integrity, costs, and failures before E2-C current-protocol investigation. Run E2-B product cases and frozen held-out intent/repair evaluations before making customer-quality claims. E3 follows with prospective reviewers and partners; E4 follows a stable signal. Partner preparation can proceed during engineering without starting a parallel current-protocol hunt.

Stop a run at its configured budget and retain an incomplete outcome. Stop expanding the experiment matrix when the main hypothesis is falsified; diagnose the failure category before rerunning. Do not repeat tests merely to find a favorable seed. Preserve all completed and failed runs in the tracker.

Intent-formalization and specification-strength evaluation have prior art. [Microsoft intent-formalization](https://github.com/microsoft/intent-formalization) and [FAST](https://cs.uwaterloo.ca/~m285xu/assets/publication/fast-paper.pdf) are relevant references. The project's claim is useful implementation and measured improvement in this workflow, not invention of these evaluation concepts.
