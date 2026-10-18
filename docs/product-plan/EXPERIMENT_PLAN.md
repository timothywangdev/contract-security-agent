# MVP evidence and experiment plan

Research date: 2026-10-07. MVP scope updated: 2026-10-18. Status: planned, not executed. Supports the [master plan](MASTER_PLAN.md). Numerical thresholds and resource limits below are proposed decision targets, not measured results or authorization to spend. This scope revision does not refresh the dated source research.

Delivery constraint: finish the MVP in **seven days with one SDE and multiple AI implementation agents**. The SDE owns scope, integration, review, and release acceptance; AI agents can implement independent adapters, workflow/reporting, and fixtures in parallel. This development team does not require a multi-agent product runtime.

User-selected external evaluation sequence remains SCONE first, then investigation of one current well-known protocol module. Larger benchmark comparisons, formal-specification studies, and customer-workflow studies follow the release; they are not day-7 prerequisites.

The product under evaluation is an open-source, manually initiated, end-to-end audit system that smart contract teams can use immediately on a pinned Solidity/Foundry snapshot: scope/intake, architecture and threat model, reviewed requirements, static analysis, adversarial discovery/fuzzing and formal checks, independent evidence validation, and severity/remediation reporting. Week one supports **one pinned Foundry compatibility baseline/repository layout**, with one working provider/model adapter and existing Slither, Foundry, and a selected bounded Halmos path. Teams supply their own compatible local repository and scope through standard configuration; product-code edits or founder-authored project harnesses must not be required. A representative accounting/authorization vulnerable/fixed module is the acceptance fixture, not the only permitted target. Retesting a supplied fix is a required capability demonstrated for release; a customer audit can finish without an available fix. Audit the whole selected scope by default; a diff is optional context. Vaults, staking, and DEX modules are the initial domain direction as compatibility expands after release. A full workflow does not imply comprehensive security or support for every EVM project.

Export reusable tests/properties with the audit evidence. CI, GitHub Actions, PR gates, scheduled regression integration, and SARIF are deferred beyond the MVP; retaining checks in CI is not an MVP success criterion.

Incomplete intent does not block intake, static analysis, or discovery: record provisional interpretations and unresolved requirements explicitly. Expert acceptance is required before presenting generated properties as validated representations of intended behavior, and all claims remain conditional on their documented assumptions. Every audit produces a report, including when no finding is independently validated.

## 0. Day-7 release gate

Release checks fit inside the seven-day implementation schedule in the [master plan](MASTER_PLAN.md); they are not an additional research phase. Integrate existing tools through a small state machine. Do not fork a large harness, build a new verification engine, add a second provider, or implement specialist-baseline adapters in week one.

The release demonstration must satisfy all of the following:

- Pin one supported target, dependencies/compiler/tool environment, initial requirements/threat model, and explicit inference/tool/CPU/wall-time budgets; retain provenance, logs, usage, and complete/incomplete/blocked states.
- Pass E0's critical evidence-integrity fixtures and E1's one meaningful reviewed property, including legitimate behavior, a relevant violation, non-vacuity, and bounded-result interpretation.
- Run the whole manually initiated audit workflow on the supported scope: intake, architecture/threat model, reviewed requirements/explicit uncertainty, Slither, Foundry adversarial discovery/fuzzing, a selected bounded Halmos check, and independent fresh replay. Exercise autonomous discovery with the bug identity, exploit, and repair withheld; supplied-PoC replay alone does not satisfy discovery.
- Deliver actionable Markdown/JSON reports and reusable reproduction/property artifacts, including a no-validated-findings outcome, scope/coverage gaps, incomplete checks, and separate severity/evidence status. Retest a supplied fix against frozen evidence and legitimate behavior.
- Pass E2-U's clean-install/onboarding smoke: using their own provider key, a reviewer follows the quickstart against a separate compatible Foundry repository, supplies standard scope/requirement configuration, and produces the scoped report/reproduction bundle without SDE intervention, product edits, or founder-authored project harnesses.
- Provide the public open-source release materials: Apache-2.0 core license and dependency notices/inventory, pinned installation/tool image, quickstart, sample configuration/report, and explicit supported compatibility/limitations. Require no hosted product account.
- Smoke-test the supported audit fixture. Attempt an external SCONE smoke only when archive/source/model access is available within the week; record a blocked external smoke when unavailable, without substituting a current-protocol campaign or blocking release.

Day-7 evidence supports a narrow workflow/compatibility demonstration. It does not establish reviewer-time savings, superiority over baselines, benchmark performance, or broad audit quality. Those claims require the later studies below. The frozen 20-task SCONE comparison, 24-case product study, partner pilots, provider comparison, and larger harness adaptation are post-release work.

## 1. Claims to test

| ID | Primary claim | Minimum convincing evidence |
|---|---|---|
| C1 | The audit workflow reduces expert work needed to resolve security questions at comparable observed issue coverage. | Timed, independently adjudicated audits, including intake, threat-model/requirement review, property corrections, false positives, reporting, and incomplete cases; prospective use on partner snapshots. |
| C2 | The workflow produces more reliable evidence grounded in intended behavior per aggregate compute budget. | Faithful properties, realistic adversarial evidence, and correct repair discrimination against strong matched baselines; failures and costs included. |

The anti-claim: existing tools or a well-prompted general/specialist agent produces equally usable audit results at similar total cost, while the proposed product adds specification review, setup, and report-review work. We should be willing to accept this result and narrow or change the product.

We are not testing claims of comprehensive security, elimination of external audits, or automatic discovery of all intended requirements. A small pilot cannot establish statistical noninferiority on rare severe vulnerabilities.

Proposed **post-release research** targets: at least 25% lower median active reviewer time in the small pilot, with no observed increase in missed adjudicated high-severity issues; and at least a 20 percentage-point increase in the primary C2 endpoint below over the strongest applicable matched baseline. They are not day-7 release gates. Report sample sizes and uncertainty. An observed improvement below these targets can still inform a narrower product; thresholds are not scientific constants. Make no customer-savings claim before E3.

Preselect **accepted reproduction rate per adjudicated reproducible issue** as the primary C2 endpoint. Fix that eligible-issue set before running systems; missed issues and incomplete attempts remain in the denominator. Report accepted semantic formalizations per eligible intent task and correct repair discrimination per bug/fix pair as separate secondary rates. Do not pool them into one score. Newly discovered issues get independent adjudication and a separate supplementary result, rather than changing a system's denominator after the fact.

## 2. Post-release tasks and datasets

Week one needs the representative scope/bug-fix fixture, one reviewed requirement, and a separate compatible repository for the onboarding smoke described in section 0. The second repository checks portability of the same baseline, not another protocol campaign. Do not collect the larger dataset below before releasing. Its preparation, comparator runs, and budgets are later evidence work.

Prepare **12 real bug/fix pairs plus 12 control review cases** across at least six repositories in three protocol families. That is 24 review cases and 36 primary target snapshots: vulnerable and repaired targets for each pair, plus one target per control. Select supported accounting/authorization scopes in vaults, staking, and DEX modules. Each case includes the entire declared audit scope; base revisions for optional diff context are additional inputs. Control means no known in-scope issue after the specified review, not proof of absence of vulnerabilities.

Use two families for development and reserve one complete family for a first held-out check. Keep protocol lineages, forks, related bugs, and both sides of each repair in the same partition. Aim for eight bug/fix pairs plus eight controls in development and four pairs plus four controls held out. This is an engineering feasibility dataset; its small held-out portion cannot substantiate broad audit-quality claims.

Add **eight reviewed intent packets** drawn from those protocol families where possible. Each contains a natural-language requirement, actors, assumptions, legitimate scenarios, prohibited scenarios, and an expert reference interpretation. Use six for development and two from the held-out family. Keep some semantic checks hidden from the translation agent.

For discovery evaluation, prepare agent-visible requirements and threat models from pre-finding documents or through reviewers blinded to the target vulnerability. Keep bug-specific forbidden examples, violating variants, and post-finding clarifications evaluator-only. Record who prepared each packet and what they knew. If a requirement was tailored after seeing the bug, label the task intent-guided detection or supplied-scenario testing; do not count it as autonomous discovery.

Formalization must be scored against both allowed and forbidden behavior. Include evaluation fixtures covering wrong units/actors, weak properties, overly strong properties, vacuity, and unsupported assumptions. Deliberately broken specifications test the evaluator; generated specifications test the generator. Report these separately.

Sources: [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs) for reproduction candidates, [SCONE](https://github.com/anthropics/scone-bench) for fork/grading patterns, [EVMbench](https://openai.com/index/introducing-evmbench/) for detect/repair/exploit task design. [SmartBugs](https://github.com/smartbugs/smartbugs-curated) and [Damn Vulnerable DeFi](https://github.com/theredguild/damn-vulnerable-defi) are smoke-test material. Record per-case provenance and rights before redistribution.

Historical public tasks can be memorized. Hide future commits, repair diffs, exploit implementations, audit answers, and grader tests from discovery. Record residual leakage risk; cosmetic renaming does not remove model pretraining exposure. Prospective partner cases provide the stronger later test.

For SCONE, freeze a separate 20-task pilot manifest before tuning, with protocol lineage and task-selection rationale recorded. Designate development and held-out tasks before use and report their results separately. Exclude the smoke task from evaluation. Pin the benchmark revision, task metadata, grader, fork blocks, model, and resource limits. A selected subset is a pilot result, not a full-benchmark score. Overlap with DeFiHackLabs or other datasets must remain visible.

## 3. Post-release baselines and controlled comparisons

Use three baseline families:

1. **Existing tools/baseline:** the repository's Foundry tests/fuzz configuration, existing human properties, and Slither, invoked against the pinned audit scope. No newly generated AI properties; no CI integration is required.
2. **General coding agent:** same underlying model, reviewed intent/context, allowed tools, and aggregate budget, prompted to produce and validate findings/properties.
3. **Specialist automation:** a pinned [Pashov workflow](https://github.com/pashov/skills) for adversarial auditing and [AutoProver](https://github.com/Certora/AutoProver) for formal tasks where compatible. They are separate branch-specific comparators, not a combined super-agent.

Preserve a specialist's actual workflow within the budget. Pashov's multi-agent workflow should not be reduced to one weak prompt and presented as the full system. Document any adapter or compatibility exclusions.

Match total inference spending across discovery, formalization, verification, retries, and all agents. Set CPU, wall-time, and tool-call limits too; report actual consumption and any paid prover charges. Compare common semantic outcomes across different proof systems; do not compare unbounded proofs and bounded passes as interchangeable counts. Supplement with a common-engine comparison where practical to isolate orchestration improvements.

Start with one provider/model configuration and one stochastic repetition for debugging. Freeze configuration before evaluating the held-out tasks. Repeat the retained configuration three times if budget permits. A second provider tests robustness later; do not expand every model × tool × prompt combination.

On SCONE specifically, use its reference agent as the initial general-agent baseline, with the same model and aggregate budgets as our workflow. Existing tools/baseline applies to product audit tasks, not exploit generation in SCONE. Add a specialist comparison only after a compatible adapter preserves that specialist's actual behavior. Reusing the defending-code harness creates no automatic independent baseline: record exactly which orchestration, prompts, and verifiers differ.

## 4. Core experiment blocks

### E0 — Execution and evidence integrity, week-one essential

**Purpose:** establish that subsequent measurements are meaningful. Supports C2.

**Tasks:** eight small fixtures covering valid reproduction, invalid privileged setup, source tampering, malformed artifacts, budget exhaustion, bounded symbolic success, an actual counterexample, and vacuous/all-reverting execution. Also smoke-test fork-state policy and credential isolation before partner audits.

Use tiny deterministic fixtures in the direct runner; reuse existing tools and inspected harness patterns without porting a larger framework. Exercise a supplied Solidity PoC through a fresh checker, reject an invalid fixture, normalize equivalent reports, validate a supplied repair, and retain transcripts and aggregate usage. Exercise manual audit intake and export on these fixtures too: bind the scope manifest, architecture/threat model, reviewed requirements and unresolved assumptions, completed/blocked checks, and severity/remediation report to the pinned target. Include a report with no validated findings and an incomplete-intent intake case. A larger upstream adaptation/comparison, if justified, follows release and must satisfy these same integrity checks.

**Setup:** pinned source, compiler, tools, worker image, and protected oracle. Start with manually prepared artifacts to isolate the runner from model quality. Run concrete replay from fresh state and verify the source hash again.

**Measurements:** expected classification, replay determinism, completeness reporting, and artifact/commit binding. A realistic exploit claim must survive the allowed attacker-capability model. A property counterexample alone is a different evidence type.

**Pass gate:** every fixture receives its expected classification; no invalid setup is accepted as a validated exploit. Broken isolation, altered source, or an incomplete check reported as success stops comparative evaluation until fixed.

**Planning cost:** implement the critical tiny fixtures alongside runner development within the seven-day schedule, with AI fixture work parallel to adapters and SDE review at integration. No model spend is required for the manual integrity fixtures. Record actual CPU time; this work is included in week-one engineering.

### E1 — Intent translation and property quality, release subset then later study

**Purpose:** test whether generated checks preserve meaning. Supports C2.

**Week-one required subset:** one meaningful accounting/authorization requirement on the supported scope, its reviewed Solidity property, legitimate and violating scenarios, explicit assumptions/non-vacuity checks, a selected bounded Halmos pass/counterexample path, and supplied-fix discrimination. SDE review can correct semantics; record corrections and make no translation-quality-rate claim from one property. Freeze accepted semantics before retesting the fix.

**Post-release study:** eight intent packets, with reference/violating implementations and withheld semantic checks. Compare the product, general agent, and compatible formal specialist; existing properties provide a deterministic reference.

**Metrics:** expert acceptance without semantic edits, correction minutes, allowed-behavior acceptance, forbidden-behavior rejection, vacuity detected, unjustified assumptions, and unresolved requirements. Report compilation and solver completion separately. A property gets no quality credit solely for proving.

**Strength check:** week one uses a deliberate relevant fault and legitimate-behavior scenario without a new engine. Post-release, use expert-prepared economic/authorization faults and selected [Gambit mutants](https://github.com/Certora/gambit). Count compile-valid relevant faults separately from compile failures, equivalent/unreachable mutants, and unresolved cases. Treat synthetic faults as specification diagnostics, not novel-vulnerability discoveries.

**Pass/failure interpretation:** useful properties preserve legitimate behavior and reject relevant violations with manageable review. Repeated expert rewrites, circular reference models, or stronger assumptions used merely to obtain green results falsify useful automation for that task class.

**Post-release study cost:** 8 packets × 3 generating systems × 1 repetition = 24 task runs. An illustrative $5 inference cap per full task gives a $120 initial inference ceiling. This is a proposed experimental cap, not a price estimate; CPU, expert time, and any external prover fees are additional. A cap that prevents a specialist from completing must be reported as such and may require a separately approved larger-budget experiment later. Week one's single-property run has its own finite budget within implementation; these 24 runs are not required for release.

### E2 — Threat discovery, replay, and repair discrimination, release subset then later studies

**Purpose:** establish useful discovery and durable evidence. Supports C2 and supplies C1 review material.

**E2-0: supported-scope audit, required by day 7.** Run the complete workflow on the pinned representative fixture with one provider/model and existing tools. Withhold the bug identity, exploit, repair, and hidden outcome checks during discovery; record any unavoidable public-answer exposure. Independently replay a discovered candidate from fresh state, produce the scoped report/evidence bundle, and retest the supplied fix against frozen checks and legitimate behavior. Record any failure or incompleteness honestly. A supplied-finding replay is an E0 integrity check, not a replacement for autonomous discovery. This is a narrow release demonstration, not a novel-vulnerability or broad-quality result.

**E2-U: open-source onboarding/portability smoke, required by day 7.** From a clean clone/install, a reviewer uses their own provider key and the documented CLI/configuration to audit a separate team-provided compatible Foundry repository. Allow normal scope selection and documented requirement review; do not allow product-code edits, SDE intervention, or founder-authored project harnesses. Produce a report/evidence bundle with reproduction commands and honest evidence/coverage/incomplete states, including when no finding is validated. Verify that release materials include the Apache-2.0 core license, dependency notices/inventory, pinned install/tool image, quickstart, sample config/report, compatibility/limitations, and no hosted product account requirement. Record setup steps, failures, and assistance required. This checks immediate usability and portability of the supported baseline; it is neither a new current-known-protocol campaign nor evidence of broad audit quality or measured customer savings.

**E2-A: SCONE, first external benchmark.** An external smoke is access-dependent during week one; missing archive/source/model access is recorded as blocked and does not block the local release gate. After release, pass the benchmark smoke task, then run the frozen 20-task manifest against the reference agent and our workflow. Keep the official grading implementation unchanged; report its exploit-success outcome, actual budgets, replay results, and infrastructure/agent failures. Treat any discrepancy with our own evidence checks as a case requiring investigation. One repetition establishes integration; repeat the frozen comparison three times when justified. SCONE evaluates executable exploitation against historical local forks and requires archive RPC, source access, and a configured model provider. [SCONE repository](https://github.com/anthropics/scone-bench)

**E2-B: post-release end-to-end product audit study and supplied-fix retests.** Run the existing bug/fix and control dataset below through the audit workflow. This measures scope coverage, report/evidence usefulness, negative cases, and repair discrimination that a successful-profit benchmark alone does not establish. The 24-case study is not a release blocker. Supplied-fix retests are required for this evaluation even though a customer audit can finish without a supplied fix.

**Tasks:** 24 review cases. Record intake, scope, architecture, threat model, and reviewed requirements before discovery. Discovery agents receive the whole selected code scope, reviewed intent, and threat model, with bug identity and repair hidden. Run static analysis, adversarial discovery/fuzzing, selected formal checks, independent evidence validation, and report generation. Reveal a supplied repair only after discovery/evidence generation is frozen. Run the same safety property against both versions and legitimate-behavior checks.

**Metrics:** independently adjudicated in-scope issues found/missed; concrete attacks successfully replayed; accepted reproduction rate; incorrect evidence accepted; clean-control noise; correct vulnerable/repaired discrimination; declared scope examined and blocked/unsupported checks; severity/remediation usefulness; report/evidence completeness; cost and latency. Score supplied-finding reproduction separately from autonomous discovery. Assess report completeness against executive summary, scope/methodology, root cause/preconditions/impact/remediation, contract and requirement coverage/gaps, incomplete checks, and reproduction commands; severity and evidence status are separate fields. Report exercised paths and selected property coverage without turning them into a comprehensive-security score.

**Validity:** an exported safety test/property should fail on the vulnerable implementation and pass on the repaired one for the intended reason. Compilation failure, removed functionality, or weakening the property is not a valid repair. Distinguish existing failures from newly introduced issues. Investigate newly discovered findings even when absent from benchmark labels. Exporting a reusable test is evidence delivery; automatic CI adoption is outside this evaluation.

**Pass/failure interpretation:** compare usable evidence with the strongest equal-budget baseline. If independent validation removes almost all apparent gains, the discovery loop is producing invalid evidence. Expert-confirmed but unreproduced findings remain in the record with blocked evidence, rather than being counted as false positives automatically.

**Planning cost:** 24 cases × 3 generating systems × 1 repetition = 72 task runs, plus deterministic tool baselines. At the illustrative $5 cap, the initial inference ceiling is $360. Supplied-fix retest and verification model calls are included in the task budget. Record compute separately. Run development cases first; stop before spending on held-out runs if E0/E1 expose fundamental failure.

The SCONE pilot is an additional budget: 20 tasks × 2 systems = 40 full agent-task runs per repetition. At an illustrative $5 inference cap per task, that is $200 for one repetition or $600 for three, excluding the smoke run, compute, archive RPC, and other services. Calibrate feasibility on the smoke/development tasks before freezing limits; a capped-out run remains incomplete. These are arithmetic planning ceilings, not forecasts or approved spending.

**E2-C: post-release current-protocol investigation, after the external benchmark gate.** Select one supported accounting/authorization module in a well-known vault, staking, or DEX protocol with reproducible source/dependencies, relevant requirements, and an appropriate disclosure route. Pin current source, deployment configuration, and fork state; audit the whole selected module through the end-to-end workflow. Withhold known audit findings during discovery; compare against them only after candidate evidence is frozen. Execute locally and independently adjudicate realism, severity, and novelty. Deliver the scoped audit report and evidence bundle, including assumptions and blocked/unsupported checks. Report search coverage, cost, false positives, and no-finding outcomes; do not assign an unknown real-world bug set a fabricated recall score. Set a distinct campaign budget before execution rather than using an open-ended hunt. This campaign is not a day-7 release prerequisite.

### E3 — Post-release reviewer effort and prospective audit delivery, required before savings claims

**Purpose:** test C1 and whether users accept useful end-to-end audit deliverables.

**Setup:** two experienced reviewers, balanced assignment and randomized task order. Avoid having the same reviewer see the same underlying case assisted and unassisted. Hide tool identity where practical. Adjudicate issues independently of the system output. Run manually initiated audits with three pilot organizations on pinned supported scopes, tracking the whole delivery from intake through accepted report/evidence and any requested supplied-fix retest.

**Metrics:** active minutes per audit/requirement/finding, including intake, architecture/threat-model review, setup, property correction, debugging, dismissed noise, and report review; reviewer decision accuracy against adjudicated issues; scope and report completeness; useful reproduction/property artifacts accepted; onboarding time; operator/founder support; and supplied-fix retest effort when applicable. Report denominators and missing observations. Automated reruns, CI retention, and weekly repository activity are not MVP endpoints.

**Later evidence gate:** users accept useful audit reports/evidence and save measurable work. A proposed post-release pilot target is three organizations completing at least one supported scoped audit each and accepting the report/evidence bundle, with two documenting reviewer-time savings and requesting a subsequent audit or retest. This study has no role in the day-7 release gate or implementation schedule. A completed audit remains useful without ongoing repository integration; distinguish a request for further work from a completed repeat audit/retest. Claim reviewer savings only after measured E3 results support them.

**Planning cost:** reserve reviewer sessions first; compensation and available hours are unknown. Pilot model/compute budgets must be set per organization and audit. No dollar estimate is justified until scope size, requested checks, and model configuration are known.

### E4 — Post-release mechanism and robustness checks, conditional

**Purpose:** determine why an improvement occurs and where it fails. Supports C2.

**Setup:** after a stable positive signal, use a small fixed development subset to ablate reviewed intent, assumption/non-vacuity checks, or fresh replay individually. Keep aggregate budgets comparable. Test one second provider; perform three repetitions of retained comparisons if affordable.

**Metrics:** semantic fidelity, invalid-evidence acceptance, accepted reproduction rate, time, and cost. Expect performance effects to be measured, not assumed. Removing a safety mechanism is an offline controlled experiment, not a customer configuration recommendation.

**Planning cost:** cap the number of combinations before launching. Three repetitions of E1 and the E2-B product cases would have an illustrative $1,440 inference ceiling for one provider; the three-repetition E2-A SCONE pilot adds $600, for $2,040 total at the illustrative per-task limits. The smoke test, current-protocol campaign, CPU, reviewers, and external services are additional. A second-provider comparison adds only the selected supported tasks; prefer selected comparisons over a full matrix.

## 5. Artifact and measurement rules

Persist run ID, task/split ID, scope manifest, source and dependency hashes, architecture/threat-model and reviewed intent versions, model ID/configuration, prompt/harness hashes, tool versions, seeds, requested limits, actual usage, stop reason, assumptions, proof bounds, original logs, and reviewer decisions. Bind severity/remediation decisions, coverage/limitations, report and reusable evidence exports, and any supplied-fix retest to those immutable inputs. Never overwrite a prior result when resuming a run.

Separately report:

- Translation quality versus proof completion.
- Bounded verification versus testing without a failure.
- Property counterexample versus validated exploit.
- Tool failure or budget exhaustion versus a completed negative result.
- Expert-confirmed issue versus independently replayed evidence.
- Historical benchmark performance versus prospective customer outcomes.

The generator must not modify the protected grading oracle, target implementation, or hidden semantic checks. Accepted property changes get a versioned semantic diff. Fresh replay validates execution feasibility; independent allowed/forbidden scenarios validate the specification's meaning. Both are needed.

## 6. Order and stopping rules

Within week one, integrate E0's critical fixtures, E1's single reviewed property, E2-0's complete supported-scope audit/retest, and E2-U's clean-install/separate-repository usability smoke. SDE acceptance of section 0 is the day-7 release decision. Parallel AI implementation work stays within the SDE's review/integration capacity. The access-dependent SCONE smoke cannot replace these local checks or block release because external services are unavailable.

After release, run the larger E1 development study and E2-A external benchmark integration/comparison. Complete the frozen SCONE pilot and review evidence integrity, costs, and failures before E2-C current-protocol investigation. Run E2-B product cases and frozen held-out intent/repair evaluations before making customer-quality claims. E3 follows with prospective reviewers and partners; E4 follows a stable signal. Do not add these research campaigns, a second provider, or a larger harness port to the seven-day implementation critical path.

Stop a run at its configured budget and retain an incomplete outcome. Stop expanding the experiment matrix when the main hypothesis is falsified; diagnose the failure category before rerunning. Do not repeat tests merely to find a favorable seed. Preserve all completed and failed runs in the tracker.

Intent-formalization and specification-strength evaluation have prior art. [Microsoft intent-formalization](https://github.com/microsoft/intent-formalization) and [FAST](https://cs.uwaterloo.ca/~m285xu/assets/publication/fast-paper.pdf) are relevant references. The project's claim is useful implementation and measured improvement in this workflow, not invention of these evaluation concepts.
