# Experiment tracker

Last updated: 2026-10-18 for the one-week standalone audit MVP; source research remains dated 2026-10-07. All experiments are **planned**. No contract tool runs, paid model calls, benchmark results, or partner studies were completed during this documentation work.

Deliver the full open-source, manually initiated audit workflow in seven days with one SDE and multiple AI implementation agents; SDE review/integration controls release. Week one supports one pinned Solidity/Foundry compatibility baseline/repository layout, one provider/model adapter, and existing Slither/Foundry plus a selected bounded Halmos path. Teams can supply compatible local repositories/scopes without product-code edits or founder-authored project harnesses. The representative accounting/authorization vulnerable/fixed module is an acceptance fixture; a separate compatible repository checks onboarding/portability. Accounting/authorization in vaults, staking, and DEX modules remains the broader domain direction. Deliver scope/intake, architecture/threat model, reviewed requirements, static and adversarial/formal results, independently validated evidence, and severity/remediation reports; supplied-fix retest is a required capability and optional per audit when no fix is supplied. Diffs are optional context. CI, GitHub Actions, PR gates, scheduled regression integration, SARIF, and CI-retention metrics are post-MVP.

| ID | Experiment | Release classification | Status | Required inputs | Results/artifacts | Decision |
|---|---|---|---|---|---|---|
| E0 | Critical execution/evidence integrity and audit intake/export fixtures | Week-one essential | Planned | Small deterministic fixtures; scope/report contracts; pinned tools/VM environment; protected checker | None | Day-7 gate pending |
| E1 release | One meaningful reviewed property | Week-one essential | Planned | One accounting/authorization requirement; allowed/violating scenarios; assumptions/non-vacuity checks; selected Halmos path | None | Day-7 gate pending |
| E2-0 | Complete supported-scope audit, discovery, fresh replay/report, and supplied-fix retest | Week-one essential | Planned | Pinned scope/environment; working provider; hidden bug/repair during discovery; frozen property; budgets | None | Day-7 gate pending |
| E2-U | Clean-install/open-source onboarding and separate-repository portability smoke | Week-one essential | Planned | Clean install; own provider key; separate compatible Foundry repo; standard config; quickstart/sample report; license/notices; pinned image | None | Day-7 gate pending; no SDE intervention |
| E2-A smoke | First external SCONE smoke | Access-dependent in week one; not a release blocker | Planned | Archive/source/model access; pinned benchmark and limits | None | Record blocked if unavailable |
| E1 full | Eight-packet intent translation/property study | Post-release research | Planned | Eight reviewed intent packets; hidden semantic checks; comparator adapters | None | Pending |
| E2-A pilot | Frozen 20-task SCONE comparison | Post-release; first external benchmark | Planned | Smoke passed; access; fixed manifest/model/limits; reference and product agents | None | Pending |
| E2-B | 24-case product audit and supplied-fix retest study | Post-release research | Planned | 12 bug/fix pairs; 12 controls; frozen split; scope/threat-model/intent packets; baseline adapters | None | Pending |
| E2-C | Current well-known protocol audit | Post-release, after SCONE benchmark gate | Planned | One pinned supported module/deployment; scope/threat-model/intent; campaign budget; disclosure route | None | Pending |
| E3 | Reviewer effort and prospective audit delivery | Post-release; required before customer-savings claims | Planned | Two reviewers; permissions; three pilot organizations with supported scopes | None | Pending |
| E4 | Mechanism/provider robustness | Post-release, conditional | Planned | Positive stable signal; frozen configurations; additional budget | None | Pending |

The day-7 release decision uses E0, E1 release, E2-0, and E2-U, including all seven approved workflow capabilities and immediate use from a clean install on team-provided compatible code. It demonstrates narrow compatibility, usability, and evidence integrity, not broad audit quality or customer savings. Larger studies, a second provider, extra engines, and a larger harness port cannot block release. The local fixture and separate-repository smokes are required; unavailable external SCONE access is recorded honestly. Keep the external order SCONE first, then the current-protocol campaign. Require no hosted product account; users bring their own provider key.

## Run record template

| Field | Value |
|---|---|
| Run/task/split IDs | |
| Week-one release check or post-release study | |
| Date and operator | |
| Scope manifest, supported domain, and optional diff context | |
| Code/intent/dependency hashes | |
| Architecture, threat-model, and reviewed-requirement versions | |
| Tool versions and image digest | |
| Model/configuration and repetition seed | |
| Baseline or product configuration | |
| Requested limits; actual inference/CPU usage | |
| Completion and stop reason | |
| Property semantics and assumptions | |
| Allowed/forbidden scenario outcomes | |
| Engine result and proof bounds | |
| Declared scope examined; completed/blocked/unsupported checks | |
| Independent replay and supplied-fix retest outcome/revision | |
| Severity, separate evidence status, and remediation | |
| Report completeness/acceptance and subsequent audit/retest requests | |
| Reviewer minutes and adjudication | |
| Report/evidence bundle, reusable tests/properties, and logs | |
| Failure category and next decision | |

Keep completed failures, unsupported cases, invalid setups, and incomplete runs in versioned manifest/JSONL checkpoints and immutable artifact directories; SQLite is post-release. Link immutable artifacts rather than replacing previous results. Record any protocol-family overlap or suspected answer leakage before interpreting scores. Use the [experiment plan](EXPERIMENT_PLAN.md) for frozen denominators, budgets, and gates; exporting reusable checks does not require CI adoption, and a full workflow does not establish comprehensive security.
