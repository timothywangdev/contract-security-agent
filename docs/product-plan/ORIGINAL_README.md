# Contract Security Agent

An open-source project for end-to-end smart contract security audits: point it at your supported Solidity/Foundry project, understand the protocol, discover vulnerabilities, validate findings, and produce an actionable report with reproducible evidence.

**Status: research and planning.** This repository currently contains the project plan and tool research. The audit system, CLI, and benchmark runner have not been implemented, and no benchmark results are claimed.

## Planned workflows

- **Scope → protocol understanding:** pin a project snapshot, map contracts, assets, roles, dependencies, and trust boundaries, and establish intended behavior.
- **Analysis → vulnerability discovery:** combine static analysis, code reasoning, stateful fuzzing, adversarial tests, and formal checks of reviewed requirements.
- **Finding → evidence → audit report:** independently validate findings, assess impact and severity, and document remediation, coverage, assumptions, and unresolved questions.
- **Repair → retest:** when a fix is supplied, check it against frozen evidence and legitimate behavior, then export reusable tests and properties.

The MVP is a standalone, manually initiated audit of a team's own compatible Solidity/Foundry repository or module. **Delivery constraint: seven days, one SDE, and multiple AI implementation agents.** Support one documented Foundry compatibility baseline and the complete audit workflow above, with initial emphasis on accounting and authorization. Validate the release on a vulnerable/fixed module and a separate compatible repository. Vaults, staking, and DEX liquidity modules are the intended domain; additional toolchains follow after delivery. CI integration, PR checks, and automated regression scheduling are post-MVP.

The day-seven release must include a pinned installation, a quickstart, sample audit configuration and reports, reproduction instructions, and clear support/analysis limitations. A team uses its own model API key and local source, with no hosted account or project-specific changes to the audit system. The planned CLI and these release materials are not available yet.

## Project documents

| Document | Contents |
|---|---|
| [Master plan](docs/MASTER_PLAN.md) | Agreed audit workflow, scope, seven-day delivery plan, and release criteria |
| [Tool research](docs/TOOL_RESEARCH.md) | Tool choices, licenses, limitations, and Anthropic harness reuse analysis |
| [Experiment plan](docs/EXPERIMENT_PLAN.md) | Claims, baselines, benchmark sequence, metrics, and decision gates |
| [Experiment tracker](docs/EXPERIMENT_TRACKER.md) | Planned experiments and the run-record template |

## Initial technical direction

Integrate Foundry for execution and fuzzing, Slither for static analysis, and Halmos for selected bounded symbolic checks. Use the defending-code harness as a workflow reference; a substantial harness port and additional proof engines are outside the delivery week.

Validate the release on a pinned vulnerable/fixed fixture, legitimate-behavior controls, and a clean installation against a separate supported repository. Start external evaluation with SCONE-bench, then investigate a current protocol module on a local deployment or fork. Larger benchmark campaigns and customer studies follow the release; evaluate specification quality and repair correctness separately from exploit benchmark scores.

The proposed application layer is a Python CLI with an `audit` entry point, structured evidence, file-based checkpoints, one model provider, and Markdown/JSON reports with reproduction bundles. Pin dependencies and versions on day one.

## License

Original project material is licensed under [Apache-2.0](LICENSE). Referenced tools and datasets retain their own licenses. No third-party harness or verification-engine source has been incorporated into this repository.
