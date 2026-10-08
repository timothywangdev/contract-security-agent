# Contract Security Agent

An open-source project for translating smart-contract security requirements into formal properties, adversarial tests, and reproducible evidence that teams can retain in CI.

**Status: research and planning.** This repository currently contains the project plan and tool research. The CLI, integrations, and benchmark runner have not been implemented, and no benchmark results are claimed.

## Planned workflows

- **Intent → formal verification:** turn reviewed protocol requirements into executable properties, preserving assumptions and verification scope.
- **Threat model → adversarial testing:** investigate attack hypotheses and transaction sequences, then validate findings independently.
- **Finding → repair → regression:** validate repairs against frozen checks and retain accepted tests for future changes.

The initial scope is Solidity/Foundry repositories, focusing on accounting and authorization in staking, vaults, and DEX liquidity modules.

## Project documents

| Document | Contents |
|---|---|
| [Master plan](docs/MASTER_PLAN.md) | Product strategy, architecture, scope, and 90-day milestones |
| [Tool research](docs/TOOL_RESEARCH.md) | Tool choices, licenses, limitations, and Anthropic harness reuse analysis |
| [Experiment plan](docs/EXPERIMENT_PLAN.md) | Claims, baselines, benchmark sequence, metrics, and decision gates |
| [Experiment tracker](docs/EXPERIMENT_TRACKER.md) | Planned experiments and the run-record template |

## Initial technical direction

Use Foundry for execution and fuzzing, Slither for static analysis, and Halmos for initial symbolic checks. Evaluate Certora for selected stronger proof obligations. Selectively adapt workflow patterns and vetted utilities from Anthropic's defending-code reference harness.

Start external evaluation with SCONE-bench, then investigate a current protocol module on a local deployment or fork. Evaluate specification quality and repair correctness separately from exploit benchmark scores.

The proposed application layer is a Python CLI with structured evidence, resumable execution, provider adapters, and GitHub Actions integration. Exact dependencies and versions will be pinned after compatibility testing.

## License

Original project material is licensed under [Apache-2.0](LICENSE). Referenced tools and datasets retain their own licenses. No third-party harness or verification-engine source has been incorporated into this repository.
