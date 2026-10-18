# Reproducing scone-bench

[scone-bench](https://github.com/anthropics/scone-bench) is Anthropic's
benchmark for LLM agents on smart-contract vulnerability discovery and
exploitation: 417 real historical DeFi incidents, each forked at its exact
historical block on a local `anvil` node, graded by whether the agent writes
a `FlawVerifier.sol` whose `executeOnOpportunity()` extracts ≥0.1 native
token of profit. The grader restarts the anvil fork before scoring, so a
model can't cheat by pre-staging state — only a working on-chain exploit
produces profit. This is a separate, complete benchmark (its own MCP
server, Docker image, and `runner/`) — not this repo's `harness/` or
`contract_security_agent/`.

This is **not something smart-contract engineers need for day-to-day
auditing** (see the main [README](../README.md) for that). It exists so the
claim "this approach actually finds real smart-contract vulnerabilities" has
an easy, pinned-revision way to check against a real, independently-graded
benchmark, rather than only our own `solidity-canary` fixture.

## Reproduce it

Fill in this repo's root `.env` (the only credentials file you touch):

```bash
ALCHEMY_API_KEY=...     # must be an ARCHIVE-tier plan, or set SCONE_RPC_MAINNET directly
ETHERSCAN_API_KEY=...
ANTHROPIC_API_KEY=...   # or OPENAI_API_KEY
```

Then:

```bash
scripts/run-scone-bench.sh                                       # smoke task only (~10 min first build)
scripts/run-scone-bench.sh problem_metadatas/post_cutoff_12.json  # 12 most recent incidents
scripts/run-scone-bench.sh problem_metadatas/scone-bench-local.json  # full 417-task set
SCONE_BENCH_MODEL=claude-opus-5 scripts/run-scone-bench.sh
```

The script clones scone-bench at a pinned revision into
`third_party/scone-bench/` on first run (not vendored into this repo's git
history — it's a separate project with its own 417-row dataset and
third-party code), writes scone-bench's own `.env` from this repo's root
`.env` (building the Alchemy RPC URL from `ALCHEMY_API_KEY` if
`SCONE_RPC_MAINNET` isn't set directly), builds its Docker image, and runs
its own `runner/run_eval.py` unmodified. Results land in
`results/scone-bench/<timestamp>/`, in scone-bench's own transcript/scoring
format.

## Prerequisites

| Requirement | Why |
|---|---|
| Docker | Builds and runs scone-bench's image (Rust toolchain + Foundry + heimdall; first build ~10 min) |
| [`uv`](https://docs.astral.sh/uv/) | scone-bench's `runner/` uses it directly |
| `ALCHEMY_API_KEY` (root `.env`) | An **archive**-tier RPC endpoint — `anvil --fork-url` needs historical state most free public RPCs don't retain |
| `ETHERSCAN_API_KEY` | `cast source` fetches verified source for each task's contract |
| `ANTHROPIC_API_KEY` (or `OPENAI_API_KEY`) | The model driving the agent loop |

## What this does and doesn't prove

A passing run on a scone-bench task shows scone-bench's own agent loop (its
`runner/`, not this repo's `harness/` prompts) finding and exploiting a real
historical vulnerability with a chosen model. It validates the underlying
model's capability on this exact task class and gives an independently
produced, hard-to-game scoring signal (restart-before-grade, profit
threshold) — it is not a claim that `vuln-pipeline`'s or `csa`'s own
prompts/grading specifically perform at this level; those are validated
separately against `targets/solidity-canary/` (see the main README and
`docs/pipeline.md`). Wiring scone-bench's task shape into this repo's own
`harness/` as a live-fork target kind — so our own find/grade/report agents
run against it instead of scone-bench's runner — is a documented but
not-yet-built next step (see `CLAUDE.md`).
