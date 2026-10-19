#!/usr/bin/env bash
# Copyright 2026 Contract Security Agent contributors
# SPDX-License-Identifier: Apache-2.0
#
# Reproduce Anthropic's scone-bench results from this repo, one command.
#
# This is a thin wrapper, not a reimplementation: it clones scone-bench
# (https://github.com/anthropics/scone-bench) at a pinned revision into
# third_party/scone-bench/ if not already present, builds its own Docker
# image, and runs its own runner/run_eval.py — unmodified. scone-bench is a
# separate, complete benchmark (its own MCP server + runner + 417 real
# historical DeFi incidents forked on anvil, graded by a profit-extracting
# FlawVerifier.sol with a restart-before-grading anti-cheat check); it does
# not use this repo's harness/ or contract_security_agent/ at all. This
# script exists purely so "does this project's approach actually work on a
# real benchmark" has a one-command, pinned-revision answer — see
# docs/scone-bench.md.
#
# Usage:
#   scripts/run-scone-bench.sh                              # smoke task only
#   scripts/run-scone-bench.sh problem_metadatas/scone-bench-local.json  # full 417-task set
#   SCONE_BENCH_MODEL=claude-opus-5 scripts/run-scone-bench.sh
#
# Prerequisites, all read from THIS repo's root .env (not scone-bench's own
# .env — this script writes that one for you):
#   - Docker
#   - uv (https://docs.astral.sh/uv/)
#   - ALCHEMY_API_KEY (must be an ARCHIVE-tier Alchemy plan — free/standard
#     tiers lack the historical state these tasks fork at) or a pre-built
#     SCONE_RPC_MAINNET URL
#   - ETHERSCAN_API_KEY
#   - ANTHROPIC_API_KEY (or OPENAI_API_KEY)
set -euo pipefail

SCONE_BENCH_REVISION="e23cab911996d75fa605633b0bf8891b6a5c4222"
SCONE_BENCH_DIR="${SCONE_BENCH_DIR:-third_party/scone-bench}"
PROBLEMS="${1:-problem_metadatas/smoke-local.json}"
MODEL="${SCONE_BENCH_MODEL:-}"
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

if [ ! -d "$SCONE_BENCH_DIR/.git" ]; then
    echo "Cloning scone-bench @ ${SCONE_BENCH_REVISION:0:12} into $SCONE_BENCH_DIR ..."
    git clone https://github.com/anthropics/scone-bench.git "$SCONE_BENCH_DIR"
    git -C "$SCONE_BENCH_DIR" checkout --quiet "$SCONE_BENCH_REVISION"
else
    current="$(git -C "$SCONE_BENCH_DIR" rev-parse HEAD)"
    if [ "$current" != "$SCONE_BENCH_REVISION" ]; then
        echo "error: $SCONE_BENCH_DIR is at $current, expected the pinned $SCONE_BENCH_REVISION." >&2
        echo "       git -C $SCONE_BENCH_DIR checkout $SCONE_BENCH_REVISION" >&2
        exit 1
    fi
fi

# Pull credentials from THIS repo's root .env and write scone-bench's own
# .env from them, so the root .env is the only file you ever touch.
if [ -f "$REPO_ROOT/.env" ]; then
    set -a
    # shellcheck disable=SC1091
    source "$REPO_ROOT/.env"
    set +a
fi

SCONE_RPC_MAINNET="${SCONE_RPC_MAINNET:-}"
if [ -z "$SCONE_RPC_MAINNET" ] && [ -n "${ALCHEMY_API_KEY:-}" ]; then
    SCONE_RPC_MAINNET="https://eth-mainnet.g.alchemy.com/v2/${ALCHEMY_API_KEY}"
fi

# chain_constants.py's rpc_endpoints() reads one SCONE_RPC_<CHAIN> env var per
# chain the problem set touches (chain names match its chain_ids dict, e.g.
# "bsc", "arbi", "base" — not "bnb"/"arbitrum"/standard chain slugs). Deriving
# only SCONE_RPC_MAINNET left every non-mainnet-chain problem's setup_problem
# unable to start anvil (KeyError on the missing chain), so grading always hit
# "connection refused" against 127.0.0.1:8545 for those problems. Alchemy
# serves all of these chains under the same API key, just a different
# subdomain per chain (verified against each endpoint directly) — derive the
# rest the same way, without clobbering an explicit SCONE_RPC_<CHAIN> override.
if [ -n "${ALCHEMY_API_KEY:-}" ]; then
    : "${SCONE_RPC_BSC:=https://bnb-mainnet.g.alchemy.com/v2/${ALCHEMY_API_KEY}}"
    : "${SCONE_RPC_ARBI:=https://arb-mainnet.g.alchemy.com/v2/${ALCHEMY_API_KEY}}"
    : "${SCONE_RPC_BASE:=https://base-mainnet.g.alchemy.com/v2/${ALCHEMY_API_KEY}}"
    : "${SCONE_RPC_OPTIM:=https://opt-mainnet.g.alchemy.com/v2/${ALCHEMY_API_KEY}}"
    : "${SCONE_RPC_POLY:=https://polygon-mainnet.g.alchemy.com/v2/${ALCHEMY_API_KEY}}"
fi

missing=()
[ -z "$SCONE_RPC_MAINNET" ] && missing+=("SCONE_RPC_MAINNET (or ALCHEMY_API_KEY)")
[ -z "${ETHERSCAN_API_KEY:-}" ] && missing+=("ETHERSCAN_API_KEY")
[ -z "${ANTHROPIC_API_KEY:-}${OPENAI_API_KEY:-}" ] && missing+=("ANTHROPIC_API_KEY (or OPENAI_API_KEY)")
if [ "${#missing[@]}" -gt 0 ]; then
    echo "error: missing from $REPO_ROOT/.env: ${missing[*]}" >&2
    exit 1
fi

# This .env file is ONLY consumed by scone-bench's standalone manual MCP
# mode (`docker run --env-file .env scone-bench uv run scone_bench mcp`,
# per its own README) — NOT by runner/run_eval.py, which never loads a
# .env file at all. client.py reads os.environ of the host process
# directly (confirmed by reading its source): the Anthropic/OpenAI client
# is constructed from os.environ.get(...) directly, and the per-problem
# container's env is built from `{k: v for k, v in os.environ.items() if
# k in _ALLOWED_DOCKER_ENV_KEYS}`. So we write this file for the manual
# mode AND export the same variables below for the actual run_eval.py path.
cat > "$SCONE_BENCH_DIR/.env" <<EOF
SCONE_RPC_MAINNET=${SCONE_RPC_MAINNET}
SCONE_RPC_BSC=${SCONE_RPC_BSC:-}
SCONE_RPC_ARBI=${SCONE_RPC_ARBI:-}
SCONE_RPC_BASE=${SCONE_RPC_BASE:-}
SCONE_RPC_OPTIM=${SCONE_RPC_OPTIM:-}
SCONE_RPC_POLY=${SCONE_RPC_POLY:-}
ETHERSCAN_API_KEY=${ETHERSCAN_API_KEY}
ANTHROPIC_API_KEY=${ANTHROPIC_API_KEY:-}
OPENAI_API_KEY=${OPENAI_API_KEY:-}
EOF
export SCONE_RPC_MAINNET ETHERSCAN_API_KEY
[ -n "${SCONE_RPC_BSC:-}" ] && export SCONE_RPC_BSC
[ -n "${SCONE_RPC_ARBI:-}" ] && export SCONE_RPC_ARBI
[ -n "${SCONE_RPC_BASE:-}" ] && export SCONE_RPC_BASE
[ -n "${SCONE_RPC_OPTIM:-}" ] && export SCONE_RPC_OPTIM
[ -n "${SCONE_RPC_POLY:-}" ] && export SCONE_RPC_POLY
[ -n "${ANTHROPIC_API_KEY:-}" ] && export ANTHROPIC_API_KEY
[ -n "${OPENAI_API_KEY:-}" ] && export OPENAI_API_KEY
if [ -n "${ANTHROPIC_BASE_URL:-}" ]; then
    # Exported (not just written to the .env file above) because
    # run_eval.py reads this straight from its own process environment.
    # Only set when non-empty: the anthropic SDK treats an empty string as
    # a literal (broken) base_url, not "unset" — it only falls back to the
    # default api.anthropic.com when the env var is absent entirely.
    echo "ANTHROPIC_BASE_URL=${ANTHROPIC_BASE_URL}" >> "$SCONE_BENCH_DIR/.env"
    export ANTHROPIC_BASE_URL
    echo "Using ANTHROPIC_BASE_URL=${ANTHROPIC_BASE_URL} (non-Anthropic model endpoint, e.g. GLM Coding Plan)"
fi

if [ ! -f "$SCONE_BENCH_DIR/$PROBLEMS" ]; then
    echo "error: no such problem-metadata file: $SCONE_BENCH_DIR/$PROBLEMS" >&2
    echo "       available: $(cd "$SCONE_BENCH_DIR" && ls problem_metadatas/)" >&2
    exit 1
fi

# flaw_verifier/foundry.toml pins solc 0.8.13 with offline = true, but the
# image only ships svm-rs, not solc itself. Unless the model happens to run
# `svm install 0.8.13` during its own exploration, grading fails with "can't
# install missing solc 0.8.13 in offline mode". Pre-install it (idempotent).
if ! grep -q '^RUN svm install 0.8.13' "$SCONE_BENCH_DIR/Dockerfile"; then
    sed -i '/^# Vyper compilers/i RUN svm install 0.8.13\n' "$SCONE_BENCH_DIR/Dockerfile"
fi

echo "Building scone-bench image (first run: ~10 min — Rust toolchain + Foundry + heimdall) ..."
docker build --platform linux/amd64 -t scone-bench "$SCONE_BENCH_DIR"

TRANSCRIPT_DIR="results/scone-bench/$(date -u +%Y%m%dT%H%M%SZ)/"
mkdir -p "$TRANSCRIPT_DIR"
echo "Results -> $TRANSCRIPT_DIR"

cd "$SCONE_BENCH_DIR/runner"
# runner/pyproject.toml declares "mcp[cli]>=1.3.0" with no upper bound and no
# checked-in lockfile. A fresh `uv run`/`uv sync` resolves that to the
# newest mcp (observed: 2.3.0), whose CallToolResult *renamed* the
# camelCase `isError` attribute scone-bench's own utils.py reads directly in
# several places to `is_error` (`isError` survives only as a pydantic
# serialization alias, not a real Python attribute) — confirmed via
# "'CallToolResult' object has no attribute 'isError'" at grading time.
# mcp's 1.x line keeps `isError` as a literal attribute, so pin below
# 2.0.0 — specifically to the latest 1.x release: the declared floor
# (1.3.0) fails to even import against current pydantic
# (ImportError: cannot import name 'eval_type_backport').
# A one-off `uv pip install` of the right version does NOT survive: `uv
# run` re-syncs the venv against pyproject.toml's declared range before
# every invocation. So patch pyproject.toml itself (idempotent) and
# lock/sync against that, which is what actually sticks across runs and
# across the fresh clones this script does on a clean checkout.
sed -i -E 's/"mcp\[cli\]>=1\.3\.0(,<2\.0\.0)?"/"mcp[cli]>=1.3.0,<2.0.0"/' pyproject.toml
uv lock
uv sync

RUN_ARGS=(
    run_eval.py
    --problems-metadata "../$PROBLEMS"
    --max-tokens 64000
    --times-per-problem 1
    --parallel-requests 1
    --transcript-dir "$REPO_ROOT/$TRANSCRIPT_DIR"
)
[ -n "$MODEL" ] && RUN_ARGS+=(--model "$MODEL")

uv run python "${RUN_ARGS[@]}"
