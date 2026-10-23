#!/usr/bin/env bash
# Copyright 2026 Contract Security Agent contributors
# SPDX-License-Identifier: Apache-2.0
#
# Run OUR vuln-pipeline (find + grade) against many scone-bench incidents as
# fork targets, with bounded parallelism, and tally the CONFIRMED exploits.
#
# Unlike scripts/run-scone-bench.sh (which runs scone-bench's OWN runner as a
# baseline), this drives *this* pipeline: our find-agent reverse-engineers each
# live-deployed contract on a fork and writes an exploit, our grader verifies
# it. Each task is generated on the fly by scripts/gen-scone-targets.py.
#
# Usage:
#   scripts/run-scone-fork-batch.sh uerii xsurge bearn ...      # explicit ids
#   scripts/run-scone-fork-batch.sh --chain bsc --limit 20      # first N of a chain
#   SCONE_FORK_PARALLEL=4 SCONE_FORK_MAXTURNS=150 \
#     scripts/run-scone-fork-batch.sh --chain bsc --limit 30
#
# Env knobs:
#   SCONE_FORK_MODEL     model (default glm-5.3; uses .env ANTHROPIC_* creds)
#   SCONE_FORK_PARALLEL  concurrent pipeline runs (default 4)
#   SCONE_FORK_MAXTURNS  find-agent turn budget per task (default 150)
#
# DEV/BENCHMARK ONLY: runs agents under --dangerously-no-sandbox (plain runc,
# bridge network) because this harness is for a throwaway benchmarking host
# where gVisor isn't available. The shipped secure path is bin/vp-sandboxed.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

MODEL="${SCONE_FORK_MODEL:-glm-5.3}"
PARALLEL="${SCONE_FORK_PARALLEL:-4}"
MAXTURNS="${SCONE_FORK_MAXTURNS:-150}"
PY=.venv/bin/python

# --- resolve the task id list -------------------------------------------------
if [ "${1:-}" = "--chain" ]; then
    CHAIN="${2:?--chain needs a value}"; LIMIT="${4:-20}"
    mapfile -t IDS < <("$PY" - "$CHAIN" "$LIMIT" <<'PY'
import csv, sys
chain, limit = sys.argv[1], int(sys.argv[2])
rows = csv.DictReader(open("third_party/scone-bench/dataset/scone_bench.csv"))
ids = [r["case_name"] for r in rows if r["chain"] == chain]
print("\n".join(ids[:limit]))
PY
)
else
    IDS=("$@")
fi
[ "${#IDS[@]}" -gt 0 ] || { echo "no task ids (pass ids, or --chain X --limit N)" >&2; exit 1; }

# --- credentials from the repo .env (never printed) ---------------------------
g() { "$PY" -c "d=dict(l.rstrip().split('=',1) for l in open('.env') if '=' in l and not l.lstrip().startswith('#')); print(d.get('$1','').strip().strip(chr(34)).strip(chr(39)))"; }
export ALCHEMY_API_KEY="$(g ALCHEMY_API_KEY)"
export ANTHROPIC_API_KEY="$(g ANTHROPIC_API_KEY)"
export ANTHROPIC_BASE_URL="$(g ANTHROPIC_BASE_URL)"
[ -n "$ALCHEMY_API_KEY" ] || { echo "error: ALCHEMY_API_KEY missing from .env" >&2; exit 1; }
export VULN_PIPELINE_AGENT_RUNTIME=runc VULN_PIPELINE_AGENT_NETWORK=bridge

# --- generate every target up front + build the shared image once -------------
echo "Generating ${#IDS[@]} fork target(s) ..."
"$PY" scripts/gen-scone-targets.py "${IDS[@]}"
echo "Building shared fork image ..."
docker build -q -t vuln-pipeline-scone-fork:latest "targets/scone-${IDS[0]}/" >/dev/null

BATCH="results/scone-fork-batch/$(date -u +%Y%m%dT%H%M%SZ)"
mkdir -p "$BATCH/logs"
SUMMARY="$BATCH/summary.tsv"
printf "task\tverdict\tscore\tstatus\n" > "$SUMMARY"
echo "Batch dir: $BATCH   (model=$MODEL parallel=$PARALLEL max_turns=$MAXTURNS)"

# --- one task: run pipeline, then append its verdict to the summary -----------
run_one() {
    local t="$1" log="$BATCH/logs/$1.log"
    if .venv/bin/vuln-pipeline run "targets/scone-$t" --model "$MODEL" \
            --max-turns "$MAXTURNS" --dangerously-no-sandbox >"$log" 2>&1; then :; fi
    # Extract the latest verdict for this task.
    "$PY" - "$t" "$SUMMARY" <<'PY'
import glob, json, os, sys
t, summary = sys.argv[1], sys.argv[2]
dirs = sorted(glob.glob(f"results/scone-{t}/*/"), reverse=True)
verdict, score, status = "no_result", "", "?"
for d in dirs:
    rj = os.path.join(d, "result.json")
    if not os.path.exists(rj):
        continue
    d_ = json.load(open(rj))
    status = d_.get("status") or "?"
    v = d_.get("verdict") or {}
    if v:
        verdict = "CONFIRMED" if v.get("passed") else "rejected"
        score = v.get("score", "")
    else:
        verdict = "no_poc" if status in ("no_crash_found", "error") else status
    break
with open(summary, "a") as f:
    f.write(f"{t}\t{verdict}\t{score}\t{status}\n")
print(f"  [{t}] {verdict} (score={score}, status={status})")
PY
}

# --- bounded-parallel job pool ------------------------------------------------
pids=()
for t in "${IDS[@]}"; do
    run_one "$t" &
    pids+=($!)
    while [ "$(jobs -rp | wc -l)" -ge "$PARALLEL" ]; do wait -n 2>/dev/null || true; done
done
wait

echo
echo "==== BATCH COMPLETE: $BATCH ===="
confirmed=$(grep -c $'\tCONFIRMED\t' "$SUMMARY" || true)
total=$(( $(wc -l < "$SUMMARY") - 1 ))
echo "CONFIRMED exploits: $confirmed / $total"
grep $'\tCONFIRMED\t' "$SUMMARY" | sed 's/^/  FIND  /' || true
echo "Full summary: $SUMMARY"
