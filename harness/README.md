# Harness: autonomous vulnerability discovery

This package is the reference pipeline: an autonomous, multi-agent harness
for finding, verifying, reporting, and patching security bugs. It ships
retargeted at Solidity/Foundry smart contracts (originally a C/C++/ASAN
pipeline — see `docs/customizing.md` and `.claude/skills/customize/` for how
a retarget works). It runs Claude Code agents inside gVisor-isolated
containers, builds a Foundry/Slither/Halmos-equipped target image, and grades
every finding with an executable oracle (the exploit test/property fails, or
it doesn't).

This README is the copy-paste path to a demo. For the architecture, every
CLI flag, and rate-limit math, see [`docs/pipeline.md`](../docs/pipeline.md).

> ⚠️ **`run`, `recon`, `report`, and `patch` execute target code.** The
> harness refuses to spawn agents outside its gVisor sandbox. Run
> `scripts/setup_sandbox.sh` once, then invoke everything through
> `bin/vp-sandboxed`. Never mount credentials into the agent environment.
> See [`docs/security.md`](../docs/security.md).

## Prerequisites

- Linux host (x86_64 or aarch64), required by gVisor. On macOS/Windows, run
  inside a Linux VM.
- Docker.
- Python 3.11+.
- An Anthropic API key or Claude Code OAuth token.

## Demo: find the planted bugs in solidity-canary

The `solidity-canary` target is a small Foundry project with three
deliberately planted bugs, one per contract: reentrancy in `ReentrancyVault`,
a missing access-control check in `FeeManager`, and a first-depositor
share-price manipulation in `ShareVault`. The pipeline finds them from
source: no answer key, no hints, no network to the agent (`known_bugs` is
deliberately left empty — see
[`targets/solidity-canary/README.md`](../targets/solidity-canary/README.md)
for the real answer key). `targets/solidity-canary/Dockerfile` builds a
Foundry + Slither + Halmos image and copies the local source in. Your own
target works the same way: a Dockerfile that pulls (or copies) your code at
a pinned commit and builds it.

### Setup (once)

```bash
cd <repo-root>
python3 -m venv .venv
.venv/bin/pip install -e .
export ANTHROPIC_API_KEY=sk-ant-...        # or CLAUDE_CODE_OAUTH_TOKEN, or Bedrock — see docs/agent-sandbox.md
export VULN_PIPELINE_MODEL=<model-id>      # Claude Opus recommended; override per-call with --model

# Installs gVisor, builds the target + agent images, verifies isolation; needs sudo.
# (Build it directly to see what's inside: docker build -f targets/solidity-canary/Dockerfile -t vuln-pipeline-solidity-canary:latest targets/solidity-canary/)
./scripts/setup_sandbox.sh
```

### Run (end to end)

One command runs **recon → find → grade → judge → report**:

```bash
bin/vp-sandboxed run solidity-canary --auto-focus --runs 3 --parallel --stream
# --auto-focus : run recon first and feed its focus_areas partition to the find agents
# --runs 3 --parallel : 3 concurrent find agents, each in its own container
# --stream : judge + report stream as each grade lands (first report in minutes)
#
# → results/solidity-canary/<timestamp>/run_NNN/{result.json, poc.bin, find_transcript.jsonl}
#   results/solidity-canary/<timestamp>/reports/bug_NN/report.json
```

Then patch the confirmed findings. This is a separate step on purpose, so
you can read the reports and decide what's worth fixing before spending
tokens. `patch` takes a results **batch directory**, not a target name: each
`run` writes a new `results/solidity-canary/<timestamp>/`, so if you've
scanned more than once you need to say which batch you're patching (the
intended loop is scan → patch → re-scan the patched tree). To patch the
batch you just ran, resolve the newest timestamp with shell expansion:

```bash
bin/vp-sandboxed patch results/solidity-canary/$(ls -t results/solidity-canary | head -1)/
# → resolves to the most recent batch
#   results/solidity-canary/<timestamp>/reports/bug_NN/{patch.diff, patch_result.json}
```

Or name the batch explicitly; the `run` command prints it in its summary
(`run 0: crash_found → results/solidity-canary/20260519T.../run_000/result.json`):

```bash
bin/vp-sandboxed patch results/solidity-canary/<timestamp>/
```

The first confirmed finding typically lands in 5-10 minutes. All three
planted bugs are fund-loss/state-corruption findings — no `--accept-dos`
needed. Full description of the three bugs in
[`targets/solidity-canary/README.md`](../targets/solidity-canary/README.md).

> **Network note.** The `docker build` step in `setup_sandbox.sh` needs
> outbound HTTPS only if your own target's Dockerfile fetches source from
> GitHub (`solidity-canary`'s source is local, so no fetch is needed for the
> demo). After the build, the find/grade/patch agents run with egress locked
> to the configured allowlist (default `api.anthropic.com:443`; see
> [`docs/agent-sandbox.md`](../docs/agent-sandbox.md) for Bedrock/Vertex);
> they never see the network beyond it. This is the setup → attack isolation
> split described in
> [`docs/security.md`](../docs/security.md#separating-setup-and-attack-phases).

> **Env-name note.** The `VULN_PIPELINE_*` env vars and the `vp-internal`
> network name are the contract with `bin/vp-sandboxed` and
> `scripts/setup_sandbox.sh`, and they configure the sandbox for **both**
> pipelines — `dnr-pipeline` uses the same proxy, network, and runtime
> despite the `VULN_` prefix. Renaming them is a breaking change for
> existing user environments; treat them as repo-wide sandbox config.

### Run (step by step)

If you'd rather inspect each phase before committing tokens to the next:

```bash
# Recon only: read the source, print a focus_areas: YAML block.
# Review it, optionally edit it, paste it into targets/solidity-canary/config.yaml.
bin/vp-sandboxed recon solidity-canary

# Find + grade only, using the focus_areas you pasted (no recon, no reports)
bin/vp-sandboxed run solidity-canary --runs 3 --parallel

# Report after the fact, once all grades land
vuln-pipeline report results/solidity-canary/<timestamp>/

# Patch
bin/vp-sandboxed patch results/solidity-canary/<timestamp>/
```

## Watching a run

Each find-agent is a headless `claude -p` session inside its own container.
Tail its transcript as it works:

```bash
tail -f results/solidity-canary/<timestamp>/run_000/find_transcript.jsonl | python3 -c \
  'import sys, json
for line in sys.stdin:
    m = json.loads(line)
    if m.get("type") == "assistant":
        for b in m.get("message", {}).get("content", []):
            if b.get("type") == "tool_use":
                print(f"→ {b['name']}: {str(b.get('input',{}))[:120]}")'
```

## After the run

```bash
vuln-pipeline dedup  results/solidity-canary/<timestamp>/   # group findings by root-cause signature
vuln-pipeline report results/solidity-canary/<timestamp>/   # exploitability analysis per unique bug
vuln-pipeline run    solidity-canary --resume results/solidity-canary/<timestamp>/   # retry failed/killed runs
```

## Other targets

```bash
ls targets/
```

`solidity-canary` is the synthetic smoke test: planted bugs, fast build,
full source in the repo (which is why the static skills `/threat-model`,
`/vuln-scan`, `/triage` demo on it). There's no pre-baked `results_sample`
fixture here yet for trying `patch`/`report` without burning find tokens
(upstream's old C/C++ canary target had one; it didn't carry over in this
fork's retarget). Add your own target under `targets/<name>/` the same
way — see `targets/README.md`'s Solidity section.

## Port to your stack

This pipeline was already ported once (C/C++/ASAN → Solidity/Foundry); the
domain-specific pieces now live in `prompts/`, `finding_parser.py` (the
former `asan.py`), and `patch_grade.py:_t1_passes()`. The orchestration
(`cli.py`, `find.py`, `grade.py`, `report.py`) is mostly domain-neutral — it
survived that port essentially unchanged. See
[`docs/customizing.md`](../docs/customizing.md), or run `/customize` in
Claude Code from the repo root to port it again.
