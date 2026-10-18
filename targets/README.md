# Adding a new target

Two kinds of targets live in this directory, with entirely different
contracts:

- [**Vuln-pipeline targets**](#vuln-pipeline-targets-crashing-binary) · A C/C++ codebase built into an ASAN-instrumented binary that agents try to crash
- [**Detection & response targets**](#detection--response-targets-kind-dnr) · A runnable demo app plus a generated log corpus with a planted attack campaign

## Vuln-pipeline targets (crashing binary)

A target is a directory under `targets/` containing everything the pipeline
needs to build an ASAN-instrumented binary and point the find-agent at it.

### Required files

#### `config.yaml`

```yaml
image_tag: vuln-pipeline-<name>:latest   # docker tag to build/run
github_url: https://github.com/...      # for the prompt (agent reads source, needs context)
commit: <full-sha>                      # pin exactly what you tested
binary_path: /work/entry                # path INSIDE the container
source_root: /work                      # path INSIDE the container
```

Optional fields:

```yaml
focus_areas:                            # starting points for parallel runs (or use --auto-focus)
  - "PNG chunk parsing (decode_chunk) — IDAT decompression, filter reconstruction"

known_bugs:                             # rendered into the prompt as do-not-resubmit
  - "Crashes in decode_chunk (decoder.h ~4500-4530) — may show as heap-overflow OR assertion. Upstream #123."

attack_surface: |                       # anchors the report-agent's reachability section
  Header-only image decoder library. Real surface: any caller of the public
  load-from-bytes API on untrusted image data. Pure file parser — no wire
  protocol, no auth.

build_command: gcc -O1 -g -fsanitize=address -o /work/entry /work/entry.c
                                        # in-container rebuild for the patch grader (T0).
                                        # Required for `vuln-pipeline patch`; the grader
                                        # applies the diff then runs this to recompile.

test_command: cd /work/src && make check
                                        # regression suite for the patch grader (T2).
                                        # Optional; T2 is skipped if absent.

memory_limit: 4g                        # docker --memory for agent containers (default 4g)
shm_size: 1g                            # docker --shm-size; unset by default
build_timeout_s: 1800                   # cap on in-container builds (default 1800)

reattack_harness: /work/run_pocs.sh     # in-image script that runs every /poc/* file and
                                        # exits 1 on a crash. When set, the find prompt
                                        # switches to harness-driven reproduction (the agent
                                        # runs this script instead of the binary directly).
                                        # No shipped target uses it.
```

**`known_bugs` format matters.** These go into the find-agent's prompt. Key on
**function name**, not line number: the same bug crashes at different lines
or with different ASAN types (SEGV vs assertion vs stack-overflow) depending on
input, so `"null-deref at file.h:1234"` won't match when the agent's crash
lands at `:1240`. Include: crash function, approximate line range, alternate
crash types you've observed.

#### `Dockerfile`

Must produce an image where:
- `{binary_path}` is an ASAN-instrumented executable taking one argument (input file)
- `{source_root}` contains the source the agent will read
- `gcc`, `python3`, `xxd`, `file`, `gdb` are available (agent uses these to craft inputs)
- `/bin/bash` works (container entrypoint)

Template:

```dockerfile
FROM gcc:14
WORKDIR /work
RUN apt-get update && apt-get install -y --no-install-recommends python3 xxd file gdb && rm -rf /var/lib/apt/lists/*

# COPY source files into /work. Prefer local COPY over git-clone — faster,
# no network in build, pins commit for free.
COPY <your_source_files> /work/

COPY entry.c /work/entry.c
RUN gcc -O1 -g -fsanitize=address -fno-omit-frame-pointer -o /work/entry /work/entry.c -lm

CMD ["/bin/bash"]
```

**Flags:** `-O1` per ASAN docs (O0 too slow, O2+ can optimize bugs away).
`-fno-omit-frame-pointer` for readable stack traces.

#### `entry.c`

A thin wrapper: `./entry <input_file>` → run the parser on the file, exit.
Keep it minimal — it defines the attack surface. ASAN abort happens before
`return 0` if there's memory corruption.

### No pipeline code changes needed

The pipeline reads `config.yaml` and runs `docker build` on this directory.
No Python edits needed to add a target.

### Solidity/Foundry targets (no single binary)

A Solidity/Foundry target is still a vuln-pipeline target — same
`config.yaml` + `Dockerfile` contract, same find→grade→report flow — but it
has no single ASAN-instrumented binary for the agent to run, so a few fields
and the Dockerfile template differ from the C/C++ case above.

**`binary_path` is optional and not meaningful here.** `TargetConfig.binary_path`
defaults to `None`; omit it from `config.yaml` entirely rather than setting
it to a placeholder. `source_root` is still required — it's the Foundry
project root inside the container (e.g. `/work`), containing `foundry.toml`,
`src/`, and `test/`.

```yaml
image_tag: vuln-pipeline-<name>:latest
github_url: https://github.com/...   # or a local-only marker, as above
commit: <full-sha>
source_root: /work                   # Foundry project root; no binary_path
build_command: forge build --offline
test_command: forge test --offline   # regression suite for T2
```

`build_command`/`test_command` map to `forge build`/`forge test` instead of
a `gcc`/`make` invocation — pass `--offline` since the sandbox has no
network. Everything else (`focus_areas`, `known_bugs`, `attack_surface`,
`memory_limit`, `build_timeout_s`, etc.) means the same thing it does for a
C/C++ target.

**The Dockerfile template differs.** Instead of `gcc:14` + an `entry.c`
wrapper, build FROM a Foundry/Solidity base image (pin an exact
`ghcr.io/foundry-rs/foundry` tag, plus a pinned `solc` binary — see
`targets/solidity-canary/Dockerfile` for the full pinned-version pattern,
including the order-sensitive step where installing `slither-analyzer` via
pip clobbers `/usr/local/bin/solc` and must be re-symlinked afterward), then
`COPY` the target's own Foundry project (`foundry.toml`, `src/`, `test/`)
into `source_root`, same "prefer local COPY over git-clone" convention as
the C/C++ targets. `/bin/bash` must still work; `gdb`/`xxd`/`file` aren't
needed for this target shape, but keeping `python3` around is cheap and
some tooling expects it.

See `targets/solidity-canary/` for a complete worked example (three planted
bugs: reentrancy, missing access control, first-depositor share-price
manipulation) and its `README.md` for the answer key.

## Detection & response targets (`kind: dnr`)

`targets/dnrcanary/` is a different kind of target: a deliberately
vulnerable web app plus a generated log corpus with a planted attack
campaign, used by the detection & response track rather than the
find→grade pipeline.

### `config.yaml`

The `kind: dnr` marker routes the target: vuln-pipeline refuses it, and
dnr-pipeline refuses targets without it. The commands and paths below are
the contract — dnrcanary's filenames (`generate_logs.py`,
`ground_truth.yaml`, `grade.py`) are conventions, not requirements.
`seed_command` and `app_command` are run by the /dnr-* skills from the
target directory and rendered into the pipeline's hunt/grade prompts,
where they run from `/work` in-container (your `app/` tree lands at
`/work/app`) — keep their paths target-relative.

```yaml
kind: dnr
seed_command: python3 app/seed.py         # deterministic DB seed
app_command: python3 app/app.py           # must bind 127.0.0.1 only
generate_logs_command: python3 generate_logs.py --seed 42
port: 5151
logs_dir: logs                            # optional (default logs); mounted ro into the hunt container
ground_truth: ground_truth.yaml           # campaign manifest, the dnr analog of known_bugs; spoiler
grader: grade.py                          # deterministic scorer for a hunter's INCIDENTS.json; spoiler
```

Generating logs is the required first step: `generate_logs_command`
writes the gitignored `logs/`, and its source encodes the campaign — a
spoiler, so run it, don't read it.

### The hunt-agent image (no Dockerfile)

A dnr target ships no Dockerfile, `entry.c`, or ASAN build. Instead the
dnr pipeline builds the hunt-agent image itself: the shared CLI base, a
fixed apt layer (`python3 python3-flask python3-yaml sqlite3 curl`), and
your `app/` tree copied in wholesale. Your demo app must run on that
stack — any other runtime dependency means editing `DNR_APT_PACKAGES` in
`dnr_harness/agent_image.py`, the one place a dnr target can require a
pipeline change.

### Where spoilers may live

The config loader enforces the hunt/answer-key separation, not just
convention:

- every configured path must stay inside the target directory
- `ground_truth` and `grader` must not sit inside `logs_dir` or `app/`:
  logs are mounted into the hunt container and `app/` is copied into its
  image, so a spoiler under either would ship to the hunt agent
- the grade stage mounts `ground_truth` and `grader` read-only at
  runtime; they never enter any image

See `targets/dnrcanary/README.md` for the worked example.
