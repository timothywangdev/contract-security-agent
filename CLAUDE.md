# Claude for Securing Source Code

**This fork retargeted the whole pipeline at Solidity/Foundry smart-contract
auditing — read this section first.** Below this, the rest of the file is the
upstream pipeline operator guide; its mechanics (CLI flags, sandboxing,
dedup/patch semantics) are accurate and unmodified, but any wording that
still says "C/C++"/"ASAN"/"crash" describes the mechanism generically — the
actual domain content (prompts, the finding parser, the shipped target) is
now Solidity. This retarget was done via `.claude/skills/customize/` (the
pipeline's own documented porting workflow) — see `docs/product-plan/` for
the original planning docs and rationale.

- **`vuln-pipeline`** (`harness/`) — the autonomous pipeline. Docker +
  Foundry/Slither/Halmos (not ASAN anymore), executes target code, needs a
  sandbox (see `docs/security.md`). Route here when the user wants an
  autonomous find → grade → report → patch loop against a Solidity target
  directory (`targets/solidity-canary/` is the shipped fast smoke test; add
  your own under `targets/<name>/` per `targets/README.md`'s Solidity
  section). `scripts/run-scone-bench.sh` reproduces Anthropic's scone-bench
  (417 historical DeFi incidents, forked on anvil) in one command as a
  separate, independently-graded validation signal — it runs scone-bench's
  own harness unmodified, not ours; see `docs/scone-bench.md`. Wiring its
  task shape into `vuln-pipeline` as a live-fork target kind, so our own
  find/grade/report agents run against it instead, remains a documented
  but not-yet-built next step — see `docs/product-plan/`.
- **`contract_security_agent/`** (`csa` / `contract-security-agent` CLI) — a
  separate, standalone, one-command, execution-verified Solidity/Foundry
  audit tool that predates and complements `vuln-pipeline`'s retarget.
  `csa audit <path-to-foundry-project>` snapshots an *arbitrary* local Foundry
  project, runs it against a single pre-built tool image (Foundry + Slither +
  Halmos, see `docker/Dockerfile.tools`), and produces a Markdown/JSON report
  with reproducible evidence — no per-target Dockerfile/config.yaml authoring
  needed, unlike `vuln-pipeline`'s fixed-target model. `csa doctor` checks
  prerequisites (Docker, the tool image, Claude Code auth) without running any
  target code. `csa reproduce`/`csa verify-fix` replay a saved finding or
  retest a supplied fix. This is the easiest on-ramp for a smart-contract
  engineer who wants to point the tool at their own repo with zero `targets/`
  setup — see `docs/product-plan/` for the full design rationale, including
  why it computes verdicts from protected checkers rather than model
  self-reports, unlike upstream's `grade.py`.
  Fixtures: `examples/vault` (vulnerable reentrancy) /
  `examples/vault-fixed` (patched) / `examples/checks` (the independent
  trusted-oracle test) are a ready-made vulnerable/fixed pair for a first run:
  `csa audit examples/vault --requirements examples/requirements.json
  --trusted-checks examples/checks --config examples/audit.json`.
- `.claude/scan-extras-solidity.txt` — pass to `/vuln-scan <dir> --extra
  .claude/scan-extras-solidity.txt` for a zero-setup (no Docker, no build)
  static pass tuned to Solidity bug classes (reentrancy, access control,
  share-price/accounting manipulation, oracle manipulation, unchecked
  external calls, delegatecall storage collisions). This is the lowest-
  friction entry point — nothing to install, works on any directory.
- **Interactive skills** (`.claude/skills/`) — read and write files in the
  repo (no target-code execution, except `/dnr-hunt` / `/dnr-respond`, which
  run the bundled demo app locally — see `docs/security.md`), run in this
  session:
  `/quickstart` (front door / Q&A), `/threat-model` (bootstrap, interview, or
  bootstrap-then-interview → `THREAT_MODEL.md`), `/vuln-scan` (static review →
  `VULN-FINDINGS.json`), `/triage` (verify + dedupe + rank a findings pile),
  `/patch` (generate candidate fixes → `PATCHES/`), `/dnr-hunt` /
  `/dnr-respond` (detection & response over logs, unrelated to the Solidity
  retarget), `/customize` (port the pipeline to another stack — this is
  literally how this Solidity retarget was done). Route the user to these for
  scoping, static review, Q&A, and post-run triage. (`/verify` is contributor
  tooling for validating harness changes on docker-less hosts, not part of
  the user flow.)

Docs for each topic are in `docs/`; targets are in `targets/`
(`solidity-canary` is the fast smoke test; `dnrcanary` is the unrelated
detection-response demo). The rest of this file is the pipeline operator
guide.

---

# vuln-pipeline

Execution-verified vulnerability discovery for C/C++ targets. A find-agent reads
source, crafts inputs, runs an ASAN-instrumented binary until it lands a 3/3
reproducing crash. A grade-agent in a fresh container verifies it. Output is a
crashing input file, not prose.

## When the user asks you to run it

**Recommended: streaming mode with CC as the dashboard.** Walk the user
through recon interactively (show the discovered focus areas, let them
adjust), then launch `--runs N --parallel --stream` in the background. Reports
land in `reports/bug_NN/` as each crash passes grade and the judge clears it —
first one typically in minutes, not hours. Tail the reports directory and
surface each new `report.json` to the user with a summary as it appears.
Status check when asked: "N finds alive, M graded, K reports written — here's
the newest." Stragglers don't block disk writes; a stuck find-agent slows
itself, not the batch.

For first-time use on a target, run a small wave first (`--runs 3 --parallel
--stream --max-turns 100`) so the user gets a feel for token burn and prompt
calibration before scaling up. Check transcripts together if something looks
off.

Launch long runs in the background (tmux with a stable socket, or
`run_in_background`) so you can tail logs, watch `found_bugs.jsonl`, and
answer the user's questions without blocking.

## Running it

Each pipeline phase is a standalone subcommand:

```bash
vuln-pipeline recon <target> --model <model>        # propose focus_areas (YAML → stdout)
vuln-pipeline run <target> --model <model>          # find + grade, one run
vuln-pipeline run <target> --runs N --parallel      # N concurrent finds, round-robin over focus_areas
vuln-pipeline run <target> --auto-focus             # recon first, use its partition
vuln-pipeline run <target> --stream                 # judge + report stream in as grades land (recommended)
vuln-pipeline run <target> --find-only              # skip grade (prompt iteration)
vuln-pipeline run <target> --accept-dos             # DoS-class crashes count as valid finds (benchmark mode)
vuln-pipeline run <target> --resume <results_dir>   # continue a partially-killed batch (skip terminal runs)
vuln-pipeline dedup results/<target>/<ts>/          # group crashes by signature (summary view)
vuln-pipeline report results/<target>/<ts>/         # batch-mode: exploitability analysis per unique crash
vuln-pipeline report results/<target>/<ts>/ --fresh # ignore existing bug_NN/report.json checkpoints
vuln-pipeline patch results/<target>/<ts>/          # generate + verify a fix per unique crash
vuln-pipeline patch results/<target>/<ts>/ --bug N --no-reattack  # one bug, faster (skip re-attack tier)
```

Results → `results/<target>/<timestamp>/`. For `--runs N`: subdirs `run_000/`,
`run_001/`, etc., plus a shared `found_bugs.jsonl` at the batch root.
Reports → `results/<target>/<timestamp>/reports/bug_NN/` (manifest at
`reports/manifest.jsonl`).

## Watching a run

Two output layers, both on by default:

- **Heartbeat** (stdout, every ~25 turns): `[agent] N tool calls (M msgs)` —
  proves the process is alive during long silent stretches.
- **Progress** (stderr, per-action): `[find:N] → Bash: /work/entry ...` — shows
  what the agent is doing. One line per tool call and text block.

Transcripts stream to `{find,grade,recon,report}_transcript.jsonl` as messages
arrive (fsync'd). With `--stream`, judge transcripts go to
`reports/judge_runNNN.jsonl` and the report-grader's to
`report_transcript_..._grader.jsonl`. A mid-run kill leaves readable
transcripts on disk — nothing is buffered in memory waiting for the run to
finish.

**Checking a background run:** tail the log, `cat found_bugs.jsonl` for crashes
landed so far, count `run_*/result.json` files for graded results. Each
result.json writes the moment its run's grade finishes — stragglers don't
block disk writes. With `--stream`, also `ls reports/bug_*/report.json` for
reports landed, `cat reports/manifest.jsonl` for bug-id assignments, and
`cat reports/judge_log.jsonl` for the per-crash NEW/DUP_BETTER/DUP_SKIP
verdicts with reasoning. A stuck straggler can be killed (`docker rm -f
find_<target>_<N>`).

**Rate limits / API errors don't kill runs.** Each agent is one long-lived
`claude -p` session; a 429 or 5xx mid-run is retried inside the CLI first,
and if the CLI gives up the pipeline backs off (exp, cap 300s) and relaunches
with `--resume <session_id>` — full conversation context restored, agent
continues from the turn that failed. Up to 20 resumes per agent
(`agent.py:run_agent`). Tell users they can run near their provisioned
capacity and let backoff absorb bursts; they don't need to self-throttle to
avoid losing work. The per-agent resume count is printed to stdout alongside
the `[find:N] done ...` summary line; it is not persisted to `result.json`. One
exception: `error_max_turns` is terminal and deliberately not resumed —
resuming would multiply the turn cap. Raise `--max-turns` and re-run
instead. A crash (or dnr submission) the agent already submitted before
hitting the cap is still extracted and graded, not discarded with the
run; the salvage is recorded in `result.json` (`error` / `hunt_error`).

## Report phase

**With `--stream` (recommended):** reports are automatic. When each grade
lands, a judge agent decides whether the crash is a new bug, a cleaner
representative of an existing one (re-report), or a duplicate to skip. New
bugs trigger a report agent immediately; no dedup gate, no batch wait.
Reports land in `reports/bug_NN/report.json` minutes after the first
crash_found, not hours after the last straggler.

**Standalone `vuln-pipeline report <results_dir>`** stays for batch-mode
recovery or a results dir produced without `--stream`: one report agent per
unique crash signature, in a fresh container with only the PoC bytes and
source tree.

Output is a structured exploitability analysis — primitive characterization,
reachability from the real attack surface, heap layout, escalation path,
constraints — plus an agent-judged severity rating. A separate grader agent
scores the report (semantic rubric, not keyword scan).

**Before launching reports, ask whether the user wants the novelty check
enabled.** `--novelty` makes the pipeline clone (blob-filtered) the target's
`github_url` on the orchestrator host and inject `git log <commit>..HEAD --
<crash_file>` into the prompt so the report can state FIXED/UNFIXED. Off by
default — air-gapped or outbound-restricted environments won't want the
pipeline reaching GitHub. The report container's egress stays restricted to
the API either way; only the orchestrator touches GitHub.

```bash
vuln-pipeline run <target> --stream --novelty --model <m>                # streaming, with novelty
vuln-pipeline report results/<target>/<ts>/ --model <m> [--novelty]      # batch-mode / recovery
```

## Patch phase

`vuln-pipeline patch <results_dir>` runs after report (or instead of it). For
each unique crash: a patch agent in a fresh sandboxed container writes
a fix and emits a `git diff`; a separate grader container walks the
verification ladder — T0 apply + rebuild → T1 original PoC no longer crashes
→ T2 target test suite passes → re-attack: a 50-turn find-agent attacks the
patched binary (T3 is an opt-in advisory style judge via `--style`; see
`docs/patching.md`). On a failing tier the evidence is fed back and the patch
agent iterates (≤5). Output: `reports/bug_NN/{patch.diff, patch_result.json}`;
tier results land as `t0_builds`/`t1_poc_stops`/`t2_tests_pass`/`re_attack_clean`.

**Before launching, check the target's `config.yaml` has a `build_command`.**
Without it the grader can't recompile after applying the diff and the CLI
will error early. The shipped `solidity-canary` target has it
(`forge build --offline`).

**Tell the user the ladder verifies the finding is gone, not that the diff is
safe to upstream.** Surface `patch.diff` for human review and point at
`docs/patching.md#reviewing-generated-patches` for what to look for. Don't
offer to apply the diff to anything outside the pipeline containers.

There's no pre-baked `results_sample` fixture for a quick patch-only demo on
`solidity-canary` yet (upstream's old canary target had one for its C bugs;
it didn't carry over) — run `vuln-pipeline run solidity-canary` first to get
a real `results/solidity-canary/<timestamp>/` to patch.

**`--accept-dos` (off by default)** lowers the find-agent's submission floor
for benchmark/validation runs. The default quality bar rules out DoS-class
crashes (`allocation-size-too-big`, stack exhaustion from unbounded
recursion) — agents triage them with `allocator_may_return_null=1` and keep
hunting for memory corruption. Right behavior for real vuln hunting, but it
means DoS-class CVEs (e.g. wild-malloc via untrusted-size-field overflow)
land in transcripts without a formal submission. With `--accept-dos`, agents
submit the DoS find instead of skipping it. Use for known-CVE demo targets
where the CVE classification is DoS — check the CVE before launching.

**`--engagement-context <file>`** overrides the authorization block in the
agent system prompt. The pipeline ships a default "authorized security
research / defensive security assessment" block that's sufficient for most
open-source targets. If the user has an org-specific engagement scope
(authorized-by, in-scope subsystems, disclosure path), point this flag at a
file containing that block. Threaded to every agent's system prompt (find,
recon, report, grade, judge).

## Duplicate handling

Two layers, both agent-judged:

**Runtime (`<dup_check>`):** find-agents must emit a `<dup_check>` tag
alongside `<poc_path>` with their reasoning for why the crash is distinct from
what's already in `found_bugs.jsonl`. The pipeline rejects submissions without
it. The agent makes the judgment (it knows root cause); the pipeline enforces
that the judgment happened. Entries in the jsonl are raw ASAN excerpts
(SUMMARY line + top frames) — agents compare semantically, not by string
match.

**Report-gate (`--stream` only):** a judge agent reads each graded crash
against the `reports/manifest.jsonl` and decides NEW / DUP_BETTER / DUP_SKIP.
Replaces regex signature-match as the gate — same root cause at different
lines/frames still dedupes. DUP_BETTER triggers a re-report; a compare agent
then picks the canonical one and writes `canonical.json`.

**Writing `known_bugs` entries:** key on function name, not line number. The
same bug crashes at adjacent lines or with different ASAN types depending on
input. See `targets/README.md`.

## Architecture (what's load-bearing)

**Two-container trust boundary.** Find and grade run in separate containers
built from the same image. Only the PoC bytes cross. The find-agent never
touches the grade container — defeats reward-hacking via pre-positioned state.

**The agent runs inside the sandbox, not on the host.** `bin/vp-sandboxed`
sets the runtime/proxy env and execs the pipeline; each find/grade/report
agent then runs `claude -p` inside its own gVisor container (`--runtime=runsc
--network=vp-internal`, egress = the configured allowlist via the proxy —
default `api.anthropic.com:443`; see docs/agent-sandbox.md for
Bedrock/Vertex). The agent's `Read`/`Write`/`Bash` are confined to that
container.
Agent-spawning subcommands refuse to start outside the sandbox unless
`--dangerously-no-sandbox` is passed.

**Agent tool set is fixed:** find/grade/report agents get `Read`, `Write`,
`Bash`. Judge, compare, and report-grader agents get no tools — everything in
the prompt, one short call each. No MCP, no web access.

## Gotchas

**Agent API requests carry a usage marker** (`anthropic-cyber-runbook` header + a
`cyber-runbook/` User-Agent token, 1P auth only). `VULN_PIPELINE_NO_TELEMETRY=1`
removes the pipeline marker; interactive sessions get a header-only marker
from `.claude/settings.json` instead (override in `.claude/settings.local.json`).
See `docs/pipeline.md#usage-marker`.

**`-e CLAUDECODE=` and `-e IS_SANDBOX=1` in `agent.py` are load-bearing.**
The first stops the in-container CLI's nested-session check; the second lets
it accept `--permission-mode bypassPermissions`. Don't remove either.

**`--tools` not `--allowedTools`.** The CLI accepts both but they're different:
`--allowedTools` is a permission allowlist; `--tools` actually restricts the
available set.

**Model is a runtime arg, not config.** Always `--model` flag or
`VULN_PIPELINE_MODEL` env. `TargetConfig` has no model field by design.

## Adding a target

Directory under `targets/` with a Dockerfile (Foundry/Slither/Halmos build,
not ASAN anymore) + `config.yaml`. `binary_path` is optional — omit it for a
Solidity target, since there's no single binary (`source_root` is the
Foundry project root instead). No pipeline code changes. See
`targets/README.md`'s Solidity section.

**Shipped targets:** `solidity-canary` is the fast-iteration smoke test
(~1-2min build, 3 planted bugs: reentrancy in `ReentrancyVault`, a missing
access-control check in `FeeManager`, and a donation/first-depositor
share-price manipulation in `ShareVault`). `known_bugs` is deliberately left
empty so it stays a real discovery exercise. The upstream C/C++ demo targets
(`canary`, `drlibs`, `alsa`, `htslib`) were removed as part of this retarget
— their `find`/`grade`/`report` prompts no longer apply to them anyway, since
the pipeline's domain content is now Solidity-only.

## Detection & response track

Post-compromise sibling of the vuln pipeline — the attacker is already in
the logs. `targets/dnrcanary` is a deliberately vulnerable Flask app plus a
generated log corpus with a planted campaign (`kind: dnr` — vuln-pipeline
refuses it). **Logs must be generated before anything runs:**
`python3 targets/dnrcanary/generate_logs.py --seed 42` (~82 MB, gitignored,
byte-deterministic per seed on the same machine).

Interactive: `/dnr-hunt` (no alert in hand) → `/dnr-respond` (lead in hand)
→ `/triage` → `/patch` (run the last two from inside the run dir so their
outputs land beside the incidents). Autonomous: `bin/vp-sandboxed
dnr-pipeline run targets/dnrcanary --model <m> [--runs N --parallel]` — a
hunt agent (app source + read-only logs; no answer key in the container by
image construction) submits `INCIDENTS.json`; a grade agent in a fresh
container scores it and independently re-fires every confirmed PoC. Only
the submission crosses the boundary. Also takes `--max-turns`,
`--results-dir`, `--engagement-context`; results land in
`results/<target>/<ts>/run_NNN/`, even for a single run.
`ground_truth.yaml`, `grade.py`, and `generate_logs.py` source are
spoilers — never mount or read them on the hunt side. See
`docs/detection-response.md`.

## Tests

`pytest tests/`. Unit coverage spans tag/XML parsing, artifact serialization,
finding extraction (`tests/test_finding_parser.py` — Foundry/Halmos JSON, not
ASAN), focus-area rendering, dedup signatures, `found_bugs.jsonl` handling,
the judge and compare agents, report parsing, the T0–T3 patch-grade ladder
(`tests/test_patch_grade_e2e.py` runs the T0-T3 ladder for real against
`solidity-canary` with real Docker, no LLM), the `/threat-model` and
`/triage` skill checkpoint files, and system-prompt construction. No
end-to-end agent integration test — `solidity-canary` is the fast path for
that (`--runs 3 --parallel --max-turns 50`).
