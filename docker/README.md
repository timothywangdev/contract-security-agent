The execution worker contains Python 3.12.11, Foundry 1.4.4, Solidity 0.8.26,
Slither 0.11.6, and Halmos 0.3.3. Build it from the repository root:

```sh
docker build -f docker/Dockerfile.tools -t contract-security-agent-tools:dev .
```

The current image supports Linux x86-64. Base image digests and the Solidity
binary checksum are pinned in the Dockerfile. Python tool versions are pinned;
their transitive dependencies resolve at build time. Each audit's diagnostics
records the resulting local image ID. Building requires internet access.

Runtime workers have no network, model credentials, or Docker socket. The
controller copies a snapshot into a temporary directory, mounts it read-only,
and starts a fresh non-root worker with a read-only root filesystem, dropped
capabilities, process/memory/CPU limits, and bounded temporary filesystems.
Tools operate on another copy inside the worker. Timeouts and output limits
terminate the worker and produce incomplete results. Docker is required;
execution never falls back to running target code on the host.

Projects must carry their dependencies and compile with the bundled 0.8.26
compiler. Other compiler versions, network-fork tests, dependencies downloaded
at runtime, symlinked sources, and source trees above the staging limits are
unsupported or incomplete. Existing Foundry configuration is retained, with
offline mode, FFI disabled, and external filesystem cheatcode access disabled.
Generated tests are limited to new Solidity files under `test/audit/`; zero
selected tests and skipped tests cannot count as a successful validation.

Slither's nonzero exit for detector findings still counts as completed analysis
when its structured result says `success: true`; detectors remain hypotheses
until executable evidence supports them. Halmos consumes its structured result,
and timeout, stuck, all-reverted, and error outcomes remain inconclusive.
Successful Halmos checks are bounded analyses.

The adapter follows the Docker CLI/lifecycle pattern of the vendored Anthropic
reference harness; its original license remains under `third_party/`.
Slither and Halmos carry their own licenses, available in the installed Python
package metadata and their [Slither](https://github.com/crytic/slither) and
[Halmos](https://github.com/a16z/halmos) repositories.
