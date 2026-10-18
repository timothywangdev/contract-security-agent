# Copyright 2026 Anthropic PBC
# SPDX-License-Identifier: Apache-2.0
"""Build the per-target agent image: target binary + claude CLI.

The agent runs *inside* its container, so the container needs the CLI. To
avoid one node+npm install per target, ``ensure()`` builds a shared
``vuln-pipeline-agent-base:<cli-version>`` once (gcc:14 + node + pinned CLI)
and then layers each target's ``/work`` on top via ``COPY --from``. Target
Dockerfiles stay unchanged (single source of truth for the binary build).
"""

from __future__ import annotations

import functools
import re
import subprocess
import tempfile
import textwrap

from . import docker_ops

CLAUDE_CODE_VERSION = "2.1.144"  # bump alongside the dev-env CLI pin
BASE_TAG = f"vuln-pipeline-agent-base:{CLAUDE_CODE_VERSION}"
_TAG_RE = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9._/:-]*$")


def agent_tag(target_tag: str) -> str:
    """Distinct agent-image tag per *full* target tag, so a committed
    ``<name>:patched-<uuid>`` snapshot doesn't collide with ``<name>:v1``."""
    return f"{target_tag.replace(':', '-')}-agent:{CLAUDE_CODE_VERSION}"


def validate_tag(tag: str) -> None:
    """Raise ValueError if ``tag`` is not a valid docker image reference."""
    if not _TAG_RE.match(tag):
        raise ValueError(f"invalid image tag: {tag!r}")


def build(dockerfile: str, tag: str, context: str | None = None) -> None:
    """Build ``dockerfile`` (a string) as ``tag``. With ``context``, the build
    context is that directory instead of the Dockerfile's temp dir — used by
    harnesses whose Dockerfiles COPY from a host tree."""
    with tempfile.TemporaryDirectory() as ctx:
        with open(f"{ctx}/Dockerfile", "w") as f:
            f.write(dockerfile)
        if context is None:
            cmd = ["docker", "build", "-q", "-t", tag, ctx]
        else:
            cmd = ["docker", "build", "-q", "-f", f"{ctx}/Dockerfile", "-t", tag, context]
        subprocess.run(cmd, check=True, capture_output=True, text=True)


def ensure_base() -> str:
    if docker_ops.image_exists(BASE_TAG):
        return BASE_TAG
    # xxd + gdb: the find/patch prompts list these as available. Target
    # Dockerfiles install them too, but ``ensure()`` only copies /work from the
    # target image — apt packages outside /work don't survive the COPY --from.
    # Anything the prompts promise has to live in this base layer.
    build(
        textwrap.dedent(f"""\
            FROM gcc:14
            RUN apt-get update && \\
                apt-get install -y --no-install-recommends nodejs npm ca-certificates xxd gdb && \\
                rm -rf /var/lib/apt/lists/* && \\
                npm install -g @anthropic-ai/claude-code@{CLAUDE_CODE_VERSION}
            WORKDIR /work
        """),
        BASE_TAG,
    )
    return BASE_TAG


@functools.lru_cache(maxsize=None)
def ensure(target_tag: str) -> str:
    """Build (if missing) and return the agent-image tag for ``target_tag``.

    Builds FROM the target's own image, not a shared base layered with
    ``COPY --from=target_tag /work /work``. That older approach (still used
    by dnr_harness's separate ``ensure()``, which has a fixed, known app
    runtime) assumed everything the prompts need beyond the compiled binary
    already lived in the shared ``gcc``-based ``ensure_base()`` image (true
    for C/C++'s ``xxd``/``gdb``, which the target Dockerfile template also
    installs itself, redundantly but harmlessly) or under ``/work``. It
    silently dropped anything else a target installed elsewhere — e.g. a
    Solidity target's ``forge``/``solc``/``slither``/``halmos``, which live
    outside ``/work``. Building FROM the target image instead preserves its
    entire toolchain; the cost is one slightly slower first build per
    target — the node/npm install layer still caches across repeated runs
    against the same target image."""
    validate_tag(target_tag)
    tag = agent_tag(target_tag)
    if docker_ops.image_exists(tag):
        return tag
    build(
        textwrap.dedent(f"""\
            FROM {target_tag}
            USER root
            RUN apt-get update && \\
                apt-get install -y --no-install-recommends nodejs npm ca-certificates && \\
                rm -rf /var/lib/apt/lists/* && \\
                npm install -g @anthropic-ai/claude-code@{CLAUDE_CODE_VERSION}
            WORKDIR /work
        """),
        tag,
    )
    subprocess.run(
        ["docker", "tag", tag, f"{tag.rsplit(':', 1)[0]}:latest"],
        check=True,
    )
    return tag
