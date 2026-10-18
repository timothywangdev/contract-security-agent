# Copyright 2026 Anthropic PBC
# SPDX-License-Identifier: Apache-2.0
"""Grade loop: fresh container from same image, grader agent verifies PoC.

The trust boundary is the image tag — find-agent could write anywhere
in its container but can't retroactively modify the image. A fresh container
from the same tag is pristine. Only the PoC bytes cross the boundary.

Budget: 50 turns — it's a checklist, not research.
"""
from __future__ import annotations

import os
import time

from . import docker_ops, sandbox
from .agent import run_agent, parse_xml_tag, AgentResult
from .artifacts import CrashArtifact, GraderVerdict
from .config import TargetConfig
from .prompts.grade_prompt import build_grade_prompt


GRADE_MAX_TURNS = 50


async def run_grade(
    crash: CrashArtifact,
    target: TargetConfig,
    model: str,
    workspace_dir: str,
    agent_env: dict[str, str] | None = None,
    container_name: str = "grader_target",
    transcript_path: str | None = None,
    progress_prefix: str | None = None,
    system_prompt: str | None = None,
) -> tuple[GraderVerdict, AgentResult, float]:
    """Verify a CrashArtifact in a fresh container.

    workspace_dir: host-side results dir where we also persist poc.bin so
    it survives the container teardown.
    """
    if target.binary_path:
        # Path-substitution sanity: replace() below no-ops silently if poc_path
        # isn't in reproduction_command. That's a find-agent output
        # inconsistency — reject it here rather than hand the grader an
        # unadapted command.
        if crash.poc_path not in crash.reproduction_command:
            raise ValueError(
                f"poc_path {crash.poc_path!r} not found in reproduction_command "
                f"{crash.reproduction_command!r} — find-agent output is inconsistent"
            )
    else:
        # Source-based target (e.g. Solidity): poc_path is an absolute
        # in-tree path (source_root/test/audit/...); reproduction_command
        # references it by its path relative to source_root (run with that
        # as cwd), so it needn't appear verbatim in the command string.
        # Still reject anything that would land outside the project tree.
        if not crash.poc_path.startswith(target.source_root.rstrip("/") + "/"):
            raise ValueError(
                f"poc_path {crash.poc_path!r} is not inside source_root "
                f"{target.source_root!r} — find-agent output is inconsistent"
            )

    # Fresh agent container from the SAME image — find-agent never touched it.
    with sandbox.agent_container(target.image_tag, container_name, agent_env) as container:
        # Only the PoC bytes cross the boundary.
        docker_ops.write_file(container, "/tmp/poc.bin", crash.poc_bytes)
        if target.binary_path:
            # Binary target: the PoC is a single input file consumed as a
            # command-line argument. Substitute the path: the find-agent
            # saved to some arbitrary path; we write to a fixed one.
            adapted_cmd = crash.reproduction_command.replace(crash.poc_path, "/tmp/poc.bin")
        else:
            # Source-based target (e.g. Solidity): the PoC IS source code
            # (a Foundry/Halmos test) that the build tool must find at its
            # original in-tree path to compile and run — substituting a
            # /tmp path into the command would point --match-path at
            # nothing. Write the bytes to BOTH locations: the original
            # in-tree path (so the unmodified reproduction_command works)
            # and /tmp/poc.bin (kept for grader prompts that reference it
            # as a sanity copy). The command is not rewritten.
            docker_ops.write_file(container, crash.poc_path, crash.poc_bytes)
            adapted_cmd = crash.reproduction_command

        os.makedirs(workspace_dir, exist_ok=True)
        workspace_poc = os.path.join(workspace_dir, "poc.bin")
        with open(workspace_poc, "wb") as f:
            f.write(crash.poc_bytes)

        prompt = build_grade_prompt(
            image_tag=target.image_tag,
            reproduction_command=crash.reproduction_command,
            reproduction_command_adapted=adapted_cmd,
            crash_type=crash.crash_type,
            exit_code=crash.exit_code,
            source_root=target.source_root,
            workspace_poc="/tmp/poc.bin",
        )
        t0 = time.time()
        result = await run_agent(
            prompt=prompt,
            max_turns=GRADE_MAX_TURNS,
            model=model,
            container=container,
            transcript_path=transcript_path,
            progress_prefix=progress_prefix,
            system_prompt=system_prompt,
        )
        elapsed = time.time() - t0

        text = result.find_tagged_message("overall")
        criteria: dict[str, bool] = {}
        for i in range(1, 6):
            val = parse_xml_tag(text, f"criterion_{i}")
            criteria[f"criterion_{i}"] = val is not None and val.upper().startswith("PASS")

        overall = parse_xml_tag(text, "overall")
        score_str = parse_xml_tag(text, "score")
        evidence = parse_xml_tag(text, "evidence") or ""

        verdict = GraderVerdict(
            passed=(overall is not None and overall.upper().startswith("PASS")),
            score=_parse_score(score_str),
            criteria=criteria,
            evidence=evidence,
        )
        return verdict, result, elapsed


def _parse_score(s: str | None) -> float:
    if not s:
        return 0.0
    try:
        return float(s.strip())
    except ValueError:
        return 0.0
