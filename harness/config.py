# Copyright 2026 Anthropic PBC
# SPDX-License-Identifier: Apache-2.0
"""Target configuration loader.

A target is a directory under targets/ containing:
  - Dockerfile   (builds ASAN-instrumented binary)
  - config.yaml  (metadata the pipeline needs)
  - any other build-context files the Dockerfile COPYs

Adding a new target = new dir, zero pipeline code changes.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

import yaml


# host:port, shape-only — guards the egress allowlist against injection the
# same way auth._AWS_REGION_RE does (no commas/whitespace/scheme/path that could
# smuggle a second allowlist entry). A bare hostname (letters/digits/dot/dash)
# plus a numeric port.
_HOST_PORT_RE = re.compile(r"[A-Za-z0-9.-]+:[0-9]{1,5}")


@dataclass(frozen=True)
class ForkConfig:
    """Fork-target settings (optional `fork:` block in config.yaml).

    Presence of this on a TargetConfig is the single switch that makes the
    pipeline treat a target as a forked-mainnet target: find/grade get the RPC
    env injected and the find/grade prompts switch to their fork-aware path.
    Everything here is per-target, so the relaxation it implies (an RPC host on
    the egress allowlist, an RPC URL in the agent container) never touches a
    non-fork target.
    """
    rpc_env: str              # env var name set in the find+grade containers (e.g. ETH_RPC_URL)
    rpc_url_template: str      # ${VAR} expanded from the orchestrator host env at launch
    block: int                 # fork block number, threaded into the prompts
    egress_hosts: list[str] = field(default_factory=list)  # extra host:port the agent/grader needs

    @classmethod
    def parse(cls, raw: dict) -> ForkConfig:
        try:
            rpc_env = str(raw["rpc_env"])
            rpc_url_template = str(raw["rpc_url_template"])
            block = int(raw["block"])
        except (KeyError, TypeError, ValueError) as e:
            raise ValueError(f"invalid fork: block — need rpc_env, rpc_url_template, block ({e})")
        hosts = [str(h) for h in (raw.get("egress_hosts") or [])]
        bad = [h for h in hosts if not _HOST_PORT_RE.fullmatch(h)]
        if bad:
            raise ValueError(f"invalid fork.egress_hosts entries (want host:port): {bad}")
        return cls(rpc_env=rpc_env, rpc_url_template=rpc_url_template, block=block, egress_hosts=hosts)


@dataclass(frozen=True)
class TargetConfig:
    name: str
    dockerfile_dir: str   # build context dir (the target dir itself)
    image_tag: str
    github_url: str
    commit: str
    source_root: str      # path inside the built container
    binary_path: str | None = None  # path inside the built container; None for targets with no single binary (e.g. Solidity/Foundry)
    focus_areas: list[str] = field(default_factory=list)
    known_bugs: list[str] = field(default_factory=list)
    attack_surface: str | None = None
    build_command: str | None = None  # rebuild in-container after applying a patch (T0)
    test_command: str | None = None   # regression suite for T2; None → T2 skipped
    build_timeout_s: int = 1800
    shm_size: str | None = None       # docker --shm-size
    memory_limit: str = "4g"          # docker --memory
    reattack_harness: str | None = None  # in-image script that runs every /poc/* and exits 1 on crash
    fork: ForkConfig | None = None    # set for forked-mainnet targets (optional `fork:` block)

    @classmethod
    def load(cls, target_dir: str | Path) -> TargetConfig:
        target_dir = Path(target_dir).resolve()
        config_path = target_dir / "config.yaml"
        if not config_path.exists():
            raise FileNotFoundError(f"No config.yaml in {target_dir}")

        with open(config_path) as f:
            cfg = yaml.safe_load(f)

        if cfg.get("kind") == "dnr":
            raise ValueError(
                f"target '{target_dir.name}' is a detection & response target "
                "(kind: dnr), not a vuln-pipeline build target — see "
                f"targets/{target_dir.name}/README.md for how to run it"
            )

        return cls(
            name=target_dir.name,
            dockerfile_dir=str(target_dir),
            image_tag=cfg["image_tag"],
            github_url=cfg["github_url"],
            commit=cfg["commit"],
            source_root=cfg["source_root"],
            binary_path=cfg.get("binary_path"),
            focus_areas=cfg.get("focus_areas") or [],
            known_bugs=cfg.get("known_bugs") or [],
            attack_surface=cfg.get("attack_surface"),
            build_command=cfg.get("build_command"),
            test_command=cfg.get("test_command"),
            build_timeout_s=cfg.get("build_timeout_s", 1800),
            shm_size=cfg.get("shm_size"),
            memory_limit=cfg.get("memory_limit", "4g"),
            reattack_harness=cfg.get("reattack_harness"),
            fork=ForkConfig.parse(cfg["fork"]) if cfg.get("fork") else None,
        )
