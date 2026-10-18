"""Operator-supplied configuration; audited repositories cannot grant permissions."""
from __future__ import annotations

import json
import math
import re
from pathlib import Path


DEFAULTS = {
    "model": "sonnet",
    "max_budget_usd": 2.0,
    "max_turns": 3,
    "model_timeout_seconds": 180,
    "tool_timeout_seconds": 90,
    "formal_timeout_seconds": 60,
    "audit_timeout_seconds": 600,
    "max_source_bytes": 120_000,
    "max_snapshot_bytes": 50_000_000,
    "max_candidates": 3,
    "max_output_bytes": 200_000,
    "image": "contract-security-agent-tools:dev",
    "memory": "2g",
    "cpus": 2,
    "pids_limit": 256,
}


def load_config(path: Path | None = None, overrides: dict | None = None) -> dict:
    supplied = json.loads(path.read_text()) if path else {}
    if not isinstance(supplied, dict):
        raise ValueError("Audit configuration must be a JSON object")
    unknown = set(supplied) - set(DEFAULTS)
    unknown |= set(overrides or {}) - set(DEFAULTS)
    if unknown:
        raise ValueError(f"Unknown configuration keys: {', '.join(sorted(unknown))}")
    config = DEFAULTS | supplied | {k: v for k, v in (overrides or {}).items() if v is not None}
    for key in DEFAULTS:
        if key in {"model", "image", "memory"}:
            continue
        value = config[key]
        if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value) or value <= 0:
            raise ValueError(f"{key} must be a positive finite number")
        if key not in {"max_budget_usd", "cpus"} and int(value) != value:
            raise ValueError(f"{key} must be a whole number")
        if key not in {"max_budget_usd", "cpus"}:
            config[key] = int(value)
    if not isinstance(config["model"], str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.:/-]*", config["model"]):
        raise ValueError("Invalid Claude model identifier")
    if not isinstance(config["image"], str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.:/@-]*", config["image"]):
        raise ValueError("Invalid Docker image reference")
    if not isinstance(config["memory"], str) or not re.fullmatch(r"[1-9][0-9]*[mg]", config["memory"]):
        raise ValueError("memory must be a Docker memory limit such as 2g or 512m")
    return config


def load_requirements(path: Path | None) -> list[dict]:
    if path is None:
        return []
    data = json.loads(path.read_text())
    if not isinstance(data, list):
        raise ValueError("Requirements must be a JSON array")
    seen = set()
    result = []
    for item in data:
        if not isinstance(item, dict) or not isinstance(item.get("id"), str) or not isinstance(item.get("text"), str):
            raise ValueError("Each requirement needs an id and plain-language text")
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,79}", item["id"]) or item["id"] in seen:
            raise ValueError("Requirement IDs must be unique safe identifiers")
        if not isinstance(item.get("reviewed", False), bool):
            raise ValueError("Requirement reviewed must be true or false")
        assumptions = item.get("assumptions", [])
        if not isinstance(assumptions, list) or not all(isinstance(x, str) for x in assumptions):
            raise ValueError("Requirement assumptions must be a list of strings")
        seen.add(item["id"])
        result.append({"id": item["id"], "text": item["text"], "reviewed": item.get("reviewed", False), "assumptions": assumptions})
    return result
