# Copyright 2026 Contract Security Agent contributors
# SPDX-License-Identifier: Apache-2.0
"""Checkpointed Solidity adaptation of the upstream find/grade/report pipeline."""
from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re
import tarfile
import time
import uuid

from . import __version__
from .config import load_config
from .snapshot import copy_snapshot, copy_trusted_checks, file_manifest

UPSTREAM_REVISION = "d3bea6b5793b5f3d59a75ebe69a58efa88383145"


def new_output(base: Path | None = None, suffix: str = "") -> Path:
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    output = base or Path("results") / f"{stamp}-{uuid.uuid4().hex[:8]}{suffix}"
    output = output.absolute()
    if any(part.is_symlink() for part in (output, *output.parents)):
        raise ValueError("Output paths may not traverse symlinks")
    output.mkdir(parents=True, exist_ok=False)
    return output


def write_json(path: Path, data: dict) -> None:
    if path.is_symlink():
        raise ValueError("Refusing to overwrite a symlink artifact")
    temporary = path.with_suffix(path.suffix + ".tmp")
    if temporary.is_symlink():
        raise ValueError("Refusing to overwrite a symlink artifact")
    temporary.write_text(json.dumps(data, indent=2, ensure_ascii=False, default=str) + "\n")
    temporary.replace(path)


def _checkpoint(output: Path, record: dict, stage: str) -> None:
    record["stage"] = stage
    write_json(output / "record.json", record)
    event = {"time": datetime.now(timezone.utc).isoformat(), "stage": stage, "status": record["status"]}
    with (output / "events.jsonl").open("a") as stream:
        stream.write(json.dumps(event) + "\n")


def _finish(output: Path, record: dict, start: float) -> dict:
    from .reporting import render_report

    record["duration_seconds"] = round(time.monotonic() - start, 3)
    record["finished_at"] = datetime.now(timezone.utc).isoformat()
    _checkpoint(output, record, "report")
    record["artifacts"] = render_report(record, output)
    _checkpoint(output, record, "finished")
    # The checksummed source and tests are portable; no local credential files
    # or model configuration directories are included in the reproduction bundle.
    items = sorted(p for p in output.rglob("*") if p.is_file() and p.name != "bundle.tar.gz")
    hashes = {}
    for path in items:
        if path.is_symlink():
            raise ValueError("Cannot bundle a symlink artifact")
        hashes[path.relative_to(output).as_posix()] = hashlib.sha256(path.read_bytes()).hexdigest()
    write_json(output / "bundle-manifest.json", {"sha256": hashes})
    with tarfile.open(output / "bundle.tar.gz", "w:gz") as archive:
        for path in [*items, output / "bundle-manifest.json"]:
            archive.add(path, arcname=path.relative_to(output).as_posix(), recursive=False)
    return record


def _baseline_build_ok(results: list[dict]) -> bool:
    return any(r.get("name") == "forge_build" and r.get("status") == "passed" for r in results)


def _incomplete(result: dict) -> bool:
    return result.get("status") in {"inconclusive", "unsupported", "error", "skipped"}


def run_audit(project: Path, output: Path, config: dict, scope: list[str],
              requirements: list[dict], trusted_checks: Path | None = None,
              *, no_model: bool = False, runner=None, discover_fn=None) -> dict:
    """Audit a local project; always leave an inspectable report on stage failure."""
    from .discovery import discover
    from .evidence import validate_candidate
    from .execution import ToolRunner

    start = time.monotonic()
    effective = dict(config)
    effective["deadline_monotonic"] = start + config["audit_timeout_seconds"]
    runner = runner or ToolRunner(effective)
    discover_fn = discover_fn or discover
    record = {
        "schema_version": 1, "version": __version__, "run_id": output.name,
        "started_at": datetime.now(timezone.utc).isoformat(), "status": "running",
        "upstream_revision": UPSTREAM_REVISION, "project": str(project.resolve()),
        "scope": scope, "config": config, "requirements": requirements,
        "source": {}, "protocol": {}, "baseline": [], "candidates": [],
        "findings": [], "formal_results": [], "usage": {}, "errors": [],
        "coverage": {"scope": scope, "completed": [], "gaps": []},
    }
    _checkpoint(output, record, "intake")
    try:
        record["source"] = copy_snapshot(project, output / "source", scope)
        record["scope"] = record["source"]["scope"]
        snapshot = output / "source"
        checks = None
        if trusted_checks:
            checks = output / "trusted-checks"
            copy_trusted_checks(trusted_checks, checks)
        _checkpoint(output, record, "baseline")
        record["diagnostics"] = runner.diagnostics()
        record["baseline"] = runner.run_baseline(snapshot)
        if not _baseline_build_ok(record["baseline"]):
            raise ValueError("Build did not complete in the supported isolated environment; discovery was not attempted")
        record["coverage"]["completed"].append("isolated native build and baseline checks")
        _checkpoint(output, record, "discovery")
        if no_model:
            record["errors"].append("Model discovery explicitly skipped (--no-model); this is an incomplete audit")
        else:
            remaining = effective["deadline_monotonic"] - time.monotonic()
            if remaining <= 0:
                raise TimeoutError("Audit wall-time budget exhausted before discovery")
            model_config = dict(config) | {"model_timeout_seconds": min(config["model_timeout_seconds"], max(1, int(remaining)))}
            discovered = discover_fn(snapshot, record["scope"], requirements, record["baseline"], model_config, output / "discovery")
            record["protocol"] = discovered.get("protocol", {})
            record["usage"] = discovered.get("usage", {})
            record["discovery"] = {k: v for k, v in discovered.items() if k not in {"candidates", "protocol", "formal_properties"}}
            record["errors"].extend(discovered.get("errors", []))
            if discovered.get("status") != "completed":
                record["errors"].append("Model discovery did not complete; zero candidates cannot be interpreted as a clean result")
            candidates = discovered.get("candidates", [])[:config["max_candidates"]]
            seen = set()
            for candidate in candidates:
                identifier = candidate.get("id", "")
                if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,79}", identifier) or identifier in seen:
                    record["errors"].append("Rejected duplicate or unsafe candidate identifier")
                    continue
                seen.add(identifier)
                record["candidates"].append(candidate)
                _checkpoint(output, record, "validation")
                validation = validate_candidate(snapshot, candidate, runner, output / "evidence" / identifier, checks)
                record["findings"].append(validation)
            reviewed = {r["id"] for r in requirements if r.get("reviewed")}
            for index, prop in enumerate(discovered.get("formal_properties", [])[:config["max_candidates"]]):
                _checkpoint(output, record, "formal")
                if prop.get("requirement_id") not in reviewed:
                    result = {"name": "halmos", "status": "skipped", "metadata": {"reason": "requirement_not_reviewed"}, "stderr": "Review the intended requirement before interpreting a generated property", "stdout": ""}
                else:
                    result = runner.run_formal(snapshot, prop.get("test_files", {}), prop.get("test_pattern", ""))
                record["formal_results"].append({"property": prop, "result": result})
            if reviewed and not record["formal_results"]:
                record["coverage"]["gaps"].append("No formal property was produced for the reviewed requirements")
            if not reviewed:
                record["coverage"]["gaps"].append("No reviewed intent: formal claims require review; intake and discovery still ran")
            if discovered.get("status") == "completed":
                record["coverage"]["completed"].append("bounded Claude Code protocol analysis and candidate generation")
        if file_manifest(snapshot)["tree_sha256"] != record["source"]["tree_sha256"]:
            raise ValueError("Audit snapshot was modified during execution")
        if any(_incomplete(r) for r in record["baseline"]):
            record["coverage"]["gaps"].append("One or more baseline tools did not complete")
        if any(_incomplete(p["result"]) for p in record["formal_results"]):
            record["coverage"]["gaps"].append("One or more bounded formal checks did not complete")
        if any(f.get("status") in {"inconclusive", "invalid", "error", "rejected"} for f in record["findings"]):
            record["coverage"]["gaps"].append("One or more candidate checks were invalid or incomplete")
        record["status"] = "incomplete" if record["errors"] or record["coverage"]["gaps"] else "completed"
    except (ValueError, OSError, TimeoutError, RuntimeError) as exc:
        record["status"] = "incomplete"
        record["errors"].append(f"{type(exc).__name__}: {exc}")
        record["coverage"]["gaps"].append(f"Stopped during {record.get('stage', 'audit')}")
    return _finish(output, record, start)


def load_run(directory: Path) -> tuple[dict, Path]:
    directory = directory.resolve()
    record = json.loads((directory / "record.json").read_text())
    source = directory / "source"
    expected = record.get("source", {}).get("tree_sha256")
    if not expected or file_manifest(source)["tree_sha256"] != expected:
        raise ValueError("Saved source does not match the original audit manifest")
    return record, source


def candidate_from(record: dict, identifier: str | None) -> dict:
    choices = [c for c in record.get("candidates", []) if identifier is None or c.get("id") == identifier]
    if len(choices) != 1:
        raise ValueError("Choose exactly one saved candidate using --candidate ID")
    return choices[0]


def reproduce_run(directory: Path, identifier: str | None, output: Path, *, fixed: Path | None = None) -> dict:
    from .evidence import retest_fix, validate_candidate
    from .execution import ToolRunner

    record, source = load_run(directory)
    candidate = candidate_from(record, identifier)
    config = load_config(overrides=record.get("config", {}))
    config["deadline_monotonic"] = time.monotonic() + config["audit_timeout_seconds"]
    runner = ToolRunner(config)
    checks = directory.resolve() / "trusted-checks"
    trusted = checks if checks.is_dir() else None
    if fixed:
        fixed_manifest = copy_snapshot(fixed, output / "fixed-source", record["scope"])
        result = retest_fix(source, output / "fixed-source", candidate, runner, output, trusted)
        result["fixed_source"] = fixed_manifest
    else:
        result = validate_candidate(source, candidate, runner, output, trusted)
    result["original_run"] = record["run_id"]
    write_json(output / "result.json", result)
    return result
