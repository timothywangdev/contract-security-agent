# Copyright 2026 Anthropic PBC
# Copyright 2026 Contract Security Agent contributors
# SPDX-License-Identifier: Apache-2.0
"""Portable audit records and reports, adapted from the reference report stage.

Upstream report.py and artifacts.py at d3bea6b5793b5f3d59a75ebe69a58efa88383145
separate claimed severity, reachability and grading. This deterministic renderer
preserves that separation without a model-generated exploitability verdict.
"""
from __future__ import annotations

import hashlib
import html
import json
import re
import shlex
import zipfile
from pathlib import Path, PurePosixPath
from typing import Any

_SECRET = re.compile(r"(?:api[_-]?key|access[_-]?token|auth[_-]?token|authorization|password|secret|credentials?)$", re.I)


def _redact(value: Any) -> Any:
    if isinstance(value, dict):
        return {str(k): "[REDACTED]" if _SECRET.search(str(k)) else _redact(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_redact(v) for v in value]
    if isinstance(value, Path):
        return str(value)
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    return str(value)


def _text(value: Any) -> str:
    if value is None or value == "":
        return "Not recorded"
    if isinstance(value, (dict, list, tuple)):
        value = json.dumps(value, sort_keys=True, ensure_ascii=False)
    # Raw model text must not create HTML, external links, images or headings.
    text = html.escape(str(value), quote=False)
    text = " ".join(text.replace("\x00", "").splitlines())
    return re.sub(r"([\\`*_{}\[\]()#!|])", r"\\\1", text)


def _items(value: Any) -> list:
    if isinstance(value, list):
        return value
    if isinstance(value, dict):
        return [{"name": k, **v} if isinstance(v, dict) else {"name": k, "value": v} for k, v in value.items()]
    return [] if value is None else [value]


def _result_lines(results: Any) -> list[str]:
    lines = []
    for entry in _items(results):
        if not isinstance(entry, dict):
            lines.append(f"- {_text(entry)}")
            continue
        result = entry.get("result", entry)
        if not isinstance(result, dict):
            lines.append("- Invalid tool result; coverage remains incomplete.")
            continue
        prop = entry.get("property")
        name = result.get("tool", result.get("name", "unnamed tool"))
        status = result.get("status", "not recorded")
        subject = f"{name} / {prop.get('id', 'unnamed property')}" if isinstance(prop, dict) else name
        line = f"- {_text(subject)}: **{_text(status)}**"
        summary = result.get("summary", result.get("error", result.get("reason")))
        if summary:
            line += f". {_text(summary)}"
        metadata = result.get("metadata") if isinstance(result.get("metadata"), dict) else {}
        details = []
        for key, label in (("selected_tests", "selected tests"), ("skipped_tests", "skipped"), ("failed_tests", "failed")):
            if key in metadata:
                details.append(f"{_text(metadata[key])} {label}")
        detectors = metadata.get("detectors")
        if isinstance(detectors, (list, dict)):
            details.append(f"{len(detectors)} detector result(s)")
        for key in ("failure_kind", "reason"):
            if metadata.get(key):
                details.append(_text(metadata[key]))
        if metadata.get("bounded"):
            details.append("bounded exploration")
        if metadata.get("output_truncated"):
            details.append("output truncated")
        if metadata.get("cleanup_unconfirmed"):
            details.append("worker cleanup unconfirmed")
        if details:
            line += ". " + "; ".join(details)
        lines.append(line + ".")
        if isinstance(prop, dict):
            lines.append(f"  Property: {_text(prop.get('description'))}. Requirement: {_text(prop.get('requirement_id'))}.")
            lines.append(f"  Assumptions: {_list_text(prop.get('assumptions'))}.")
        limits = result.get("limits", result.get("bounds"))
        if not limits and isinstance(prop, dict):
            limits = prop.get("limits", prop.get("bounds"))
        if not limits:
            limits = metadata.get("limits", metadata.get("bounds"))
        if limits:
            lines.append(f"  Limits: {_text(limits)}")
        elif isinstance(prop, dict):
            lines.append("  Limits: configured solver defaults and execution timeout; no exhaustive proof claim.")
    return lines or ["- Not run or not recorded; coverage remains incomplete."]


def _list_text(values: Any) -> str:
    if isinstance(values, (list, tuple)):
        return "; ".join(_text(v) for v in values) if values else "None recorded"
    return _text(values)


def _source_summary(source: Any) -> str:
    if not isinstance(source, dict):
        return _text(source)
    revision = source.get("git_revision", source.get("commit", source.get("revision")))
    details = [f"revision {_text(revision)}"]
    files = source.get("files")
    if isinstance(files, (list, dict)):
        details.append(f"{len(files)} snapshot files")
    if source.get("total_bytes") is not None:
        details.append(f"{_text(source['total_bytes'])} bytes")
    if source.get("tree_sha256"):
        details.append(f"tree SHA256 {_text(source['tree_sha256'])}")
    return "; ".join(details) + ". Per-file hashes are in report.json."


def _provenance_lines(record: dict) -> list[str]:
    config = record.get("config") if isinstance(record.get("config"), dict) else {}
    diagnostics = record.get("diagnostics") if isinstance(record.get("diagnostics"), dict) else {}
    usage = record.get("usage") if isinstance(record.get("usage"), dict) else {}
    image = diagnostics.get("image", config.get("image"))
    model = usage.get("resolved_model", config.get("model"))
    lines = [f"- Model: {_text(model)}. Runtime: {_text(usage.get('runtime_version'))}.",
             f"- Tool image: {_text(image)}. Image ID: {_text(diagnostics.get('image_id'))}."]
    versions = diagnostics.get("pinned_tools")
    if isinstance(versions, dict):
        lines.append("- Pinned tools: " + "; ".join(f"{_text(k)} {_text(v)}" for k, v in versions.items()) + ".")
    budget = [("max_budget_usd", "model budget USD"), ("max_turns", "model turn limit"),
              ("tool_timeout_seconds", "tool timeout seconds"), ("formal_timeout_seconds", "formal timeout seconds"),
              ("audit_timeout_seconds", "audit timeout seconds")]
    limits = [f"{label}: {_text(config[key])}" for key, label in budget if key in config]
    if limits:
        lines.append("- Limits: " + "; ".join(limits) + ".")
    return lines


def _protocol_lines(protocol: Any) -> list[str]:
    if not isinstance(protocol, dict):
        return [_text(protocol)]
    lines = [_text(protocol.get("summary")), ""]
    for key, label in (("assets", "Assets"), ("roles", "Roles"), ("entry_points", "Entry points"),
                       ("trust_boundaries", "Trust boundaries"), ("assumptions", "Assumptions"),
                       ("open_questions", "Unknowns requiring review")):
        if key in protocol:
            lines.append(f"- {label}: {_list_text(protocol[key])}")
    return lines


def _requirement_lines(requirements: Any) -> list[str]:
    lines = []
    for requirement in _items(requirements):
        if not isinstance(requirement, dict):
            lines.append(f"- {_text(requirement)}")
            continue
        identifier = requirement.get("id", requirement.get("name"))
        reviewed = requirement.get("reviewed") is True or requirement.get("status") == "reviewed"
        text = requirement.get("text", requirement.get("description", ""))
        lines.append(f"- {_text(identifier)}: {_text(text)} (**{'reviewed' if reviewed else 'requires review'}**).")
        if requirement.get("assumptions"):
            lines.append(f"  Assumptions: {_list_text(requirement['assumptions'])}.")
    return lines or ["- No reviewed requirements supplied. Requirement-dependent claims need protocol-owner review."]


def _coverage_lines(coverage: Any) -> list[str]:
    if not isinstance(coverage, dict):
        return [f"- {_text(coverage)}"]
    lines = []
    for item in _items(coverage.get("completed")):
        lines.append(f"- Completed: {_text(item)}")
    for item in _items(coverage.get("gaps")):
        lines.append(f"- Gap: {_text(item)}")
    return lines or ["- No completed coverage or explicit gaps recorded; review tool limits above."]


def _replay_summary(replays: Any) -> str:
    parts = []
    for replay in _items(replays):
        if not isinstance(replay, dict):
            continue
        tests = replay.get("observed_tests", [])
        tests = tests if isinstance(tests, list) else []
        part = f"attempt {_text(replay.get('attempt'))}: {_text(replay.get('status'))}, {len(tests)} test(s)"
        failures = [test.get("reason") for test in tests if isinstance(test, dict) and test.get("reason")]
        if failures:
            part += f", {_text(failures[0])}"
        parts.append(part)
    return "; ".join(parts) or "Not run"


def _finding_parts(finding: Any) -> tuple[dict, dict]:
    if not isinstance(finding, dict):
        return {"title": str(finding)}, {}
    candidate = finding.get("candidate")
    if isinstance(candidate, dict):
        return candidate, finding
    return finding, finding.get("evidence", {}) if isinstance(finding.get("evidence"), dict) else finding


def _safe_destination(output: Path, name: str) -> Path:
    target = output / name
    if any(p.is_symlink() for p in (target, *target.absolute().parents)):
        raise ValueError("report artifacts cannot traverse symlinks")
    return target


def _evidence_files(record: dict, output: Path) -> list[str]:
    artifacts = []
    findings = _items(record.get("findings"))
    if not findings:
        findings = _items(record.get("candidates"))
    for index, item in enumerate(findings, 1):
        candidate, evidence = _finding_parts(item)
        groups = [("", evidence.get("test_files", candidate.get("test_files", {}))),
                  ("trusted/", evidence.get("trusted_test_files", {}))]
        for prefix, files in groups:
            if not isinstance(files, dict):
                continue
            for name, contents in files.items():
                if not isinstance(name, str) or not isinstance(contents, str):
                    continue
                path = PurePosixPath(name)
                if (path.is_absolute() or "\\" in name or path.as_posix() != name
                        or len(path.parts) != 3 or path.parts[:2] != ("test", "audit")
                        or not name.endswith(".t.sol") or ".." in path.parts):
                    continue
                relative = f"report-evidence/candidate-{index:03d}/{prefix}{name}"
                target = _safe_destination(output, relative)
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_text(contents, encoding="utf-8")
                artifacts.append(relative)
        if evidence.get("trusted_test_files") and isinstance(evidence.get("trusted_metadata"), dict):
            relative = f"report-evidence/candidate-{index:03d}/trusted/metadata.json"
            target = _safe_destination(output, relative)
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(json.dumps(evidence["trusted_metadata"], indent=2) + "\n", encoding="utf-8")
            artifacts.append(relative)
    return artifacts


def render_report(record: dict, output: Path) -> dict:
    """Write deterministic Markdown/JSON plus a hashed, traversal-safe ZIP bundle."""
    if not isinstance(record, dict):
        raise ValueError("audit record must be an object")
    output = Path(output).absolute()
    _safe_destination(output, "report.json")
    output.mkdir(parents=True, exist_ok=True)
    record = _redact(record)
    findings = _items(record.get("findings"))
    candidates = _items(record.get("candidates"))
    validated = sum(1 for f in findings if isinstance(f, dict) and f.get("validated") is True)
    pending = len(findings) - validated
    lines = ["# Smart contract security audit", "", "## Executive summary", "",
             f"Project: {_text(record.get('project'))}. Run: {_text(record.get('run_id'))}. Status: **{_text(record.get('status', 'incomplete'))}**.", "",
             f"{validated} requirement violation(s) validated by reviewed executable checks; {pending} reported candidate(s) pending evidence or review; {len(candidates)} discovered candidate(s).",
             "", "Severity is a candidate assessment. Execution evidence, semantic validation and human review are separate states.", ""]
    if not validated:
        lines += ["No independently validated security issue was established by this run. This is not a clean-security claim or a guarantee that the contracts are safe.", ""]
    lines += ["## Scope and provenance", "",
              f"- Source revision and integrity: {_source_summary(record.get('source'))}",
              f"- Reviewed scope and exclusions: {_list_text(record.get('scope'))}"]
    lines += _provenance_lines(record)
    lines += [
              "- Harness adaptation: Anthropic defending-code-reference-harness, revision d3bea6b5793b5f3d59a75ebe69a58efa88383145 (Apache-2.0).", "",
              "## Protocol and threat map", ""]
    lines += _protocol_lines(record.get("protocol"))
    lines += ["", "## Requirements, assumptions and unknowns", ""]
    lines += _requirement_lines(record.get("requirements"))
    lines += ["", "## Baseline and bounded formal results", ""]
    lines += _result_lines(record.get("baseline"))
    lines += ["", "Formal and invariant checks:", ""] + _result_lines(record.get("formal_results"))
    lines += ["", "Tool success and bounded exploration do not prove the absence of vulnerabilities. Unsupported, skipped, timed out and inconclusive stages remain coverage gaps.", "",
              "## Findings and candidate evidence", ""]
    if not findings:
        lines += ["No findings recorded. Discovered candidates and full execution records, when present, remain in report.json.", ""]
    for index, finding in enumerate(findings, 1):
        candidate, evidence = _finding_parts(finding)
        lines += [f"### {index}. {_text(candidate.get('title', 'Untitled candidate'))}", "",
                  f"- Candidate ID: {_text(candidate.get('id'))}",
                  f"- Candidate severity: **{_text(candidate.get('severity', 'unrated'))}**. Rationale: {_text(candidate.get('severity_rationale'))}",
                  f"- Evidence status: {_text(evidence.get('status', 'unverified'))}; replay: {_text(evidence.get('replay_status', 'not recorded'))}; semantics: {_text(evidence.get('semantic_status', 'unverified'))}; reviewer: {_text(evidence.get('reviewer_state', 'needs_review'))}.",
                  f"- Requirement: {_text(candidate.get('requirement_id'))}",
                  f"- Affected files: {_text(candidate.get('affected_files'))}",
                  f"- Root cause: {_text(candidate.get('root_cause'))}",
                  f"- Preconditions: {_text(candidate.get('preconditions'))}",
                  f"- Impact: {_text(candidate.get('impact'))}",
                  f"- Remediation: {_text(candidate.get('remediation'))}"]
        command = evidence.get("reproduction_command")
        if not command and candidate.get("test_pattern"):
            command = shlex.join(["forge", "test", "--offline", "--json", "--match-path", "test/audit/**", "--match-test", str(candidate["test_pattern"])])
        lines += [f"- Reproduction command: {_text(command)}",
                  f"- Independent safety command: {_text(evidence.get('trusted_reproduction_command'))}",
                  f"- Replay evidence: {_replay_summary(evidence.get('replays'))}",
                  f"- Independent safety evidence: {_replay_summary(evidence.get('trusted_replays'))}",
                  f"- Evidence limits and errors: {_text(evidence.get('errors', []))}. {_text(evidence.get('semantic_limit', evidence.get('limitation', '')))}", ""]
        repair = evidence.get("retest", evidence.get("repair"))
        if isinstance(repair, dict):
            lines += [f"Repair retest: **{_text(repair.get('status'))}**. Errors: {_list_text(repair.get('errors'))}.", ""]
        elif repair:
            lines += [f"Repair retest: {_text(repair)}", ""]
    lines += ["## Reproduction artifacts", "",
              "report.json contains raw execution records, source hashes, candidate tests and reviewed-check hashes when available. Copy each candidate's report-evidence/candidate-NNN/test/audit/*.t.sol into a checkout matching the recorded source revision, then run its exact reproduction command using the recorded tool image. Reviewed checks, when provided, are frozen separately under each candidate's trusted directory with metadata.json. Replay these in a separate fresh checkout using the independent safety command. Model test success alone is not security validation.", "",
              "## Coverage, gaps and incomplete reasons", ""]
    lines += _coverage_lines(record.get("coverage"))
    lines += ["", f"Run errors: {_list_text(record.get('errors', []))}", "",
              "Any unreviewed assumptions, omitted components, unavailable tools, bounded solver limits, non-reproduced candidates and incomplete stages limit this report. Human review of protocol requirements and impact remains required.", "",
              "## Usage and costs", "", _text(record.get("usage")), "",
              "Missing usage or cost data means unknown, not zero.", ""]
    json_path = _safe_destination(output, "report.json")
    md_path = _safe_destination(output, "report.md")
    json_path.write_text(json.dumps(record, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    md_path.write_text("\n".join(lines), encoding="utf-8")
    members = ["report.json", "report.md", *_evidence_files(record, output)]
    manifest = {"schema_version": 1, "run_id": record.get("run_id"), "hash_algorithm": "sha256",
                "files": {name: hashlib.sha256(_safe_destination(output, name).read_bytes()).hexdigest() for name in members},
                "scope": "Report and portable candidate tests only; original source must match recorded source hashes."}
    manifest_path = _safe_destination(output, "manifest.json")
    manifest_path.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    bundle = _safe_destination(output, "audit-bundle.zip")
    with zipfile.ZipFile(bundle, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for name in [*members, "manifest.json"]:
            path = _safe_destination(output, name)
            if path.is_file():
                archive.write(path, arcname=name)
    return {"report_json": str(json_path), "report_md": str(md_path), "manifest": str(manifest_path), "bundle": str(bundle)}
