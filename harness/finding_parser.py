# Copyright 2026 Anthropic PBC
# Copyright 2026 Contract Security Agent contributors
# SPDX-License-Identifier: Apache-2.0
"""Foundry/Slither/Halmos finding parsing — the Solidity analog of asan.py.

Shared by the runtime found-bugs jsonl (cli.py) and post-hoc dedup (dedup.py).
Where asan.py regex-parses an AddressSanitizer stack trace, this module parses
`forge test --json` / Halmos JSON output: there is no sanitizer signal, so the
detector is a failing Foundry test (an exploit/invariant-violation the find
agent wrote) plus, where available, a matching Slither detector's own
vulnerability-class label (`check`, e.g. "reentrancy-eth") as free, tool-
reported taxonomy — stronger ground truth than regexing a crash string.

Exposes the same four function names asan.py did (`project_frames`,
`top_frame`, `crash_reason`, `asan_excerpt`) so cli.py/dedup.py/novelty.py's
call sites don't need touching — only the import source. `crash_output` here
holds `forge test --json` (or Halmos JSON) stdout, not a sanitizer trace.
"""
from __future__ import annotations

import json
import re


# find-agents name exploit tests `test_Exploit_<Class>_<...>` and safety/
# property tests `test_Safety_<Requirement>` (see find_prompt.py's output
# contract). `<Class>` free text, e.g. Reentrancy, AccessControl, Accounting.
_TEST_CLASS = re.compile(r"test_(?:Exploit|Safety)_([A-Za-z0-9]+)")


def _iter_failures(crash_output: str) -> list[dict]:
    """Every non-passing test from a `forge test --json` suite map.

    Returns `[]` on anything that isn't a well-formed suite map (invalid
    JSON, compilation failure, no tests) — callers treat that as "no finding
    parsed", matching asan.py's `project_frames` returning `[]` on unparseable
    input. A test counts as a failure if its Foundry status is "Failure" —
    "Success"/"Skipped" are not findings.
    """
    try:
        suites = json.loads(crash_output)
        if not isinstance(suites, dict):
            return []
    except (ValueError, TypeError):
        return []
    out: list[dict] = []
    for suite_path, suite in suites.items():
        if not isinstance(suite, dict):
            continue
        for test_name, result in (suite.get("test_results") or {}).items():
            if not isinstance(result, dict) or result.get("status") != "Failure":
                continue
            out.append({
                "suite": suite_path,
                "test": test_name,
                "reason": result.get("reason"),
                "counterexample": result.get("counterexample"),
                "decoded_logs": result.get("decoded_logs") or [],
            })
    return out


def _halmos_counterexamples(crash_output: str) -> list[dict]:
    """Every Halmos test with a *validated* (`is_valid: true`) counterexample.

    Mirrors execution.py's `_classify_halmos`: Halmos emits progress text
    before its own JSON object, so scan for `{` and keep the last value that
    looks like a Halmos result (has `test_results` + `exitcode`). An
    unvalidated symbolic model is not a finding — same discipline as the
    audit CLI's `ToolRunner._classify_halmos`.
    """
    data = None
    decoder = json.JSONDecoder()
    for match in re.finditer(r"\{", crash_output):
        try:
            value, _ = decoder.raw_decode(crash_output[match.start():])
            if isinstance(value, dict) and "test_results" in value and "exitcode" in value:
                data = value
        except ValueError:
            continue
    groups = (data or {}).get("test_results") or {}
    out: list[dict] = []
    if not isinstance(groups, dict):
        return out
    for path, group in groups.items():
        if not isinstance(path, str) or not isinstance(group, list):
            continue
        for test in group:
            if not isinstance(test, dict) or test.get("exitcode") != 1:
                continue
            models = test.get("models") or []
            if any(isinstance(m, dict) and m.get("is_valid") is True for m in models):
                out.append({"suite": path, "test": test.get("name", "?"), "reason": "halmos_counterexample",
                            "counterexample": next((m for m in models if isinstance(m, dict) and m.get("is_valid")), None),
                            "decoded_logs": []})
    return out


def project_frames(crash_output: str, n: int = 3) -> list[str]:
    """Up to n `Contract::test` identifiers for the failing/counterexample tests.

    Solidity analog of asan.py's stack frames: there's no call stack to walk,
    so "frames" are distinct failing tests, most-specific (narrowest suite
    path) first — same contract as asan.py's `[]` on nothing parsed.
    """
    failures = _iter_failures(crash_output) or _halmos_counterexamples(crash_output)
    return [f"{f['suite']}::{f['test']}" for f in failures[:n]]


def top_frame(crash_output: str) -> str | None:
    """First failing test identifier (convenience wrapper)."""
    frames = project_frames(crash_output, n=1)
    return frames[0] if frames else None


def crash_reason(crash_output: str) -> dict[str, str | None]:
    """vulnerability class (from the test name's `_Class_` segment) + revert reason.

    Display-only, same as asan.py's `crash_reason`: feeds found_bugs.jsonl
    excerpts and dedup summaries. Not a decision input — judge/report agents
    read the full excerpt and judge semantic duplicates themselves, never a
    string-equality match on this classification.
    """
    failures = _iter_failures(crash_output) or _halmos_counterexamples(crash_output)
    if not failures:
        return {"crash_type": None, "operation": None}
    first = failures[0]
    m = _TEST_CLASS.search(first["test"])
    return {"crash_type": m.group(1) if m else "unclassified", "operation": first.get("reason")}


def asan_excerpt(crash_output: str, max_frames: int = 10) -> str:
    """Failing-test identifiers + revert reasons + decoded logs, for dedup context.

    Solidity analog of asan.py's SUMMARY-line + stack-frame excerpt: compact
    enough (~500 bytes) for a find- or judge-agent to compare signatures
    semantically without replaying the full test.
    """
    failures = (_iter_failures(crash_output) or _halmos_counterexamples(crash_output))[:max_frames]
    if not failures:
        return crash_output.strip().splitlines()[0] if crash_output.strip() else ""
    out: list[str] = []
    for f in failures:
        line = f"{f['suite']}::{f['test']}"
        if f.get("reason"):
            line += f" — {f['reason']}"
        out.append(line)
        for log in (f.get("decoded_logs") or [])[:2]:
            out.append(f"    {log}")
    return "\n".join(out)


def has_failures(crash_output: str) -> bool:
    """True if `crash_output` still shows a failing Foundry test or a
    validated Halmos counterexample.

    T1 oracle for patch grading: a patched re-run of the originally-failing
    test passes iff this is False.
    """
    return bool(_iter_failures(crash_output) or _halmos_counterexamples(crash_output))
