# Copyright 2026 Anthropic PBC
# SPDX-License-Identifier: Apache-2.0
"""Post-hoc crash deduplication: signature extraction + results-tree grouping.

Summary-only view now — the judge agent gates report dispatch in streaming
mode; dedup just answers "these N crashes cluster into M signatures".
"""
import json

from harness.dedup import _signature, dedup, format_report, NO_FRAME


# ── _signature ───────────────────────────────────────────────────────────────
# Fixtures are `forge test --offline --json` / Halmos JSON output (what
# finding_parser.py actually parses), not ASAN traces.

SUITE_A = "test/audit/Exploit_Reentrancy_DrainVault.t.sol:ExploitTest"
TEST_A = "test_Exploit_Reentrancy_DrainVault"
REASON_A = "VIOLATION: attacker drained other depositors' funds via reentrant withdraw"
TRACE_A = json.dumps({SUITE_A: {"test_results": {f"{TEST_A}()": {
    "status": "Failure", "reason": REASON_A, "decoded_logs": [],
}}}})

SUITE_B = "test/audit/Exploit_AccessControl_SetFeeRecipient.t.sol:ExploitTest"
TEST_B = "test_Exploit_AccessControl_SetFeeRecipient"
REASON_B = "VIOLATION: unauthorized caller changed fee recipient"
TRACE_B = json.dumps({SUITE_B: {"test_results": {f"{TEST_B}()": {
    "status": "Failure", "reason": REASON_B, "decoded_logs": [],
}}}})

# Same finding as TRACE_A, but as a Halmos counterexample instead of a forge
# test failure — a different raw shape that should still dedup identically
# *given the same suite identifier* (in practice each tool's path format may
# differ; the point here is that _signature()/top_frame() treat whatever
# identifier they're given as an opaque key, not that forge and Halmos
# happen to agree on formatting).
HALMOS_TRACE_A = json.dumps({
    "test_results": {SUITE_A: [
        {"name": f"{TEST_A}()", "exitcode": 1, "models": [{"is_valid": True, "args": {"amount": 1}}]},
    ]},
    "exitcode": 1,
})


def test_signature_basic():
    crash = {"crash_type": "Reentrancy", "crash_output": TRACE_A}
    assert _signature(crash) == ("Reentrancy", f"{SUITE_A}::{TEST_A}()")


def test_signature_skips_interceptor():
    # Historical name (upstream skipped ASAN interceptor frames); here it
    # just confirms a distinct finding gets its own distinct signature.
    crash = {"crash_type": "AccessControl", "crash_output": TRACE_B}
    assert _signature(crash) == ("AccessControl", f"{SUITE_B}::{TEST_B}()")


def test_signature_assertion():
    # A Halmos counterexample for the SAME exploit as TRACE_A should dedup
    # to the same signature as the forge-test version — format-agnostic.
    forge_crash = {"crash_type": "Reentrancy", "crash_output": TRACE_A}
    halmos_crash = {"crash_type": "Reentrancy", "crash_output": HALMOS_TRACE_A}
    assert _signature(forge_crash) == _signature(halmos_crash)


def test_signature_no_frame_fallback():
    crash = {"crash_type": "SEGV", "crash_output": "<no parseable stack>"}
    assert _signature(crash) == ("SEGV", NO_FRAME)


def test_signature_missing_fields():
    assert _signature({}) == ("unknown", NO_FRAME)
    assert _signature({"crash_type": None, "crash_output": None}) == ("unknown", NO_FRAME)


# ── dedup (results tree walk) ────────────────────────────────────────────────

def _write_result(path, status, crash_type=None, crash_output=None):
    path.parent.mkdir(parents=True, exist_ok=True)
    crash = None
    if crash_type is not None:
        crash = {
            "poc_path": "/tmp/poc.bin",
            "poc_bytes": "AAAA",
            "reproduction_command": "/work/entry /tmp/poc.bin",
            "crash_type": crash_type,
            "crash_output": crash_output or "",
            "exit_code": 134,
        }
    path.write_text(json.dumps({
        "target": "synthetic", "status": status, "crash": crash,
        "verdict": None, "timings": {}, "error": None,
        "find_transcript": "stub", "grade_transcript": "stub",
    }))


SIG_A = ("Reentrancy", f"{SUITE_A}::{TEST_A}()")
SIG_B = ("AccessControl", f"{SUITE_B}::{TEST_B}()")


def _build_tree(tmp_path):
    """3 crashes on signature A, 1 on B, plus a no-crash and a rejected-on-A."""
    root = tmp_path / "results" / "synthetic" / "20260101T000000Z"

    # run_000, run_002: same bug, both passed
    _write_result(root / "run_000" / "result.json", "crash_found",
                  "Reentrancy", TRACE_A)
    _write_result(root / "run_002" / "result.json", "crash_found",
                  "Reentrancy", TRACE_A)

    # run_003: same bug, grader bounced it — still groups with the above
    _write_result(root / "run_003" / "result.json", "crash_rejected",
                  "Reentrancy", TRACE_A)

    # run_001: different bug
    _write_result(root / "run_001" / "result.json", "crash_found",
                  "AccessControl", TRACE_B)

    # run_004: no crash — should be skipped
    _write_result(root / "run_004" / "result.json", "no_crash_found")

    return root


def test_dedup_groups_duplicates(tmp_path):
    root = _build_tree(tmp_path)
    groups = dedup(root)

    assert set(groups.keys()) == {SIG_A, SIG_B}
    assert len(groups[SIG_A]) == 3
    assert len(groups[SIG_B]) == 1


def test_dedup_includes_rejected(tmp_path):
    root = _build_tree(tmp_path)
    groups = dedup(root)

    statuses = {status for _, status, _ in groups[SIG_A]}
    assert statuses == {"crash_found", "crash_rejected"}


def test_dedup_parses_operation(tmp_path):
    root = _build_tree(tmp_path)
    groups = dedup(root)

    ops_a = {r["operation"] for _, _, r in groups[SIG_A]}
    ops_b = {r["operation"] for _, _, r in groups[SIG_B]}
    assert ops_a == {REASON_A}
    assert ops_b == {REASON_B}


def test_dedup_signature_prefers_parsed_type(tmp_path):
    # Agent wrote free-text "overflow!!" but the test actually failed as a
    # parseable Reentrancy finding.
    root = tmp_path / "batch"
    _write_result(root / "run_000" / "result.json", "crash_found",
                  "overflow!!", TRACE_A)
    groups = dedup(root)
    # Signature key uses the pipeline-parsed type, not the agent tag.
    assert SIG_A in groups


def test_dedup_skips_null_crash(tmp_path):
    root = _build_tree(tmp_path)
    groups = dedup(root)

    # 5 result.json files, but only 4 have a crash
    total = sum(len(v) for v in groups.values())
    assert total == 4


def test_dedup_walks_nested_batches(tmp_path):
    # Two timestamp dirs, each with a single-run layout (no run_NNN subdir)
    target_root = tmp_path / "results" / "synthetic"
    _write_result(target_root / "20260101T000000Z" / "result.json", "crash_found",
                  "Reentrancy", TRACE_A)
    _write_result(target_root / "20260102T000000Z" / "result.json", "crash_found",
                  "Reentrancy", TRACE_A)

    groups = dedup(target_root)
    assert len(groups) == 1
    (_, entries), = groups.items()
    assert len(entries) == 2


def test_dedup_skips_malformed_json(tmp_path):
    root = tmp_path / "batch"
    _write_result(root / "run_000" / "result.json", "crash_found",
                  "Reentrancy", TRACE_A)
    (root / "run_001").mkdir(parents=True)
    (root / "run_001" / "result.json").write_text("{ not valid json")

    groups = dedup(root)
    # good run survives; bad one silently skipped
    assert sum(len(v) for v in groups.values()) == 1


def test_dedup_empty_dir(tmp_path):
    assert dedup(tmp_path) == {}


# ── format_report ────────────────────────────────────────────────────────────

def test_format_report_sorted_by_count(tmp_path):
    root = _build_tree(tmp_path)
    groups = dedup(root)
    report = format_report(groups, root)

    # A (3 crashes) sorts before B (1 crash) — larger group first.
    pos_a = report.index("Reentrancy")
    pos_b = report.index("AccessControl")
    assert pos_a < pos_b

    assert "[3x]" in report
    assert "[1x]" in report
    assert "2 unique signature(s) across 4 crash(es)" in report


def test_format_report_shows_operation(tmp_path):
    root = _build_tree(tmp_path)
    report = format_report(dedup(root), root)
    assert f"AccessControl ({REASON_B})" in report
    assert f"Reentrancy ({REASON_A})" in report


def test_format_report_shows_relative_paths(tmp_path):
    root = _build_tree(tmp_path)
    report = format_report(dedup(root), root)

    assert "run_000/result.json" in report
    assert str(tmp_path) not in report  # absolute prefix stripped


def test_format_report_shows_status(tmp_path):
    root = _build_tree(tmp_path)
    report = format_report(dedup(root), root)
    assert "(crash_found)" in report
    assert "(crash_rejected)" in report


def test_format_report_empty():
    assert format_report({}) == "No crashes found.\n"
