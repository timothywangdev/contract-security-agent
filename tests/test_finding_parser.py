# Copyright 2026 Anthropic PBC
# Copyright 2026 Contract Security Agent contributors
# SPDX-License-Identifier: Apache-2.0
"""finding_parser: forge/Halmos JSON parsing, crash_type + excerpt construction."""
import json

from harness.finding_parser import (
    _halmos_counterexamples,
    _iter_failures,
    asan_excerpt,
    crash_reason,
    has_failures,
    project_frames,
    top_frame,
)


# ── fixtures ─────────────────────────────────────────────────────────────────

FORGE_PASSING = json.dumps({
    "test/audit/Exploit.t.sol:ExploitTest": {
        "test_results": {
            "test_Safety_InvariantHolds()": {
                "status": "Success",
                "reason": None,
                "decoded_logs": [],
            }
        }
    }
})

FORGE_FAILING = json.dumps({
    "test/audit/Exploit.t.sol:ExploitTest": {
        "test_results": {
            "test_Exploit_Reentrancy_DrainVault()": {
                "status": "Failure",
                "reason": "revert: vault drained",
                "decoded_logs": ["Transfer(attacker, 100)"],
            }
        }
    }
})

FORGE_MULTI_SUITE = json.dumps({
    "test/audit/A.t.sol:ATest": {
        "test_results": {
            "test_Exploit_Accounting_Overflow()": {
                "status": "Failure",
                "reason": "arithmetic underflow or overflow",
                "decoded_logs": [],
            }
        }
    },
    "test/audit/B.t.sol:BTest": {
        "test_results": {
            "test_Safety_NoLockup()": {"status": "Success", "reason": None, "decoded_logs": []}
        }
    },
})

HALMOS_VALID = json.dumps({
    "test_results": {
        "test/audit/Invariant.t.sol": [
            {
                "name": "check_invariant_balance",
                "exitcode": 1,
                "models": [{"is_valid": True, "model": "x=1"}],
            }
        ]
    },
    "exitcode": 1,
})

HALMOS_UNVALIDATED = json.dumps({
    "test_results": {
        "test/audit/Invariant.t.sol": [
            {
                "name": "check_invariant_balance",
                "exitcode": 1,
                "models": [{"is_valid": False, "model": "x=1"}],
            }
        ]
    },
    "exitcode": 1,
})


# ── _iter_failures ───────────────────────────────────────────────────────────


def test_iter_failures_empty_on_all_passing():
    assert _iter_failures(FORGE_PASSING) == []


def test_iter_failures_finds_failing_test():
    failures = _iter_failures(FORGE_FAILING)
    assert len(failures) == 1
    assert failures[0]["suite"] == "test/audit/Exploit.t.sol:ExploitTest"
    assert failures[0]["test"] == "test_Exploit_Reentrancy_DrainVault()"
    assert failures[0]["reason"] == "revert: vault drained"
    assert failures[0]["decoded_logs"] == ["Transfer(attacker, 100)"]


def test_iter_failures_only_failing_suite_across_multiple():
    failures = _iter_failures(FORGE_MULTI_SUITE)
    assert len(failures) == 1
    assert failures[0]["test"] == "test_Exploit_Accounting_Overflow()"


def test_iter_failures_malformed_input_returns_empty():
    assert _iter_failures("<not json>") == []
    assert _iter_failures("") == []
    assert _iter_failures("[]") == []  # not a suite map (dict)
    assert _iter_failures('{"not": "a suite map"}') == []


# ── _halmos_counterexamples ───────────────────────────────────────────────────


def test_halmos_validated_counterexample_counted():
    out = _halmos_counterexamples(HALMOS_VALID)
    assert len(out) == 1
    assert out[0]["suite"] == "test/audit/Invariant.t.sol"
    assert out[0]["test"] == "check_invariant_balance"


def test_halmos_unvalidated_model_not_counted():
    assert _halmos_counterexamples(HALMOS_UNVALIDATED) == []


def test_halmos_malformed_input_returns_empty():
    assert _halmos_counterexamples("<not json>") == []
    assert _halmos_counterexamples("") == []


# ── has_failures ─────────────────────────────────────────────────────────────


def test_has_failures_false_on_passing():
    assert has_failures(FORGE_PASSING) is False


def test_has_failures_true_on_forge_failure():
    assert has_failures(FORGE_FAILING) is True


def test_has_failures_true_on_validated_halmos_counterexample():
    assert has_failures(HALMOS_VALID) is True


def test_has_failures_false_on_unvalidated_halmos_model():
    assert has_failures(HALMOS_UNVALIDATED) is False


def test_has_failures_false_on_malformed_input():
    assert has_failures("<not json>") is False
    assert has_failures("") is False


# ── project_frames / top_frame ─────────────────────────────────────────────────


def test_top_frame_passing_is_none():
    assert top_frame(FORGE_PASSING) is None


def test_top_frame_failing_test_identifier():
    assert top_frame(FORGE_FAILING) == (
        "test/audit/Exploit.t.sol:ExploitTest::test_Exploit_Reentrancy_DrainVault()"
    )


def test_project_frames_respects_n():
    assert project_frames(FORGE_MULTI_SUITE, n=1) == ["test/audit/A.t.sol:ATest::test_Exploit_Accounting_Overflow()"]
    assert project_frames(FORGE_PASSING, n=3) == []


def test_project_frames_falls_back_to_halmos():
    frames = project_frames(HALMOS_VALID, n=3)
    assert frames == ["test/audit/Invariant.t.sol::check_invariant_balance"]


def test_project_frames_empty_on_malformed_input():
    assert project_frames("not json", n=3) == []
    assert project_frames("", n=3) == []


# ── crash_reason ─────────────────────────────────────────────────────────────


def test_crash_reason_failing_test():
    r = crash_reason(FORGE_FAILING)
    assert r == {"crash_type": "Reentrancy", "operation": "revert: vault drained"}


def test_crash_reason_no_failures():
    assert crash_reason(FORGE_PASSING) == {"crash_type": None, "operation": None}


def test_crash_reason_unclassified_test_name():
    output = json.dumps({
        "test/audit/X.t.sol:XTest": {
            "test_results": {
                "testSomethingWeird()": {
                    "status": "Failure",
                    "reason": "revert",
                    "decoded_logs": [],
                }
            }
        }
    })
    assert crash_reason(output) == {"crash_type": "unclassified", "operation": "revert"}


def test_crash_reason_malformed_input():
    assert crash_reason("<not json>") == {"crash_type": None, "operation": None}
    assert crash_reason("") == {"crash_type": None, "operation": None}


# ── asan_excerpt ─────────────────────────────────────────────────────────────


def test_excerpt_includes_test_identifier_and_reason():
    ex = asan_excerpt(FORGE_FAILING)
    assert "test/audit/Exploit.t.sol:ExploitTest::test_Exploit_Reentrancy_DrainVault()" in ex
    assert "revert: vault drained" in ex
    assert "Transfer(attacker, 100)" in ex


def test_excerpt_is_compact_multiline():
    ex = asan_excerpt(FORGE_MULTI_SUITE)
    lines = ex.splitlines()
    assert len(lines) == 1  # only the one failing test from FORGE_MULTI_SUITE
    assert "test_Exploit_Accounting_Overflow()" in lines[0]


def test_excerpt_caps_frames():
    suites = {
        f"test/audit/{i}.t.sol:T{i}": {
            "test_results": {
                f"test_Exploit_Case{i}_Thing()": {
                    "status": "Failure", "reason": "r", "decoded_logs": [],
                }
            }
        }
        for i in range(15)
    }
    ex = asan_excerpt(json.dumps(suites), max_frames=10)
    assert len(ex.splitlines()) == 10


def test_excerpt_non_json_fallback():
    assert asan_excerpt("plain crash text\nsecond line") == "plain crash text"


def test_excerpt_empty():
    assert asan_excerpt("") == ""
