# Copyright 2026 Anthropic PBC
# Copyright 2026 Contract Security Agent contributors
# SPDX-License-Identifier: Apache-2.0
"""Runtime bug-sharing: found_bugs.jsonl write/read.

finding_parser's own parsing behavior (top_frame/project_frames over
forge/Halmos JSON) has its own thorough coverage in test_finding_parser.py;
this file only exercises the jsonl round-trip and the concurrent-agents
prompt section that depends on it.
"""
import json

from harness.artifacts import CrashArtifact
from harness.finding_parser import top_frame, project_frames
from harness.cli import _append_found, _read_found_summaries, _seed_found_bugs
from harness.prompts.find_prompt import build_find_prompt


# ── forge-shaped fixtures ─────────────────────────────────────────────────────

FORGE_REENTRANCY = json.dumps({
    "test/audit/Exploit_Reentrancy_DrainVault.t.sol:ExploitReentrancyDrainVaultTest": {
        "test_results": {
            "test_Exploit_Reentrancy_DrainVault()": {
                "status": "Failure",
                "reason": "revert: vault drained",
                "decoded_logs": ["Transfer(attacker, 100)"],
            }
        }
    }
})

FORGE_ACCESSCONTROL = json.dumps({
    "test/audit/Exploit_AccessControl_AdminTakeover.t.sol:ExploitAccessControlAdminTakeoverTest": {
        "test_results": {
            "test_Exploit_AccessControl_AdminTakeover()": {
                "status": "Failure",
                "reason": "revert: unauthorized admin set",
                "decoded_logs": [],
            }
        }
    }
})


def test_top_frame_and_project_frames_sanity():
    # Smoke check that the jsonl helpers below are exercising a real parse
    # (full coverage lives in test_finding_parser.py).
    assert top_frame(FORGE_REENTRANCY) == (
        "test/audit/Exploit_Reentrancy_DrainVault.t.sol:ExploitReentrancyDrainVaultTest"
        "::test_Exploit_Reentrancy_DrainVault()"
    )
    assert len(project_frames(FORGE_REENTRANCY, n=3)) == 1


# ── jsonl append/read round-trip (raw finding excerpt format) ─────────────────

def _mk_crash(crash_type="Reentrancy", crash_output=FORGE_REENTRANCY):
    return CrashArtifact(
        poc_path="/tmp/poc.bin",
        poc_bytes=b"test/audit/Exploit.t.sol contents",
        reproduction_command="forge test --offline --json --match-test 'test_Exploit'",
        crash_type=crash_type,
        crash_output=crash_output,
        exit_code=1,
    )


def test_append_writes_raw_excerpt(tmp_path):
    p = tmp_path / "found_bugs.jsonl"
    _append_found(p, _mk_crash(), run_idx=3)

    entry = json.loads(p.read_text().strip())
    assert entry["run_idx"] == 3
    assert "asan_excerpt" in entry
    assert "test_Exploit_Reentrancy_DrainVault" in entry["asan_excerpt"]
    assert "vault drained" in entry["asan_excerpt"]
    # Old pre-parsed fields are gone — agents parse the raw finding themselves now.
    assert "crash_type" not in entry
    assert "top_frame" not in entry
    assert "call_stack" not in entry


def test_append_and_read_excerpts(tmp_path):
    p = tmp_path / "found_bugs.jsonl"
    _append_found(p, _mk_crash(), run_idx=0)
    _append_found(p, _mk_crash(crash_type="AccessControl", crash_output=FORGE_ACCESSCONTROL), run_idx=1)

    excerpts = _read_found_summaries(p)
    assert len(excerpts) == 2
    assert "DrainVault" in excerpts[0]
    assert "AdminTakeover" in excerpts[1]


def test_seed_then_append_mixed_formats(tmp_path):
    # Config-seeded entries are prose summaries; runtime entries are finding excerpts.
    # _read_found_summaries handles both.
    p = tmp_path / "found_bugs.jsonl"
    _seed_found_bugs(p, ["known reentrancy in Vault.withdraw at Vault.sol:142"])
    _append_found(p, _mk_crash(), run_idx=0)

    entries = _read_found_summaries(p)
    assert len(entries) == 2
    assert "reentrancy" in entries[0]  # config prose
    assert "DrainVault" in entries[1]  # finding excerpt


def test_read_missing_file(tmp_path):
    assert _read_found_summaries(tmp_path / "nope.jsonl") == []


def test_read_empty_file(tmp_path):
    p = tmp_path / "found_bugs.jsonl"
    p.write_text("")
    assert _read_found_summaries(p) == []


def test_read_skips_malformed_lines(tmp_path):
    p = tmp_path / "found_bugs.jsonl"
    p.write_text(
        '{"summary": "good entry 1"}\n'
        'not json at all\n'
        '{"no_usable_field": true}\n'
        '\n'
        '{"asan_excerpt": "good entry 2"}\n'
    )
    assert _read_found_summaries(p) == ["good entry 1", "good entry 2"]


# ── concurrent-agents prompt section ─────────────────────────────────────────

def test_concurrent_section_renders_with_path():
    p = build_find_prompt("url", "abc", "/src", "/bin",
                          found_bugs_path="/results/canary/found_bugs.jsonl")
    assert "## Concurrent Agents" in p
    assert "/results/canary/found_bugs.jsonl" in p
    assert "cat /results/canary/found_bugs.jsonl" in p


def test_concurrent_section_omitted_without_path():
    p = build_find_prompt("url", "abc", "/src", "/bin")
    assert "## Concurrent Agents" not in p


def test_concurrent_section_describes_readonly_mount():
    # Agent runs in-container; the shared file is bind-mounted read-only.
    p = build_find_prompt("url", "abc", "/src", "/bin",
                          found_bugs_path="/tmp/found_bugs.jsonl")
    sect = p[p.index("## Concurrent Agents"):]
    assert "read-only" in sect.lower()
    assert "/tmp/found_bugs.jsonl" in sect


def test_concurrent_section_mentions_asan_excerpt():
    # The comparison guidance references the (historically-named) asan_excerpt
    # field, which now holds failing-test identifiers, not raw ASAN.
    p = build_find_prompt("url", "abc", "/src", "/bin",
                          found_bugs_path="/r/found.jsonl")
    sect = p[p.index("## Concurrent Agents"):]
    assert "asan_excerpt" in sect


def test_all_optional_sections_render_in_order():
    p = build_find_prompt("url", "abc", "/src", "/bin",
                          focus_area="JPEG", known_bugs=["bug1"],
                          found_bugs_path="/r/found.jsonl")
    positions = [
        p.index("## Setup"),
        p.index("## Focus Area"),
        p.index("## Already Filed"),
        p.index("## Concurrent Agents"),
        p.index("## Task"),
    ]
    assert positions == sorted(positions)
