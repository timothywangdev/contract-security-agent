import json
from pathlib import Path

import pytest

from contract_security_agent.evidence import retest_fix, validate_candidate


def forge(status="passed", reason="", *, count=1, tool="forge_candidate"):
    return {"tool": tool, "status": status, "stdout": json.dumps({"test/audit/Probe.t.sol:Probe": {
        "test_results": {"testSafety()": {"status": "Success" if status == "passed" else "Failure", "reason": reason}} if count else {}}})}


class Runner:
    def __init__(self, results, baseline=None):
        self.results = list(results)
        self.calls = []
        self.baseline = baseline if baseline is not None else [
            {"tool": "forge_build", "status": "passed"},
            forge(tool="forge_test"), {"tool": "slither", "status": "passed"}]

    def run_candidate(self, snapshot, files, pattern):
        self.calls.append((snapshot, dict(files), pattern))
        return self.results.pop(0)

    def run_baseline(self, snapshot):
        return self.baseline


@pytest.fixture
def setup(tmp_path):
    source = tmp_path / "vulnerable"
    source.mkdir()
    (source / "src").mkdir()
    (source / "src/Vault.sol").write_text("contract Vault {}")
    (source / "test").mkdir()
    (source / "test/Native.t.sol").write_text("contract Native { function testDeposit() public {} }")
    candidate = {"id": "C-1", "title": "Withdrawal entitlement", "severity": "high",
                 "requirement_id": "withdrawal-entitlement", "test_pattern": "testSafety",
                 "test_files": {"test/audit/Probe.t.sol": "contract Probe { function testSafety() public {} }"}}
    trusted = tmp_path / "trusted"
    (trusted / "test/audit").mkdir(parents=True)
    (trusted / "test/audit/Safety.t.sol").write_text("contract Safety { function testSafety() public { require(false, 'audit: safety violation'); } }")
    (trusted / "metadata.json").write_text(json.dumps({"requirement_id": "withdrawal-entitlement", "test_pattern": "testSafety",
                                                       "expected_failure": "audit: safety violation"}))
    return source, candidate, trusted


def fixed_copy(tmp_path, source):
    import shutil
    fixed = tmp_path / "fixed"
    shutil.copytree(source, fixed)
    (fixed / "src/Vault.sol").write_text("contract Vault { bool fixedBug; }")
    return fixed


def test_model_success_is_replayed_but_never_a_validated_security_issue(setup, tmp_path):
    source, candidate, _ = setup
    runner = Runner([forge(), forge()])
    record = validate_candidate(source, candidate, runner, tmp_path / "out")
    assert record["status"] == "replayed_candidate"
    assert record["reviewer_state"] == "needs_review"
    assert not record["validated"]
    assert len(runner.calls) == 2
    assert all(c[0] == source for c in runner.calls)
    assert (tmp_path / "out/evidence.json").is_file()


def test_reviewed_safety_oracle_can_validate_requirement_violation(setup, tmp_path):
    source, candidate, trusted = setup
    runner = Runner([forge(), forge(), forge("failed", "audit: safety violation"), forge("failed", "audit: safety violation")])
    record = validate_candidate(source, candidate, runner, tmp_path / "out", trusted)
    assert record["status"] == "validated"
    assert record["validated"]
    assert record["semantic_status"] == "requirement_violation"
    assert len(record["trusted_replays"]) == 2
    assert "test/audit/Safety.t.sol" in record["trusted_check_hashes"]


def test_plain_revert_does_not_establish_safety_violation(setup, tmp_path):
    source, candidate, trusted = setup
    record = validate_candidate(source, candidate, Runner([forge("failed", "EvmError: Revert") for _ in range(4)]), tmp_path / "out", trusted)
    assert record["replay_status"] == "reproduced"
    assert record["status"] == "replayed_candidate"
    assert not record["validated"]


def test_flaky_candidate_cannot_be_validated_by_trusted_failure(setup, tmp_path):
    source, candidate, trusted = setup
    runner = Runner([forge(), forge("failed", "assertion failed"), forge("failed", "audit: safety violation"), forge("failed", "audit: safety violation")])
    record = validate_candidate(source, candidate, runner, tmp_path / "out", trusted)
    assert record["replay_status"] == "unstable"
    assert not record["validated"]


@pytest.mark.parametrize("filename", ["../../src/Vault.sol", "/tmp/Probe.t.sol", "src/Vault.sol", "test/audit/../../src/Vault.t.sol", "test\\audit\\Probe.t.sol"])
def test_path_tampering_is_rejected_before_execution(setup, tmp_path, filename):
    source, candidate, _ = setup
    candidate["test_files"] = {filename: "contract Evil {}"}
    runner = Runner([])
    result = validate_candidate(source, candidate, runner, tmp_path / "out")
    assert result["status"] == "rejected"
    assert not runner.calls


@pytest.mark.parametrize("call", ["vm.ffi(args)", "vm.envString('API_KEY')", "vm.store(target, slot, value)", "vm.deal(attacker, 1 ether)", "vm.prank(owner)", "vm.etch(target, code)", "vm.mockCall(target, data, value)", "assembly { mstore(0, 0) }"])
def test_dangerous_cheatcodes_and_state_injection_are_rejected(setup, tmp_path, call):
    source, candidate, _ = setup
    candidate["test_files"]["test/audit/Probe.t.sol"] = f"contract Probe {{ function testSafety() public {{ {call}; }} }}"
    runner = Runner([])
    result = validate_candidate(source, candidate, runner, tmp_path / "out")
    assert result["status"] == "rejected"
    assert not runner.calls


def test_existing_test_cannot_be_overwritten(setup, tmp_path):
    source, candidate, _ = setup
    (source / "test/audit").mkdir()
    (source / "test/audit/Probe.t.sol").write_text("contract RealSafety {}")
    runner = Runner([])
    assert validate_candidate(source, candidate, runner, tmp_path / "out")["status"] == "rejected"
    assert not runner.calls


def test_symlink_snapshot_and_output_are_rejected(setup, tmp_path):
    source, candidate, _ = setup
    (source / "src/link").symlink_to(source / "src/Vault.sol")
    assert validate_candidate(source, candidate, Runner([]), tmp_path / "out")["status"] == "rejected"
    (tmp_path / "linked-output").symlink_to(tmp_path / "out")
    with pytest.raises(ValueError, match="symlink"):
        validate_candidate(source, candidate, Runner([]), tmp_path / "linked-output")


def test_runner_source_mutation_invalidates_evidence(setup, tmp_path):
    source, candidate, _ = setup

    class MutatingRunner(Runner):
        def run_candidate(self, snapshot, files, pattern):
            (snapshot / "src/Vault.sol").write_text("contract Tampered {}")
            return forge()

    result = validate_candidate(source, candidate, MutatingRunner([]), tmp_path / "out")
    assert result["status"] == "rejected"
    assert "modified the immutable snapshot" in " ".join(result["errors"])


@pytest.mark.parametrize("result", [forge(count=0), {"status": "passed", "stdout": "Compiler error"}, {"status": "failed", "stdout": "Compiler error"}])
def test_missing_execution_or_compile_failure_is_inconclusive(setup, tmp_path, result):
    source, candidate, _ = setup
    record = validate_candidate(source, candidate, Runner([result, result]), tmp_path / "out")
    assert not record["validated"]
    assert record["status"] == "inconclusive"
    assert record["replay_status"] == "inconclusive"


def test_partly_skipped_tests_cannot_establish_reproducibility(setup, tmp_path):
    source, candidate, _ = setup
    result = forge()
    data = json.loads(result["stdout"])
    data["test/audit/Probe.t.sol:Probe"]["test_results"]["testSkipped()"] = {"status": "Skipped"}
    result["stdout"] = json.dumps(data)
    record = validate_candidate(source, candidate, Runner([result, result]), tmp_path / "out")
    assert record["status"] == "inconclusive"
    assert record["replay_status"] == "inconclusive"


def test_trusted_checks_must_match_reviewed_requirement(setup, tmp_path):
    source, candidate, trusted = setup
    candidate["requirement_id"] = "different"
    result = validate_candidate(source, candidate, Runner([forge(), forge()]), tmp_path / "out", trusted)
    assert result["status"] == "rejected"
    assert "requirement_id" in " ".join(result["errors"])


def test_fix_requires_vulnerable_failure_fixed_success_and_native_baseline(setup, tmp_path):
    source, candidate, trusted = setup
    fixed = fixed_copy(tmp_path, source)
    runner = Runner([forge("failed", "audit: safety violation"), forge("failed", "audit: safety violation"), forge(), forge()])
    result = retest_fix(source, fixed, candidate, runner, tmp_path / "out", trusted)
    assert result["passed"]
    assert result["status"] == "passed"
    assert runner.calls[0][1] == runner.calls[-1][1]
    assert len(result["baseline"]) == 3


def test_ineffective_fix_fails_frozen_safety_gate(setup, tmp_path):
    source, candidate, trusted = setup
    fixed = fixed_copy(tmp_path, source)
    runner = Runner([forge("failed", "audit: safety violation") for _ in range(4)])
    result = retest_fix(source, fixed, candidate, runner, tmp_path / "out", trusted)
    assert result["status"] == "failed"
    assert not result["passed"]


def test_broken_compile_and_missing_native_tests_cannot_validate_fix(setup, tmp_path):
    source, candidate, trusted = setup
    fixed = fixed_copy(tmp_path, source)
    baseline = [{"tool": "forge_build", "status": "failed"}, forge(tool="forge_test", count=0)]
    runner = Runner([forge("failed", "audit: safety violation"), forge("failed", "audit: safety violation"), forge(), forge()], baseline)
    result = retest_fix(source, fixed, candidate, runner, tmp_path / "out", trusted)
    assert result["status"] == "failed"
    assert not result["passed"]


def test_fix_cannot_delete_native_regression_tests(setup, tmp_path):
    source, candidate, trusted = setup
    fixed = fixed_copy(tmp_path, source)
    (fixed / "test/Native.t.sol").unlink()
    runner = Runner([])
    result = retest_fix(source, fixed, candidate, runner, tmp_path / "out", trusted)
    assert result["status"] == "rejected"
    assert not runner.calls


def test_fix_cannot_change_foundry_test_selection(setup, tmp_path):
    source, candidate, trusted = setup
    (source / "foundry.toml").write_text('[profile.default]\ntest = "custom-tests"\n')
    fixed = fixed_copy(tmp_path, source)
    (fixed / "foundry.toml").write_text('[profile.default]\ntest = "empty-tests"\n')
    result = retest_fix(source, fixed, candidate, Runner([]), tmp_path / "out", trusted)
    assert result["status"] == "rejected"
    assert "test configuration" in " ".join(result["errors"])


def test_fix_cannot_remove_custom_foundry_test_helpers(setup, tmp_path):
    source, candidate, trusted = setup
    (source / "foundry.toml").write_text('[profile.default]\ntest = "custom-tests"\n')
    (source / "custom-tests").mkdir()
    (source / "custom-tests/Helpers.sol").write_text("contract Helpers {}")
    fixed = fixed_copy(tmp_path, source)
    (fixed / "custom-tests/Helpers.sol").unlink()
    result = retest_fix(source, fixed, candidate, Runner([]), tmp_path / "out", trusted)
    assert result["status"] == "rejected"


def test_fix_without_reviewed_oracle_remains_unvalidated(setup, tmp_path):
    source, candidate, _ = setup
    fixed = fixed_copy(tmp_path, source)
    result = retest_fix(source, fixed, candidate, Runner([]), tmp_path / "out")
    assert result["status"] == "rejected"
    assert not result["passed"]


def test_slither_findings_do_not_veto_otherwise_valid_fix(setup, tmp_path):
    source, candidate, trusted = setup
    fixed = fixed_copy(tmp_path, source)
    baseline = [{"tool": "forge_build", "status": "passed"}, forge(tool="forge_test"), {"tool": "slither", "status": "failed", "summary": "Existing detector finding"}]
    runner = Runner([forge("failed", "audit: safety violation"), forge("failed", "audit: safety violation"), forge(), forge()], baseline)
    result = retest_fix(source, fixed, candidate, runner, tmp_path / "out", trusted)
    assert result["passed"]
