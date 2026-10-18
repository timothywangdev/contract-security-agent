import json
from pathlib import Path
import subprocess
import sys
from unittest.mock import Mock

import pytest

from contract_security_agent.execution import ToolRunner


@pytest.fixture
def project(tmp_path):
    source = tmp_path / "project"
    source.mkdir()
    (source / "foundry.toml").write_text('[profile.default]\nsolc_version = "0.8.26"\n')
    (source / "src").mkdir()
    (source / "src" / "Vault.sol").write_text("pragma solidity 0.8.26; contract Vault {}")
    return source


def forge_output(status="Success"):
    return json.dumps({"test/audit/Check.t.sol:Check": {"test_results": {"testAudit()": {"status": status}}}})


def test_worker_boundary_and_fresh_sources(monkeypatch, project):
    runner = ToolRunner({})
    seen = []
    monkeypatch.setattr(subprocess, "run", Mock(return_value=subprocess.CompletedProcess([], 0)))

    def capture(argv, timeout):
        mount = argv[argv.index("--mount") + 1]
        source = Path(mount.split("source=", 1)[1].split(",target=", 1)[0])
        assert (source / "src" / "Vault.sol").read_text().endswith("contract Vault {}")
        seen.append((argv, source))
        return 0, "ok", "", None

    monkeypatch.setattr(runner, "_capture", capture)
    monkeypatch.setenv("ANTHROPIC_API_KEY", "must-not-enter-worker")
    for _ in range(2):
        assert runner.run(project, ["forge", "build"], name="build")["status"] == "passed"
    assert seen[0][1] != seen[1][1]
    assert all(not path.exists() for _, path in seen)
    args = seen[0][0]
    for flag in ["--network=none", "--read-only", "--cap-drop=ALL", "--security-opt=no-new-privileges",
                 "--user=1000:1000", "--pull=never", "--pids-limit", "--memory", "--cpus"]:
        assert flag in args
    assert "readonly" in args[args.index("--mount") + 1]
    assert "FOUNDRY_FFI=false" in args
    assert "FOUNDRY_FS_PERMISSIONS=[]" in args
    assert all("must-not-enter-worker" not in value and "docker.sock" not in value for value in args)


@pytest.mark.parametrize("path", ["../evil.sol", "/test/audit/Evil.sol", "test/audit/../../../src/X.sol",
                                  "src/X.sol", "test/audit/X.py", "test\\audit\\X.sol"])
def test_generated_paths_cannot_escape_or_replace_source(project, path):
    runner = ToolRunner({})
    runner.run = Mock(side_effect=AssertionError("Must reject before execution"))
    result = runner.run_candidate(project, {path: "contract X {}"}, "testAudit")
    assert result["status"] == "unsupported"
    runner.run.assert_not_called()


def test_existing_audit_file_cannot_be_overwritten(project):
    existing = project / "test" / "audit" / "Check.t.sol"
    existing.parent.mkdir(parents=True)
    existing.write_text("original")
    runner = ToolRunner({})
    result = runner.run_candidate(project, {"test/audit/Check.t.sol": "replacement"}, "testAudit")
    assert result["status"] == "unsupported"
    assert existing.read_text() == "original"


def test_symlink_source_is_rejected(monkeypatch, project, tmp_path):
    (project / "src" / "secret.sol").symlink_to(tmp_path / "outside.sol")
    runner = ToolRunner({})
    monkeypatch.setattr(subprocess, "run", Mock(return_value=subprocess.CompletedProcess([], 0)))
    runner._capture = Mock(side_effect=AssertionError("Must not execute"))
    assert runner.run(project, ["forge", "test"], name="test")["status"] == "unsupported"
    runner._capture.assert_not_called()


def test_source_credentials_are_not_staged(project, tmp_path):
    (project / ".env").write_text("API_KEY=secret")
    (project / ".env.local").write_text("API_KEY=secret")
    (project / ".claude").mkdir()
    (project / ".claude" / "credentials.json").write_text("secret")
    staged = tmp_path / "stage"
    ToolRunner({})._stage(project, staged)
    assert not (staged / ".env").exists()
    assert not (staged / ".env.local").exists()
    assert not (staged / ".claude").exists()
    assert (staged / "foundry.toml").is_file()


@pytest.mark.parametrize("reason", ["timeout", "output_limit"])
def test_incomplete_execution_is_never_passed(monkeypatch, project, reason):
    runner = ToolRunner({})
    runner._capture = Mock(return_value=(-9, "partial", "", reason))
    cleanup = Mock(return_value=subprocess.CompletedProcess([], 0))
    monkeypatch.setattr(subprocess, "run", cleanup)
    result = runner.run(project, ["forge", "test"], name="candidate")
    assert result["status"] == "inconclusive"
    assert result["metadata"]["reason"] == reason
    assert cleanup.call_args.args[0][:3] == ["docker", "rm", "--force"]


def test_capture_bounds_actual_subprocess_logs_and_time():
    runner = ToolRunner({"max_output_bytes": 1024})
    _, stdout, stderr, reason = runner._capture([sys.executable, "-c", "print('x'*100000)"], 5)
    assert reason == "output_limit"
    assert len(stdout.encode()) + len(stderr.encode()) <= 1024
    _, _, _, reason = runner._capture([sys.executable, "-c", "import time; time.sleep(10)"], 0.1)
    assert reason == "timeout"


@pytest.mark.parametrize("output,status,count", [("{}", "inconclusive", 0), ("compiler error", "inconclusive", None),
                                                (forge_output("Skipped"), "inconclusive", 0),
                                                (forge_output("Failure"), "failed", 1),
                                                (forge_output(), "passed", 1)])
def test_candidate_requires_executed_structured_tests(project, output, status, count):
    runner = ToolRunner({})
    source_before = (project / "src" / "Vault.sol").read_text()
    runner.run = Mock(return_value={"status": "passed", "stdout": output, "exit_code": 0, "metadata": {}})
    result = runner.run_candidate(project, {"test/audit/Check.t.sol": "contract Check {}"}, "^testAudit$")
    assert result["status"] == status
    assert result["metadata"].get("selected_tests") == count
    assert not (project / "test").exists()
    assert (project / "src" / "Vault.sol").read_text() == source_before


@pytest.mark.parametrize("exitcode,status", [(0, "passed"), (1, "failed"), (2, "inconclusive"),
                                            (3, "inconclusive"), (4, "inconclusive"), (5, "inconclusive")])
def test_formal_timeout_stuck_or_vacuity_is_inconclusive(exitcode, status):
    result = {"status": "passed" if exitcode == 0 else "failed", "exit_code": 0 if exitcode == 0 else 1,
              "stdout": 'progress\n' + json.dumps({"exitcode": exitcode,
              "test_results": {"test/audit/Check.t.sol:Check": [{"name": "checkAudit()", "exitcode": exitcode,
                                                               "models": [{"is_valid": True}]}]}}), "metadata": {}}
    assert ToolRunner._classify_halmos(result)["status"] == status


def test_missing_docker_has_no_host_fallback(monkeypatch, project):
    runner = ToolRunner({})
    runner._capture = Mock(side_effect=FileNotFoundError("docker"))
    monkeypatch.setattr(subprocess, "run", Mock(return_value=subprocess.CompletedProcess([], 0)))
    assert runner.run(project, ["forge", "test"], name="candidate")["status"] == "unsupported"
    assert runner._capture.call_args.args[0][:2] == ["docker", "run"]


def test_exhausted_audit_deadline_skips_worker(monkeypatch, project):
    runner = ToolRunner({"deadline_monotonic": 0})
    runner._capture = Mock(side_effect=AssertionError("Worker must not start after deadline"))
    cleanup = Mock(side_effect=AssertionError("No worker requires cleanup"))
    monkeypatch.setattr(subprocess, "run", cleanup)
    result = runner.run(project, ["forge", "test"], name="test")
    assert result["status"] == "inconclusive"
    assert result["metadata"]["reason"] == "audit_deadline"
    runner._capture.assert_not_called()
    cleanup.assert_not_called()


def test_formal_invalid_model_cannot_count_as_counterexample():
    result = {"status": "failed", "exit_code": 1, "metadata": {}, "stdout": json.dumps({"exitcode": 1,
              "test_results": {"test/audit/Check.t.sol:Check": [{"name": "checkAudit()", "exitcode": 1,
              "models": [{"is_valid": False}]}]}})}
    assert ToolRunner._classify_halmos(result)["status"] == "inconclusive"


def test_formal_original_tests_cannot_substitute_for_generated_check():
    result = {"status": "passed", "exit_code": 0, "metadata": {}, "stdout": json.dumps({"exitcode": 0,
              "test_results": {"test/Original.t.sol:Original": [{"name": "checkAudit()", "exitcode": 0}]}})}
    assert ToolRunner._classify_halmos(result)["status"] == "inconclusive"


def test_automatic_container_removal_race_is_verified(monkeypatch, project):
    runner = ToolRunner({})
    runner._capture = Mock(return_value=(-9, "partial", "", "output_limit"))
    cleanup = Mock(side_effect=[subprocess.CompletedProcess([], 1, stderr=b"removal is already in progress"),
                               subprocess.CompletedProcess([], 1, stderr=b"Error: No such object")])
    monkeypatch.setattr(subprocess, "run", cleanup)
    result = runner.run(project, ["forge", "test"], name="candidate")
    assert result["status"] == "inconclusive"
    assert "cleanup_unconfirmed" not in result["metadata"]
    assert cleanup.call_args.args[0][:2] == ["docker", "inspect"]


def test_execution_snapshot_limit_is_independent_of_model_context(project, tmp_path):
    large = project / "src" / "Large.sol"
    large.write_bytes(b"/" * 150_000)
    ToolRunner({"max_source_bytes": 120_000})._stage(project, tmp_path / "stage")
    assert (tmp_path / "stage" / "src" / "Large.sol").stat().st_size == 150_000
    with pytest.raises(ValueError, match="staging limit"):
        ToolRunner({"max_snapshot_bytes": 140_000})._stage(project, tmp_path / "bounded")


def test_diagnostics_pins_immutable_worker_image(monkeypatch, tmp_path):
    image_id = "sha256:" + "a" * 64
    calls = Mock(side_effect=[subprocess.CompletedProcess([], 0, stdout="28.3.2\n"),
                             subprocess.CompletedProcess([], 0, stdout=image_id + "\n")])
    monkeypatch.setattr(subprocess, "run", calls)
    runner = ToolRunner({})
    assert runner.diagnostics()["image_id"] == image_id
    runner.image = "different-tag:dev"
    argv = runner._argv(tmp_path, ["forge", "test"], "test-container")
    assert image_id in argv
    assert "different-tag:dev" not in argv
