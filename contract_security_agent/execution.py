# SPDX-License-Identifier: Apache-2.0
"""Credential-free, disposable Docker execution for untrusted audit targets.

The subprocess Docker CLI and finally-cleanup pattern adapts the approach in
Anthropic's defending-code-reference-harness/harness/{docker_ops,sandbox}.py
(Copyright 2026 Anthropic PBC, Apache-2.0; vendored under third_party/).
No target code or generated test is ever executed by the controller.
"""
from __future__ import annotations

import json
import os
from pathlib import Path, PurePosixPath
import re
import selectors
import shutil
import stat
import subprocess
import tempfile
import time
import uuid


# Source is mounted read-only; all tool writes live in a bounded, disposable
# tmpfs. -I prevents target PYTHONPATH/sitecustomize from controlling bootstrap.
_BOOTSTRAP = """import os,shutil,sys
os.symlink('/opt/solc','/tmp/.svm')
shutil.copytree('/source','/work/project',symlinks=False)
os.chdir('/work/project')
os.execvp(sys.argv[1],sys.argv[1:])
"""
_EXCLUDED_DIRS = {".git", ".claude", ".aws", ".ssh", ".venv", "node_modules", "out", "cache", "broadcast", "__pycache__"}
_SECRET_FILES = {".env", ".npmrc", ".netrc", ".pypirc", "credentials", "credentials.json"}
_PINNED_TOOLS = {"python": "3.12.11", "forge": "1.4.4", "solc": "0.8.26", "slither": "0.11.6", "halmos": "0.3.3"}


class ToolRunner:
    def __init__(self, config: dict):
        self.config = dict(config)
        self.image = str(config.get("image", "contract-security-agent-tools:dev"))
        self.image_id: str | None = None
        self.output_limit = int(config.get("max_output_bytes", 200_000))
        self.timeout = float(config.get("tool_timeout_seconds", 90))
        if self.output_limit < 1024 or self.timeout <= 0:
            raise ValueError("Output limit must be >=1024 bytes and timeout must be positive")

    def diagnostics(self) -> dict:
        """Inspect prerequisites only; never download or run target code."""
        result = {"image": self.image, "pinned_tools": dict(_PINNED_TOOLS), "docker_available": False,
                  "image_available": False, "status": "unsupported"}
        try:
            docker = subprocess.run(["docker", "version", "--format", "{{.Server.Version}}"],
                                    capture_output=True, text=True, timeout=15)
            result["docker_available"] = docker.returncode == 0
            if docker.returncode:
                result["reason"] = docker.stderr[:2000]
                return result
            result["docker_version"] = docker.stdout.strip()
            inspect = subprocess.run(["docker", "image", "inspect", self.image_id or self.image, "--format", "{{.Id}}"],
                                     capture_output=True, text=True, timeout=15)
            inspected_id = inspect.stdout.strip() if inspect.returncode == 0 else None
            available = inspected_id is not None and re.fullmatch(r"sha256:[0-9a-f]{64}", inspected_id) is not None
            result["image_available"] = available
            result["image_id"] = inspected_id if available else None
            result["status"] = "passed" if available else "unsupported"
            if available:
                self.image_id = inspected_id
            else:
                result["reason"] = "Tools image is absent; build docker/Dockerfile.tools first."
        except (OSError, subprocess.TimeoutExpired) as exc:
            result["reason"] = str(exc)
        return result

    @staticmethod
    def _result(name: str, command: list[str]) -> dict:
        return {"name": name, "status": "error", "command": list(command), "exit_code": None,
                "stdout": "", "stderr": "", "duration_seconds": 0.0, "metadata": {}}

    def _stage(self, project: Path, destination: Path) -> None:
        """Copy regular source files only, with hard byte/file limits."""
        if project.is_symlink() or not project.is_dir():
            raise ValueError("Project must be a real directory, not a symlink")
        total = count = 0
        for parent, dirs, files in os.walk(project, followlinks=False):
            dirs[:] = sorted(d for d in dirs if d not in _EXCLUDED_DIRS)
            target = destination / Path(parent).relative_to(project)
            target.mkdir(parents=True, exist_ok=True)
            target.chmod(0o755)
            for d in dirs:
                if (Path(parent) / d).is_symlink():
                    raise ValueError("Symlink directories are unsupported in audit sources")
            for filename in sorted(files):
                if filename in _SECRET_FILES or filename.startswith(".env."):
                    continue
                source = Path(parent) / filename
                info = source.lstat()
                if not stat.S_ISREG(info.st_mode):
                    raise ValueError("Only regular files are supported in audit sources")
                total += info.st_size
                count += 1
                if total > int(self.config.get("max_snapshot_bytes", 50_000_000)) or count > 20_000:
                    raise ValueError("Source snapshot exceeds execution staging limit")
                shutil.copyfile(source, target / filename, follow_symlinks=False)
                (target / filename).chmod(0o644)

    def _argv(self, staging: Path, command: list[str], container: str) -> list[str]:
        args = ["docker", "run", "--rm", "--pull=never", "--name", container,
                "--network=none", "--read-only", "--cap-drop=ALL",
                "--security-opt=no-new-privileges", "--user=1000:1000",
                "--memory", str(self.config.get("memory", "2g")),
                "--memory-swap", str(self.config.get("memory", "2g")),
                "--cpus", str(self.config.get("cpus", 2)),
                "--pids-limit", str(self.config.get("pids_limit", 256)),
                "--ulimit", "nofile=1024:1024", "--log-driver=none",
                "--tmpfs", "/tmp:rw,nosuid,nodev,size=128m,uid=1000,gid=1000,mode=1777",
                "--tmpfs", "/work:rw,nosuid,nodev,size=512m,uid=1000,gid=1000,mode=0755",
                "--mount", f"type=bind,source={staging},target=/source,readonly",
                "--env", "HOME=/tmp", "--env", "FOUNDRY_OFFLINE=true",
                "--env", "FOUNDRY_FFI=false", "--env", "DAPP_FFI=false",
                "--env", "FOUNDRY_FS_PERMISSIONS=[]",
                "--env", "NO_COLOR=1", "--env", "PYTHONDONTWRITEBYTECODE=1"]
        if self.config.get("docker_runtime"):
            args += ["--runtime", str(self.config["docker_runtime"])]
        return args + ["--entrypoint", "/usr/local/bin/python3", self.image_id or self.image, "-I", "-c", _BOOTSTRAP, *command]

    def _capture(self, argv: list[str], timeout: float) -> tuple[int | None, str, str, str | None]:
        """Drain both pipes while bounding memory, elapsed time, and log volume."""
        process = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                   stderr=subprocess.PIPE, bufsize=0)
        chunks = {"stdout": bytearray(), "stderr": bytearray()}
        reason = None
        used = 0
        deadline = time.monotonic() + timeout
        try:
            with selectors.DefaultSelector() as selector:
                selector.register(process.stdout, selectors.EVENT_READ, "stdout")
                selector.register(process.stderr, selectors.EVENT_READ, "stderr")
                while selector.get_map():
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        reason = "timeout"
                        break
                    for key, _ in selector.select(min(remaining, 0.1)):
                        data = os.read(key.fileobj.fileno(), 65536)
                        if not data:
                            selector.unregister(key.fileobj)
                            continue
                        take = max(0, self.output_limit - used)
                        chunks[key.data].extend(data[:take])
                        used += len(data[:take])
                        if len(data) > take:
                            reason = "output_limit"
                            break
                    if reason:
                        break
            if reason:
                process.kill()
            process.wait(timeout=max(0.1, deadline - time.monotonic()) if not reason else 5)
        except subprocess.TimeoutExpired:
            reason = "timeout"
            process.kill()
            process.wait(timeout=5)
        finally:
            if process.poll() is None:
                process.kill()
                process.wait(timeout=5)
            process.stdout.close()
            process.stderr.close()
        return process.returncode, chunks["stdout"].decode("utf-8", "replace"), chunks["stderr"].decode("utf-8", "replace"), reason

    def run(self, project: Path, command: list[str], *, name: str, timeout: float | None = None) -> dict:
        result = self._result(name, command)
        started = time.monotonic()
        container = "csa-" + uuid.uuid4().hex
        attempted = False
        try:
            if not isinstance(command, list) or not command or any(not isinstance(x, str) or "\x00" in x for x in command):
                raise ValueError("Command must be a nonempty argv list")
            timeout = self.timeout if timeout is None else float(timeout)
            if timeout <= 0:
                raise ValueError("Timeout must be positive")
            with tempfile.TemporaryDirectory(prefix="csa-worker-") as temporary:
                staging = Path(temporary) / "source"
                self._stage(Path(project), staging)
                deadline = self.config.get("deadline_monotonic")
                if deadline is not None:
                    timeout = min(timeout, float(deadline) - time.monotonic())
                    if timeout <= 0:
                        result["status"] = "inconclusive"
                        result["metadata"]["reason"] = "audit_deadline"
                        return result
                attempted = True
                code, stdout, stderr, reason = self._capture(self._argv(staging, command, container), timeout)
                result.update(exit_code=code, stdout=stdout, stderr=stderr)
                result["metadata"].update(network="none", read_only_source=True, isolated=True,
                                          image_id=self.image_id,
                                          output_truncated=reason == "output_limit")
                if reason:
                    result["status"] = "inconclusive"
                    result["metadata"]["reason"] = reason
                elif code in (125, 126, 127):
                    result["status"] = "unsupported"
                    result["metadata"]["reason"] = "Docker worker or requested tool could not start"
                else:
                    result["status"] = "passed" if code == 0 else "failed"
        except ValueError as exc:
            result["status"] = "unsupported"
            result["stderr"] = str(exc)
        except OSError as exc:
            result["status"] = "unsupported"
            result["stderr"] = str(exc)
        finally:
            # Killing docker's client alone does not kill the worker.
            try:
                cleanup = (subprocess.run(["docker", "rm", "--force", container], capture_output=True, timeout=10)
                           if attempted else None)
                if cleanup is not None and cleanup.returncode and b"No such container" not in (cleanup.stderr or b""):
                    # --rm may race the explicit forced cleanup. Confirm that
                    # the worker is absent or stopped before accepting it.
                    state = subprocess.run(["docker", "inspect", "--format", "{{.State.Running}}", container],
                                           capture_output=True, timeout=5)
                    absent = state.returncode != 0 and any(message in (state.stderr or b"")
                             for message in (b"No such object", b"No such container"))
                    stopped = state.returncode == 0 and (state.stdout or b"").strip() == b"false"
                    if not absent and not stopped:
                        result["metadata"]["cleanup_unconfirmed"] = True
                        result["metadata"]["container"] = container
                        result["status"] = "error"
            except FileNotFoundError:
                pass  # No Docker executable means no worker was launched.
            except (OSError, subprocess.TimeoutExpired):
                result["metadata"]["cleanup_unconfirmed"] = True
                result["metadata"]["container"] = container
                result["status"] = "error"
            result["duration_seconds"] = round(time.monotonic() - started, 3)
        return result

    @staticmethod
    def _classify_forge(result: dict) -> dict:
        if result["status"] not in {"passed", "failed"}:
            return result
        try:
            suites = json.loads(result["stdout"])
            if not isinstance(suites, dict):
                raise ValueError("Expected suite map")
            tests = [test for suite in suites.values() if isinstance(suite, dict)
                     for test in suite.get("test_results", {}).values()]
            if any(not isinstance(t, dict) or t.get("status") not in {"Success", "Failure", "Skipped"} for t in tests):
                raise ValueError("Unrecognized test result")
        except (ValueError, TypeError, AttributeError):
            result["status"] = "inconclusive"
            no_tests = result["exit_code"] == 0 and "No tests found" in result["stdout"]
            result["metadata"]["failure_kind"] = "no_tests" if no_tests else "compilation_or_invalid_output"
            if no_tests:
                result["metadata"].update(selected_tests=0, skipped_tests=0, failed_tests=0)
            return result
        selected = sum(t.get("status") != "Skipped" for t in tests)
        skipped = len(tests) - selected
        failures = sum(t.get("status") == "Failure" for t in tests)
        result["metadata"].update(selected_tests=selected, skipped_tests=skipped, failed_tests=failures)
        if not selected or skipped:
            result["status"] = "inconclusive"
            result["metadata"]["failure_kind"] = "no_tests" if not selected else "skipped_tests"
        elif failures:
            result["status"] = "failed"
            result["metadata"]["failure_kind"] = "test_failure"
        elif result["exit_code"] == 0:
            result["status"] = "passed"
        else:
            result["status"] = "inconclusive"
            result["metadata"]["failure_kind"] = "tool_exit"
        return result

    def run_baseline(self, snapshot: Path) -> list[dict]:
        build = self.run(snapshot, ["forge", "build", "--offline"], name="forge_build")
        tests = self._classify_forge(self.run(snapshot, ["forge", "test", "--offline", "--json"], name="forge_test"))
        slither = self.run(snapshot, ["slither", ".", "--json", "-", "--disable-color"], name="slither")
        if slither["status"] in {"passed", "failed"}:
            try:
                data = json.loads(slither["stdout"])
                if data.get("success") is not True:
                    raise ValueError("Slither did not complete analysis")
                slither["metadata"]["detectors"] = data.get("results", {}).get("detectors", [])
                slither["status"] = "passed"
            except (ValueError, AttributeError):
                slither["status"] = "inconclusive"
                slither["metadata"]["failure_kind"] = "compilation_or_invalid_output"
        return [build, tests, slither]

    def _with_tests(self, snapshot: Path, test_files: dict[str, str], test_pattern: str, *, formal: bool) -> dict:
        name = "halmos" if formal else "candidate"
        command = (["halmos", "--match-test", test_pattern, "--json-output", "/dev/stdout"] if formal else
                   ["forge", "test", "--offline", "--json", "--match-path", "test/audit/**", "--match-test", test_pattern])
        result = self._result(name, command)
        try:
            if not isinstance(test_files, dict) or not 1 <= len(test_files) <= 32 or not test_pattern or len(test_pattern) > 500:
                raise ValueError("Generated tests and a bounded test pattern are required")
            re.compile(test_pattern)
            if any(not isinstance(k, str) or not isinstance(v, str) for k, v in test_files.items()):
                raise ValueError("Generated tests must map paths to source text")
            if sum(len(s.encode()) for s in test_files.values()) > int(self.config.get("max_generated_bytes", 200_000)):
                raise ValueError("Generated tests exceed size limit")
            with tempfile.TemporaryDirectory(prefix="csa-tests-") as temporary:
                staged = Path(temporary) / "project"
                self._stage(Path(snapshot), staged)
                for filename, content in test_files.items():
                    path = PurePosixPath(filename)
                    if (path.is_absolute() or ".." in path.parts or "\\" in filename or
                            len(path.parts) < 3 or path.parts[:2] != ("test", "audit") or path.suffix != ".sol"):
                        raise ValueError("Generated files must be .sol files beneath test/audit/")
                    destination = staged.joinpath(*path.parts)
                    if destination.exists():
                        raise ValueError("Generated tests cannot replace original files")
                    destination.parent.mkdir(parents=True, exist_ok=True)
                    destination.write_text(content, encoding="utf-8")
                result = self.run(staged, command, name=name,
                                  timeout=float(self.config.get("formal_timeout_seconds", 60)) if formal else self.timeout)
        except (ValueError, TypeError, OSError, re.error) as exc:
            result["status"] = "unsupported"
            result["stderr"] = str(exc)
            return result
        return self._classify_halmos(result) if formal else self._classify_forge(result)

    def run_candidate(self, snapshot: Path, test_files: dict[str, str], test_pattern: str) -> dict:
        return self._with_tests(snapshot, test_files, test_pattern, formal=False)

    def run_formal(self, snapshot: Path, test_files: dict[str, str], test_pattern: str) -> dict:
        return self._with_tests(snapshot, test_files, test_pattern, formal=True)

    @staticmethod
    def _classify_halmos(result: dict) -> dict:
        if result["status"] not in {"passed", "failed"}:
            return result
        # Halmos emits progress followed by its own JSON object. Decode the
        # final structured result, never interpret a textual PASS as evidence.
        data = None
        decoder = json.JSONDecoder()
        for match in re.finditer(r"\{", result["stdout"]):
            try:
                value, _ = decoder.raw_decode(result["stdout"][match.start():])
                if isinstance(value, dict) and "test_results" in value and "exitcode" in value:
                    data = value
            except ValueError:
                continue
        groups = (data or {}).get("test_results") or {}
        tests = ([test for path, group in groups.items() if isinstance(path, str)
                  and path.startswith("test/audit/") and isinstance(group, list) for test in group]
                 if isinstance(groups, dict) else [])
        result["metadata"].update(selected_tests=len(tests), skipped_tests=0, bounded=True)
        if not tests or any(not isinstance(t, dict) or t.get("exitcode") not in (0, 1) for t in tests):
            result["status"] = "inconclusive"
            result["metadata"]["failure_kind"] = "incomplete_symbolic_analysis"
        elif any(t["exitcode"] == 1 for t in tests):
            valid = any(isinstance(model, dict) and model.get("is_valid") is True
                        for test in tests if test["exitcode"] == 1 for model in (test.get("models") or []))
            result["status"] = "failed" if valid else "inconclusive"
            result["metadata"]["failure_kind"] = "symbolic_counterexample" if valid else "unvalidated_symbolic_model"
        elif result["exit_code"] == 0:
            result["status"] = "passed"
        else:
            result["status"] = "inconclusive"
        return result
