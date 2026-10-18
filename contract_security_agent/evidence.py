# Copyright 2026 Anthropic PBC
# Copyright 2026 Contract Security Agent contributors
# SPDX-License-Identifier: Apache-2.0
"""Fresh-replay and executable repair gates, adapted from the reference harness.

The trust-boundary and build/replay/regression ladder follow upstream grade.py,
patch_grade.py and artifacts.py at d3bea6b5793b5f3d59a75ebe69a58efa88383145.
Unlike the upstream model verdict, a successful model-authored test never
establishes a security finding. Only an independently reviewed safety oracle
can validate the requirement violation. All execution belongs to the runner.
"""
from __future__ import annotations

import hashlib
import json
import re
import shlex
import tomllib
from pathlib import Path, PurePosixPath
from typing import Any

_STATUSES = {"passed", "failed", "inconclusive", "unsupported", "error", "skipped"}
_FORBIDDEN = re.compile(
    r"\b(?:ffi|tryFfi|setEnv|env\w*|store|deal|etch|prank|startPrank|stopPrank|"
    r"changePrank|hoax|startHoax|broadcast|startBroadcast|stopBroadcast|"
    r"writeFile\w*|writeLine|removeFile|createDir|copyFile|writeJson|"
    r"readFile\w*|readLine|readDir|readLink|fsMetadata|projectRoot|"
    r"rpc\w*|createFork|createSelectFork|selectFork|activeFork|"
    r"warp|roll|chainId|fee|coinbase|txGasPrice|setNonce|resetNonce|"
    r"setArbitraryStorage|mockCall\w*|mockFunction|allowCheatcodes)\s*\(",
    re.IGNORECASE,
)
_CHEATCODE_ADDRESS = re.compile(r"7109709ecfa91a80626ff3989d68f67f5b1dd12d|hevm\s+cheat\s+code", re.I)
_ASSERTION = re.compile(r"assertion[ _-]*(?:failed|violation)|panic\s*\(?(?:0x0?1|1)\)?\b", re.I)


def _plain(value: Any) -> Any:
    if isinstance(value, Path):
        return str(value)
    if isinstance(value, dict):
        return {str(k): _plain(v) for k, v in value.items()}
    if isinstance(value, (tuple, list)):
        return [_plain(v) for v in value]
    return value


def _write(output: Path, name: str, value: dict) -> None:
    output = Path(output)
    _no_symlink_ancestors(output)
    output.mkdir(parents=True, exist_ok=True)
    target = output / name
    if target.is_symlink():
        raise ValueError("artifact destination cannot be a symlink")
    target.write_text(json.dumps(_plain(value), indent=2, ensure_ascii=False) + "\n", encoding="utf-8")


def _no_symlink_ancestors(path: Path) -> None:
    absolute = path.absolute()
    if any(part.is_symlink() for part in (absolute, *absolute.parents)):
        raise ValueError("symlink paths are not allowed")


def _fingerprint(snapshot: Path) -> dict[str, str]:
    snapshot = Path(snapshot)
    _no_symlink_ancestors(snapshot)
    if not snapshot.is_dir():
        raise ValueError("snapshot must be an existing directory")
    hashes = {}
    for path in sorted(snapshot.rglob("*")):
        if path.is_symlink():
            raise ValueError("snapshot contains a symlink")
        if path.is_file():
            hashes[path.relative_to(snapshot).as_posix()] = hashlib.sha256(path.read_bytes()).hexdigest()
        elif not path.is_dir():
            raise ValueError("snapshot contains a non-regular file")
    return hashes


def _test_files(files: Any, *, untrusted: bool) -> dict[str, str]:
    if not isinstance(files, dict) or not files:
        raise ValueError("test_files must contain at least one Solidity test")
    if len(files) > 20:
        raise ValueError("too many candidate test files")
    result = {}
    for name, content in files.items():
        if not isinstance(name, str) or not isinstance(content, str):
            raise ValueError("test paths and contents must be strings")
        path = PurePosixPath(name)
        if (path.is_absolute() or "\\" in name or len(path.parts) != 3
                or path.parts[:2] != ("test", "audit") or not name.endswith(".t.sol")
                or name != path.as_posix() or any(p in {".", ".."} for p in path.parts)):
            raise ValueError("tests may only add test/audit/*.t.sol")
        if len(content.encode()) > 256_000:
            raise ValueError("test file exceeds 256 KB limit")
        if untrusted:
            # A deliberately conservative admission policy, not a Solidity sandbox.
            # The runner still isolates the compiler and EVM without credentials.
            if (_FORBIDDEN.search(content) or _CHEATCODE_ADDRESS.search(content)
                    or re.search(r"\bassembly\b", content)):
                raise ValueError("candidate uses prohibited cheatcodes or injected execution state")
            if re.search(r"\bimport\b[^;]*(?:https?://|[\"']/|[\"']~)", content):
                raise ValueError("candidate imports must resolve within the frozen project")
        result[name] = content
    return result


def _candidate(candidate: Any) -> tuple[dict[str, str], str]:
    if not isinstance(candidate, dict):
        raise ValueError("candidate must be an object")
    files = _test_files(candidate.get("test_files"), untrusted=True)
    pattern = candidate.get("test_pattern")
    if not isinstance(pattern, str) or not pattern.strip() or len(pattern) > 256 or "\x00" in pattern:
        raise ValueError("test_pattern must be a nonempty bounded test selector")
    return files, pattern


def _command(pattern: str) -> str:
    return shlex.join(["forge", "test", "--offline", "--json", "--match-path", "test/audit/**", "--match-test", pattern])


def _check_output(snapshot: Path, output: Path) -> None:
    _no_symlink_ancestors(output)
    if Path(output).resolve().is_relative_to(Path(snapshot).resolve()):
        raise ValueError("evidence output must be outside the immutable snapshot")


def _forge_tests(result: dict) -> list[dict]:
    """Read actual Forge JSON tests; never infer execution from exit code alone."""
    raw = result.get("stdout", "")
    if isinstance(raw, dict):
        parsed = raw
    elif isinstance(raw, str):
        try:
            parsed = json.loads(raw)
        except (ValueError, TypeError):
            # Some Forge versions prefix JSON with compiler diagnostics.
            parsed = None
            for line in raw.splitlines():
                try:
                    possible = json.loads(line)
                except ValueError:
                    continue
                if isinstance(possible, dict):
                    parsed = possible
            if parsed is None:
                return []
    else:
        return []
    observed = []

    def walk(node: Any) -> None:
        if not isinstance(node, dict):
            return
        tests = node.get("test_results")
        if isinstance(tests, dict):
            for name, test in tests.items():
                if isinstance(test, dict):
                    observed.append({"name": str(name), "status": str(test.get("status", "")).lower(),
                                     "reason": str(test.get("reason") or "")})
        for key, value in node.items():
            if key != "test_results":
                if isinstance(value, dict):
                    walk(value)
                elif isinstance(value, list):
                    for item in value:
                        walk(item)
    walk(parsed)
    return observed


def _normalize(result: Any) -> dict:
    if not isinstance(result, dict):
        return {"status": "error", "error": "runner returned a non-object"}
    result = dict(result)
    if result.get("status") not in _STATUSES:
        result["status"] = "error"
        result["error"] = "runner returned an unknown status"
    tests = _forge_tests(result)
    result["observed_tests"] = tests
    if result["status"] in {"passed", "failed"}:
        executed = [t for t in tests if t["status"] in {"success", "failure", "passed", "failed"}]
        if not executed:
            result["status"] = "inconclusive"
            result["error"] = "no executed tests in Forge JSON evidence"
        elif any(t["status"] not in {"success", "failure", "passed", "failed"} for t in tests):
            result["status"] = "inconclusive"
            result["error"] = "selected tests were skipped or had unrecognized statuses"
        elif result["status"] == "passed" and any(t["status"] in {"failure", "failed"} for t in tests):
            result["status"] = "error"
            result["error"] = "runner status conflicts with Forge JSON"
        elif result["status"] == "failed" and not any(t["status"] in {"failure", "failed"} for t in tests):
            result["status"] = "error"
            result["error"] = "failed run lacks a failing test (possible tool or compile failure)"
    return result


def _replay(snapshot: Path, files: dict, pattern: str, runner: Any, frozen: dict) -> list[dict]:
    replays = []
    for attempt in range(2):
        if _fingerprint(snapshot) != frozen:
            raise ValueError("immutable snapshot changed before replay")
        try:
            result = _normalize(runner.run_candidate(Path(snapshot), dict(files), pattern))
        except Exception as exc:
            result = {"status": "error", "error": f"runner failed: {type(exc).__name__}: {exc}"}
        if _fingerprint(snapshot) != frozen:
            raise ValueError("runner modified the immutable snapshot")
        replays.append({"attempt": attempt + 1, **result})
    return replays


def _trusted(directory: Path, candidate: dict, snapshot: Path) -> tuple[dict, str, dict]:
    directory = Path(directory)
    _no_symlink_ancestors(directory)
    if directory.resolve().is_relative_to(Path(snapshot).resolve()):
        raise ValueError("trusted checks must be reviewed outside the model-controlled snapshot")
    for path in directory.rglob("*"):
        if path.is_symlink():
            raise ValueError("trusted checks contain a symlink")
    metadata = json.loads((directory / "metadata.json").read_text(encoding="utf-8"))
    if not isinstance(metadata, dict):
        raise ValueError("trusted metadata must be an object")
    requirement = candidate.get("requirement_id")
    if not requirement or metadata.get("requirement_id") != requirement:
        raise ValueError("trusted check requirement_id does not match candidate")
    if (metadata.get("expected_vulnerable_status", "failed") != "failed"
            or metadata.get("expected_fixed_status", "passed") != "passed"):
        raise ValueError("trusted safety checks must fail vulnerable and pass fixed code")
    files = _test_files({p.relative_to(directory).as_posix(): p.read_text(encoding="utf-8")
                         for p in directory.rglob("*.t.sol")}, untrusted=False)
    pattern = metadata.get("test_pattern")
    if not isinstance(pattern, str) or not pattern.strip() or len(pattern) > 256 or "\x00" in pattern:
        raise ValueError("trusted test_pattern is missing or invalid")
    return files, pattern, metadata


def _safety_failure(result: dict, metadata: dict) -> bool:
    if result.get("status") != "failed":
        return False
    reasons = [t["reason"] for t in result.get("observed_tests", [])
               if t["status"] in {"failure", "failed"}]
    marker = metadata.get("expected_failure")
    if marker is not None:
        return isinstance(marker, str) and bool(marker.strip()) and any(marker in reason for reason in reasons)
    return any(_ASSERTION.search(reason) for reason in reasons)


def validate_candidate(snapshot: Path, candidate: dict, runner: Any, output: Path,
                       trusted_checks: Path | None = None) -> dict:
    """Replay twice from pristine source; keep reproducibility apart from meaning."""
    record = {"candidate": candidate, "status": "inconclusive", "validated": False,
              "replay_status": "not_run", "semantic_status": "unverified", "reviewer_state": "needs_review",
              "replays": [], "trusted_replays": [], "errors": []}
    try:
        _check_output(snapshot, output)
        files, pattern = _candidate(candidate)
        frozen = _fingerprint(snapshot)
        collisions = set(files) & set(frozen)
        if collisions:
            raise ValueError("candidate may not overwrite existing snapshot tests")
        record["source_hashes"] = frozen
        record["evidence_hashes"] = {p: hashlib.sha256(v.encode()).hexdigest() for p, v in files.items()}
        record["test_files"] = files
        record["reproduction_command"] = _command(pattern)
        replays = record["replays"] = _replay(snapshot, files, pattern, runner, frozen)
        states = [r["status"] for r in replays]
        if states == ["passed", "passed"] or states == ["failed", "failed"]:
            record.update(status="replayed_candidate", replay_status="reproduced")
        elif len(set(states)) > 1:
            record.update(replay_status="unstable")
            record["errors"].append("independent replays did not agree")
        else:
            record["replay_status"] = states[0]
        record["semantic_limit"] = "Model assertions and simple reverts do not establish a security issue. Independent reviewed safety checks are required."
        if trusted_checks is not None:
            trusted_files, trusted_pattern, metadata = _trusted(trusted_checks, candidate, snapshot)
            if set(trusted_files) & set(frozen):
                raise ValueError("trusted checks may not overwrite snapshot tests")
            record["trusted_check_hashes"] = {p: hashlib.sha256(v.encode()).hexdigest() for p, v in trusted_files.items()}
            record["trusted_test_files"] = trusted_files
            record["trusted_metadata"] = metadata
            record["trusted_reproduction_command"] = _command(trusted_pattern)
            trusted = record["trusted_replays"] = _replay(snapshot, trusted_files, trusted_pattern, runner, frozen)
            if record["replay_status"] == "reproduced" and all(_safety_failure(r, metadata) for r in trusted):
                record.update(status="validated", validated=True, semantic_status="requirement_violation",
                              reviewer_state="needs_review")
            else:
                record["errors"].append("trusted checks did not reproducibly establish the claimed safety violation")
    except (ValueError, OSError, TypeError) as exc:
        record.update(status="rejected", semantic_status="unverified", validated=False)
        record["errors"].append(str(exc))
    # Invalid output destinations must never receive writes.
    _check_output(snapshot, output)
    _write(Path(output), "evidence.json", record)
    return record


def _baseline_result(results: Any) -> tuple[bool, list, list]:
    if isinstance(results, dict):
        results = [results]
    if not isinstance(results, list):
        return False, [], ["baseline runner returned invalid results"]
    by_name = {str(r.get("tool", r.get("name", ""))): r for r in results if isinstance(r, dict)}
    build = by_name.get("forge_build")
    tests = by_name.get("forge_test")
    gaps = []
    for name in ("slither",):
        result = by_name.get(name)
        if result is None or result.get("status") in {"error", "unsupported", "inconclusive", "skipped"}:
            gaps.append(f"{name} coverage incomplete")
    passed = bool(build and build.get("status") == "passed" and tests and _normalize(tests).get("status") == "passed")
    return passed, results, gaps


def _protected_checks(snapshot: Path, hashes: dict) -> dict:
    """Freeze test selection and native checks, including custom Foundry paths."""
    roots = {"test"}
    config = Path(snapshot) / "foundry.toml"
    if config.is_file():
        parsed = tomllib.loads(config.read_text(encoding="utf-8"))
        for profile in parsed.get("profile", {}).values():
            if isinstance(profile, dict) and isinstance(profile.get("test"), str):
                path = PurePosixPath(profile["test"])
                if path.is_absolute() or ".." in path.parts:
                    raise ValueError("Foundry test directory must be inside the snapshot")
                roots.add(path.as_posix().rstrip("/"))
    return {p: digest for p, digest in hashes.items()
            if p in {"foundry.toml", "remappings.txt"} or p.endswith(".t.sol")
            or any(p == root or p.startswith(root + "/") for root in roots)}


def retest_fix(vulnerable_snapshot: Path, fixed_snapshot: Path, candidate: dict, runner: Any,
               output: Path, trusted_checks: Path | None = None) -> dict:
    """Freeze reviewed safety checks across vulnerable/fixed replay and baseline."""
    record = {"status": "inconclusive", "passed": False, "candidate_id": candidate.get("id"),
              "vulnerable_replays": [], "fixed_replays": [], "baseline": [], "errors": [], "coverage_gaps": []}
    try:
        _check_output(vulnerable_snapshot, output)
        _check_output(fixed_snapshot, output)
        _candidate(candidate)
        if trusted_checks is None:
            raise ValueError("fix validation requires independent reviewed safety checks")
        original_hashes = _fingerprint(vulnerable_snapshot)
        fixed_hashes = _fingerprint(fixed_snapshot)
        files, pattern, metadata = _trusted(trusted_checks, candidate, vulnerable_snapshot)
        if Path(trusted_checks).resolve().is_relative_to(Path(fixed_snapshot).resolve()):
            raise ValueError("trusted checks must be outside the fixed snapshot")
        if set(files) & (set(original_hashes) | set(fixed_hashes)):
            raise ValueError("repair must not replace or preinstall frozen safety checks")
        # Deleting or changing pre-existing tests can manufacture a green baseline.
        original_tests = _protected_checks(vulnerable_snapshot, original_hashes)
        if any(fixed_hashes.get(p) != digest for p, digest in original_tests.items()):
            raise ValueError("repair removed or changed pre-existing regression checks or test configuration")
        record["trusted_check_hashes"] = {p: hashlib.sha256(v.encode()).hexdigest() for p, v in files.items()}
        record["trusted_test_files"] = files
        record["trusted_metadata"] = metadata
        record["reproduction_command"] = _command(pattern)
        record["vulnerable_source_hashes"] = original_hashes
        record["fixed_source_hashes"] = fixed_hashes
        record["vulnerable_replays"] = _replay(vulnerable_snapshot, files, pattern, runner, original_hashes)
        if not all(_safety_failure(r, metadata) for r in record["vulnerable_replays"]):
            record["errors"].append("frozen safety assertion does not establish the vulnerable behavior")
        record["fixed_replays"] = _replay(fixed_snapshot, files, pattern, runner, fixed_hashes)
        fixed_passed = all(r["status"] == "passed" for r in record["fixed_replays"])
        if not fixed_passed:
            record["errors"].append("fixed source did not pass the frozen safety checks twice")
        try:
            baseline_passed, baseline, gaps = _baseline_result(runner.run_baseline(Path(fixed_snapshot)))
        except Exception as exc:
            baseline_passed, baseline, gaps = False, [], []
            record["errors"].append(f"baseline failed: {type(exc).__name__}: {exc}")
        if _fingerprint(fixed_snapshot) != fixed_hashes:
            raise ValueError("baseline modified the immutable fixed snapshot")
        record["baseline"], record["coverage_gaps"] = baseline, gaps
        if not baseline_passed:
            record["errors"].append("fixed source must build and pass its legitimate native Forge test suite")
        if not record["errors"]:
            record.update(status="passed", passed=True)
        else:
            record["status"] = "failed"
        record["limitation"] = "This bounded repair retest covers the frozen requirement and native regression suite; it does not prove all protocol behavior is safe."
    except (ValueError, OSError, TypeError) as exc:
        record["errors"].append(str(exc))
        record["status"] = "rejected"
    _check_output(vulnerable_snapshot, output)
    _check_output(fixed_snapshot, output)
    _write(Path(output), "retest.json", record)
    return record
