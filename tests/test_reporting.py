import hashlib
import json
import zipfile

import pytest

from contract_security_agent.reporting import render_report


def test_empty_report_retains_incomplete_scope_without_clean_claim(tmp_path):
    paths = render_report({"run_id": "run-1", "status": "incomplete", "project": "Vault"}, tmp_path)
    markdown = (tmp_path / "report.md").read_text()
    assert "not a clean-security claim" in markdown
    assert "No reviewed requirements supplied" in markdown
    assert "coverage remains incomplete" in markdown
    assert "Missing usage or cost data means unknown, not zero" in markdown
    assert all(__import__("pathlib").Path(path).is_file() for path in paths.values())


def test_report_separates_severity_evidence_and_reviewer_status(tmp_path):
    record = {"run_id": "run-1", "status": "completed", "source": {"commit": "abc123"},
              "protocol": {"assets": ["deposits"], "trust_boundaries": ["withdraw callback"]},
              "requirements": [{"id": "withdrawal-entitlement", "status": "reviewed"}],
              "baseline": [{"tool": "forge_test", "status": "passed"}],
              "formal_results": [{"tool": "halmos", "status": "inconclusive", "bounds": "depth 3"}],
              "findings": [{"validated": False, "status": "replayed_candidate", "replay_status": "reproduced", "semantic_status": "unverified", "reviewer_state": "needs_review",
                            "candidate": {"id": "C-1", "title": "Withdraw twice", "severity": "critical", "root_cause": "Effects after call", "impact": "Asset loss",
                                          "preconditions": ["Attacker deposit"], "remediation": "Update accounting before call", "test_pattern": "testWithdraw",
                                          "test_files": {"test/audit/Probe.t.sol": "contract Probe {}"}}}],
              "usage": {"cost_usd": 1.5}}
    render_report(record, tmp_path)
    markdown = (tmp_path / "report.md").read_text()
    for text in ("Candidate severity: **critical**", "replayed", "unverified", "needs", "Effects after call", "Asset loss", "depth 3", "abc123", "forge test"):
        assert text in markdown
    assert (tmp_path / "report-evidence/candidate-001/test/audit/Probe.t.sol").read_text() == "contract Probe {}"
    assert "not a clean-security claim" in markdown


def test_bundle_contains_exact_hashed_manifest_and_only_safe_artifacts(tmp_path):
    record = {"findings": [{"candidate": {"test_files": {"test/audit/Safe.t.sol": "contract Test {}", "../../outside.txt": "escape"}}}]}
    paths = render_report(record, tmp_path)
    manifest = json.loads((tmp_path / "manifest.json").read_text())
    with zipfile.ZipFile(paths["bundle"]) as archive:
        assert "manifest.json" in archive.namelist()
        assert not any(".." in name.split("/") or name.startswith("/") for name in archive.namelist())
        for name, digest in manifest["files"].items():
            assert hashlib.sha256(archive.read(name)).hexdigest() == digest
    assert not (tmp_path.parent / "outside.txt").exists()


def test_markdown_injection_and_secret_configuration_are_sanitized(tmp_path):
    record = {"project": "<script>alert(1)</script>\n# forged heading ![beacon](https://attacker.example)",
              "config": {"anthropic_api_key": "do-not-publish", "model": "claude", "nested": {"password": "also-secret"}},
              "findings": [{"candidate": {"title": "<img src=x onerror=alert(1)>", "impact": "[click](javascript:alert(1))"}}]}
    render_report(record, tmp_path)
    markdown = (tmp_path / "report.md").read_text()
    raw = (tmp_path / "report.json").read_text()
    assert "<script>" not in markdown
    assert "<img" not in markdown
    assert "\n# forged" not in markdown
    assert "![beacon]" not in markdown
    assert "[click](javascript:" not in markdown
    assert "do-not-publish" not in markdown + raw
    assert "also-secret" not in markdown + raw
    assert "[REDACTED]" in raw


def test_report_refuses_symlink_artifact_destinations(tmp_path):
    outside = tmp_path / "outside"
    outside.write_text("do not overwrite")
    output = tmp_path / "output"
    output.mkdir()
    (output / "report.json").symlink_to(outside)
    with pytest.raises(ValueError, match="symlink"):
        render_report({}, output)
    assert outside.read_text() == "do not overwrite"


def test_report_does_not_archive_unrelated_files(tmp_path):
    (tmp_path / "private.env").write_text("SECRET=do-not-publish")
    render_report({}, tmp_path)
    with zipfile.ZipFile(tmp_path / "audit-bundle.zip") as archive:
        assert "private.env" not in archive.namelist()


def test_report_bundles_frozen_trusted_oracle_separately(tmp_path):
    record = {"findings": [{"candidate": {"test_files": {"test/audit/Probe.t.sol": "contract Probe {}"}},
                            "trusted_test_files": {"test/audit/Safety.t.sol": "contract Safety {}"},
                            "trusted_metadata": {"requirement_id": "entitlement", "test_pattern": "testSafety"}}]}
    render_report(record, tmp_path)
    with zipfile.ZipFile(tmp_path / "audit-bundle.zip") as archive:
        metadata = json.loads(archive.read("report-evidence/candidate-001/trusted/metadata.json"))
        assert metadata["requirement_id"] == "entitlement"
        assert archive.read("report-evidence/candidate-001/trusted/test/audit/Safety.t.sol") == b"contract Safety {}"


def test_formal_property_wrapper_shows_actual_outcome_assumptions_and_limits(tmp_path):
    record = {"formal_results": [{
        "property": {"id": "withdraw-entitlement", "requirement_id": "REQ-1",
                     "description": "Withdrawals cannot exceed deposits", "assumptions": ["No fee tokens"], "bounds": "unroll 2"},
        "result": {"name": "halmos", "status": "inconclusive", "metadata": {"bounded": True, "reason": "timeout"}}
    }]}
    render_report(record, tmp_path)
    markdown = (tmp_path / "report.md").read_text()
    assert "halmos / withdraw-entitlement: **inconclusive**" in markdown
    assert "Requirement: REQ-1" in markdown
    assert "No fee tokens" in markdown
    assert "unroll 2" in markdown
    assert "timeout" in markdown
    assert "unnamed tool" not in markdown


def test_markdown_summarizes_large_source_and_detector_records_without_losing_json(tmp_path):
    record = {
        "source": {"git_revision": "abc123", "tree_sha256": "treehash456", "total_bytes": 9900,
                   "files": [{"path": f"src/VerboseFile{n}.sol", "sha256": f"perfilehash-{n}"} for n in range(200)]},
        "config": {"image": "tools:dev", "model": "sonnet", "max_budget_usd": 2},
        "diagnostics": {"image_id": "sha256:abc", "pinned_tools": {"forge": "1.4.4"}},
        "baseline": [{"name": "slither", "status": "passed", "metadata": {"detectors": [
            {"description": f"Very large detector description {n}", "elements": ["giant internal detail"] * 30} for n in range(20)]}}],
        "coverage": {"completed": ["Native build"], "gaps": ["Missing reviewed intent"]}}
    render_report(record, tmp_path)
    markdown = (tmp_path / "report.md").read_text()
    raw = json.loads((tmp_path / "report.json").read_text())
    assert "200 snapshot files" in markdown
    assert "treehash456" in markdown
    assert "abc123" in markdown
    assert "20 detector result" in markdown
    assert "VerboseFile199" not in markdown
    assert "perfilehash-199" not in markdown
    assert "giant internal detail" not in markdown
    assert "tools:dev" in markdown
    assert "forge 1.4.4" in markdown
    assert "- Gap: Missing reviewed intent" in markdown
    assert len(raw["source"]["files"]) == 200
    assert "giant internal detail" in raw["baseline"][0]["metadata"]["detectors"][0]["elements"]
