from __future__ import annotations

from copy import deepcopy
import json
from pathlib import Path
import re
import tempfile
import unittest
from unittest.mock import patch

from contract_security_agent.discovery import discover, _source_context, build_discovery_prompt


PROTOCOL = {"summary": "A vault", "assets": ["tokens"], "roles": ["owner", "user"],
            "entry_points": ["withdraw"], "trust_boundaries": ["untrusted callers"],
            "assumptions": [], "open_questions": []}
CANDIDATE = {
    "id": "AUTH-1", "title": "Unauthorized withdrawal", "severity": "high",
    "description": "An unprivileged caller withdraws another user's funds.",
    "root_cause": "Missing ownership check", "affected_files": ["src/Vault.sol"],
    "preconditions": ["funded vault"], "impact": "Theft", "remediation": "Check caller entitlement",
    "severity_rationale": "An arbitrary caller can steal a funded balance.",
    "requirement_id": "R1", "test_pattern": "^test_withdrawAuth$",
    "test_files": {"test/audit/Authorization.t.sol": "pragma solidity ^0.8.26;\nimport {Vault} from '../../src/Vault.sol';\ncontract AuthTest { function test_withdrawAuth() public { Vault v = new Vault(); require(v.safe()); } }"},
}


class DiscoveryTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name) / "snapshot"
        self.root.mkdir()
        self.out = Path(self.temp.name) / "out"
        self.write("src/Vault.sol", "pragma solidity ^0.8.26; contract Vault { function safe() external pure returns(bool) { return true; } }")
        self.write("foundry.toml", '[profile.default]\nsolc_version = "0.8.26"\n')
        self.requirements = [{"id": "R1", "text": "Users can only withdraw their own funds", "reviewed": False, "assumptions": []}]

    def write(self, filename: str, source: str):
        file = self.root / filename
        file.parent.mkdir(parents=True, exist_ok=True)
        file.write_text(source)

    def run_discovery(self, candidates=None, formal=None, **kwargs):
        generation = {"status": "completed", "data": {
            "protocol": deepcopy(PROTOCOL), "candidates": deepcopy(candidates or []),
            "formal_properties": deepcopy(formal or []),
        }, "usage": {"total_cost_usd": 0.1}, "errors": []}
        with patch("contract_security_agent.discovery.ClaudeRuntime.ask", return_value=generation) as call:
            result = discover(self.root, ["src/**/*.sol"], self.requirements, [], kwargs, self.out)
        return result, call

    def test_source_context_tracks_imports_but_excludes_unrelated_bug_hints(self):
        self.write("src/Vault.sol", 'import "../lib/Token.sol" as Token; contract Vault {}')
        self.write("lib/Token.sol", "contract Token {}")
        self.write("README.md", "KNOWN BUG: the exploit is... do not include me")
        self.write("test/Exploit.t.sol", "contract Exploit {}")
        context = _source_context(self.root, ["src/**/*.sol"], 120000)
        self.assertEqual(set(context["sources"]), {"src/Vault.sol", "lib/Token.sol"})
        self.assertEqual(context["scope"], ["src/Vault.sol"])
        self.assertEqual(context["unresolved_imports"], [])
        prompt = build_discovery_prompt(context, self.requirements, [], 3)
        self.assertNotIn("KNOWN BUG", prompt)
        self.assertNotIn("contract Exploit", prompt)
        self.assertIn('"reviewed": false', prompt)

    def test_remapped_imports_are_included_in_bounded_context(self):
        self.write("src/Vault.sol", 'import {Token} from "@token/Token.sol"; contract Vault {}')
        self.write("lib/token/src/Token.sol", "contract Token {}")
        self.write("remappings.txt", "@token/=lib/token/src/\n")
        context = _source_context(self.root, ["src"], 120000)
        self.assertIn("lib/token/src/Token.sol", context["sources"])
        self.assertFalse(context["unresolved_imports"])

    def test_context_size_or_scope_escape_stops_before_model(self):
        for scope, config in ((["../outside.sol"], {}), (["src"], {"max_source_bytes": 5})):
            with self.subTest(scope=scope, config=config):
                with patch("contract_security_agent.discovery.ClaudeRuntime.ask") as call:
                    result = discover(self.root, scope, [], [], config, self.out)
                call.assert_not_called()
                self.assertEqual(result["status"], "inconclusive")
                self.assertTrue(result["errors"])

    def test_symlink_and_import_escapes_are_rejected(self):
        outside = self.root.parent / "outside.sol"
        outside.write_text("contract Secret {}")
        (self.root / "src/Link.sol").symlink_to(outside)
        with self.assertRaises(ValueError):
            _source_context(self.root, ["src/Link.sol"], 120000)
        (self.root / "src/Link.sol").unlink()
        self.write("src/Vault.sol", 'import "../../outside.sol"; contract Vault {}')
        with self.assertRaises(ValueError):
            _source_context(self.root, ["src"], 120000)

    def test_valid_generated_candidate_retains_unknown_intent_and_is_not_confirmed(self):
        result, call = self.run_discovery([CANDIDATE])
        self.assertEqual(result["status"], "completed")
        self.assertEqual(len(result["candidates"]), 1)
        self.assertNotIn("confirmed", result["candidates"][0])
        self.assertTrue(any("unreviewed" in question for question in result["protocol"]["open_questions"]))
        self.assertEqual(result["usage"]["total_cost_usd"], 0.1)
        self.assertEqual(call.call_count, 1)
        self.assertTrue((self.out / "context_manifest.json").is_file())
        self.assertEqual(json.loads((self.out / "discovery.json").read_text())["status"], "completed")

    def test_generation_failure_never_claims_a_successful_empty_audit(self):
        failure = {"status": "error", "data": None, "usage": {}, "errors": [{"code": "authentication", "message": "login"}]}
        with patch("contract_security_agent.discovery.ClaudeRuntime.ask", return_value=failure):
            result = discover(self.root, ["src"], [], [], {}, self.out)
        self.assertEqual(result["status"], "error")
        self.assertEqual(result["errors"][0]["code"], "authentication")

    def test_forbidden_harnesses_do_not_reach_execution(self):
        cases = [
            {"test_files": {"../../src/Vault.sol": "contract X {}"}},
            {"test_files": {"test/audit/Bad.t.sol": "contract X { function test_withdrawAuth() public { vm.ffi(args); } }"}},
            {"test_files": {"test/audit/Bad.t.sol": 'import "forge-std/Test.sol"; contract X { function test_withdrawAuth() public {} }'}},
            {"test_pattern": "^missing$"}, {"affected_files": ["not_in_scope.sol"]},
            {"requirement_id": "invented"},
        ]
        for replacement in cases:
            with self.subTest(replacement=replacement):
                candidate = {**deepcopy(CANDIDATE), **replacement}
                result, _ = self.run_discovery([candidate])
                self.assertEqual(result["status"], "inconclusive")
                self.assertFalse(result["candidates"])
                self.assertTrue(result["errors"])

    def test_missing_import_is_reported_as_incomplete_context(self):
        self.write("src/Vault.sol", 'import "missing.sol"; contract Vault {}')
        result, _ = self.run_discovery()
        self.assertEqual(result["status"], "inconclusive")
        self.assertEqual(result["errors"][0]["code"], "unresolved_imports")

    def test_duplicate_candidate_ids_and_unknown_formal_requirements_are_rejected(self):
        result, _ = self.run_discovery([CANDIDATE, CANDIDATE])
        self.assertEqual(result["status"], "inconclusive")
        formal = {"id": "P1", "requirement_id": "unknown", "description": "Funds remain safe", "assumptions": [],
                  "test_pattern": "^check_safe$", "test_files": {"test/audit/P.t.sol": "contract P { function check_safe(uint256 x) public { assert(x == x); } }"}}
        result, _ = self.run_discovery(formal=[formal])
        self.assertEqual(result["status"], "inconclusive")

    def test_unknown_metadata_is_not_included_as_context(self):
        context = _source_context(self.root, ["src"], 120000)
        requirements = [{**self.requirements[0], "known_bugs": "SECRET_BUG", "exploit": "SECRET_EXPLOIT"}]
        prompt = build_discovery_prompt(context, requirements, [{"title": "Fresh lead", "repair": "SECRET_REPAIR"}], 3)
        self.assertIn("Fresh lead", prompt)
        for sentinel in ("SECRET_BUG", "SECRET_EXPLOIT", "SECRET_REPAIR"):
            self.assertNotIn(sentinel, prompt)

    def test_real_shaped_slither_result_keeps_detector_locations_and_tool_coverage(self):
        context = _source_context(self.root, ["src"], 120000)
        baseline = [
            {"name": "forge_test", "status": "passed", "exit_code": 0, "stdout": "RAW_LOG_NOT_CONTEXT",
             "metadata": {"selected_tests": 2, "skipped_tests": 0, "failed_tests": 0}},
            {"name": "slither", "status": "passed", "exit_code": 255,
             "stdout": "RAW_JSON_NOT_CONTEXT", "stderr": "RAW_STDERR_NOT_CONTEXT", "metadata": {
                 "detectors": [{"id": "detector-1", "check": "reentrancy-eth", "impact": "High", "confidence": "Medium",
                                "description": "External call precedes the credit update", "elements": [{
                                    "type": "function", "name": "withdraw",
                                    "source_mapping": {"filename_relative": "src/Vault.sol", "filename_absolute": "/work/project/src/Vault.sol", "lines": [11, 12, 13]},
                                    "type_specific_fields": {"parent": {"unbounded": "DO_NOT_COPY_NESTING"}},
                                }]}], "output_truncated": False,
             }},
            {"name": "halmos", "status": "inconclusive", "metadata": {"failure_kind": "incomplete_symbolic_analysis", "bounded": True}},
        ]
        prompt = build_discovery_prompt(context, self.requirements, baseline, 3)
        data = json.loads(re.search(r"\n(\{.*\})\n</audit_input", prompt, re.DOTALL).group(1))
        self.assertEqual(len(data["fresh_static_analysis"]), 1)
        lead = data["fresh_static_analysis"][0]
        self.assertEqual((lead["tool"], lead["detector"], lead["impact"]), ("slither", "reentrancy-eth", "High"))
        self.assertEqual(lead["locations"][0]["file"], "src/Vault.sol")
        self.assertEqual(lead["locations"][0]["lines"], [11, 12, 13])
        self.assertEqual(data["baseline_tool_results"][0]["coverage"]["selected_tests"], 2)
        self.assertEqual(data["baseline_tool_results"][1]["detector_count"], 1)
        self.assertEqual(data["baseline_tool_results"][2]["status"], "inconclusive")
        for excluded in ("RAW_LOG_NOT_CONTEXT", "RAW_JSON_NOT_CONTEXT", "RAW_STDERR_NOT_CONTEXT", "DO_NOT_COPY_NESTING", "/work/project"):
            self.assertNotIn(excluded, prompt)

    def test_static_context_bounds_detector_count_and_description_size(self):
        context = _source_context(self.root, ["src"], 120000)
        detector = {"check": "example", "description": "x" * 10000, "elements": []}
        baseline = [{"name": "slither", "status": "passed", "metadata": {"detectors": [detector] * 100}}]
        prompt = build_discovery_prompt(context, [], baseline, 3)
        data = json.loads(re.search(r"\n(\{.*\})\n</audit_input", prompt, re.DOTALL).group(1))
        self.assertEqual(len(data["fresh_static_analysis"]), 50)
        self.assertEqual(len(data["fresh_static_analysis"][0]["description"]), 2000)
        self.assertTrue(data["fresh_static_analysis"][0]["description_truncated"])
        self.assertEqual(data["baseline_tool_results"][0]["detector_count"], 100)


if __name__ == "__main__":
    unittest.main()
