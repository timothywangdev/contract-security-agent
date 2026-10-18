"""Exercise the real subprocess/JSON boundaries without calling any model."""
from __future__ import annotations

import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

from contract_security_agent.claude_runtime import ClaudeRuntime


SCHEMA = {"type": "object", "required": ["ok"], "additionalProperties": False,
          "properties": {"ok": {"type": "boolean"}}}


class ClaudeRuntimeTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.binary = self.root / "fake claude"
        self.capture = self.root / "capture.json"
        self.output = self.root / "out"

    def fake(self, body: str):
        self.binary.write_text(
            f"#!{sys.executable}\n"
            "import json, os, pathlib, sys, time\n"
            "if '--version' in sys.argv:\n"
            "    print('2.1.296 (Fake Claude Code)'); sys.exit(0)\n"
            "prompt = sys.stdin.read()\n"
            f"pathlib.Path({str(self.capture)!r}).write_text(json.dumps({{'argv': sys.argv, 'cwd': os.getcwd(), 'prompt': prompt, 'env': dict(os.environ)}}))\n"
            "def emit(event): print(json.dumps(event), flush=True)\n"
            + body + "\n", encoding="utf-8",
        )
        self.binary.chmod(0o700)

    def ask(self, **config):
        return ClaudeRuntime().ask("literal $(do-not-run) `never` source", SCHEMA,
                                   {"claude_binary": str(self.binary), **config}, self.output)

    @staticmethod
    def success(data=None, **extras):
        return "emit(" + repr({"type": "result", "subtype": "success", "is_error": False,
                              "structured_output": {"ok": True} if data is None else data,
                              "num_turns": 1, "total_cost_usd": 0.13, **extras}) + ")"

    def test_success_records_provenance_and_enforces_tool_free_argv(self):
        self.fake("emit({'type':'system','subtype':'init','session_id':'s1','model':'claude-resolved'})\n"
                  "emit({'type':'assistant','message':{'stop_reason':'end_turn','content':[{'type':'text','text':'done'}]}})\n"
                  + self.success(usage={"input_tokens": 40, "output_tokens": 10}))
        with patch.dict(os.environ, {"ANTHROPIC_BASE_URL": "https://untrusted.invalid", "CLAUDE_PROJECT_DIR": "/bad"}):
            result = self.ask()
        self.assertEqual(result["status"], "completed")
        self.assertTrue(result["data"]["ok"])
        usage = result["usage"]
        self.assertEqual(usage["runtime_version"], "2.1.296 (Fake Claude Code)")
        self.assertEqual((usage["session_id"], usage["stop_reason"], usage["total_cost_usd"]), ("s1", "end_turn", 0.13))
        self.assertEqual((usage["input_tokens"], usage["output_tokens"]), (40, 10))
        captured = json.loads(self.capture.read_text())
        argv = captured["argv"]
        self.assertEqual(argv[argv.index("--tools") + 1], "")
        self.assertEqual(argv[argv.index("--setting-sources") + 1], "")
        for flag in ("--safe-mode", "--strict-mcp-config", "--disable-slash-commands", "--no-session-persistence"):
            self.assertIn(flag, argv)
        self.assertEqual(captured["prompt"], "literal $(do-not-run) `never` source")
        self.assertNotIn("literal $(do-not-run)", " ".join(argv))
        self.assertNotIn("ANTHROPIC_BASE_URL", captured["env"])
        self.assertNotIn("CLAUDE_PROJECT_DIR", captured["env"])
        self.assertFalse(Path(captured["cwd"]).exists())
        self.assertEqual(len((self.output / "transcript.jsonl").read_text().splitlines()), 3)
        self.assertEqual(json.loads((self.output / "runtime.json").read_text())["status"], "completed")

    def test_authentication_failure_is_explicit(self):
        self.fake("emit({'type':'result','subtype':'error_during_execution','is_error':True,'result':'Not logged in. Please run /login'}); sys.exit(1)")
        result = self.ask()
        self.assertEqual(result["errors"][0]["code"], "authentication")
        self.assertIsNone(result["data"])

    def test_audit_text_about_authentication_is_not_a_login_error(self):
        self.fake(self.success(result="Authentication and authorization review is complete."))
        self.assertEqual(self.ask()["status"], "completed")

    def test_missing_result_is_error_even_with_valid_assistant_json(self):
        self.fake("emit({'type':'assistant','message':{'content':[{'type':'text','text':'{\"ok\": true}'}]}})")
        result = self.ask()
        self.assertEqual(result["status"], "error")
        self.assertEqual(result["errors"][0]["code"], "missing_result")

    def test_timeout_preserves_transcript_and_discards_partial_generation(self):
        self.fake("emit({'type':'system','subtype':'init','session_id':'partial'}); time.sleep(10)")
        result = self.ask(model_timeout_seconds=0.4)
        self.assertEqual(result["status"], "inconclusive")
        self.assertEqual(result["errors"][0]["code"], "timeout")
        self.assertEqual(result["usage"]["session_id"], "partial")
        self.assertIn("partial", (self.output / "transcript.jsonl").read_text())

    def test_wrong_json_shape_is_rejected(self):
        self.fake(self.success(data={"ok": "yes"}))
        result = self.ask()
        self.assertEqual(result["errors"][0]["code"], "invalid_json")
        self.assertIsNone(result["data"])

    def test_invalid_result_text_is_rejected(self):
        self.fake("emit({'type':'result','subtype':'success','result':'```json\\n{}\\n```'})")
        self.assertEqual(self.ask()["errors"][0]["code"], "invalid_json")

    def test_invalid_stream_does_not_hide_behind_success(self):
        self.fake("print('not JSON', flush=True)\n" + self.success())
        self.assertEqual(self.ask()["errors"][0]["code"], "invalid_stream_json")

    def test_cli_limit_results_are_inconclusive(self):
        for subtype in ("error_max_turns", "error_max_budget_usd", "error_max_structured_output_retries"):
            with self.subTest(subtype=subtype):
                self.fake("emit(" + repr({"type": "result", "subtype": subtype, "is_error": True}) + ")")
                result = self.ask()
                self.assertEqual(result["status"], "inconclusive")
                self.assertEqual(result["errors"][0]["code"], subtype)

    def test_refusal_does_not_become_a_successful_empty_audit(self):
        self.fake("emit({'type':'assistant','message':{'stop_reason':'refusal','content':[]}})\n" + self.success())
        result = self.ask()
        self.assertEqual(result["status"], "inconclusive")
        self.assertEqual(result["errors"][0]["code"], "refusal")

    def test_unexpected_tool_request_is_a_boundary_failure(self):
        self.fake("emit({'type':'assistant','message':{'content':[{'type':'tool_use','name':'Bash','input':{'command':'true'}}]}})\n" + self.success())
        self.assertEqual(self.ask()["errors"][0]["code"], "tool_boundary")

    def test_unexpected_enabled_tools_or_mcp_fail_before_generation(self):
        for fields in ({"tools": ["Bash"]}, {"tools": ["StructuredOutput"], "mcp_servers": [{"name": "unsafe"}]}):
            with self.subTest(fields=fields):
                self.fake("emit(" + repr({"type": "system", "subtype": "init", **fields}) + ")\ntime.sleep(10)")
                result = self.ask(model_timeout_seconds=1)
                self.assertEqual(result["status"], "error")
                self.assertEqual(result["errors"][0]["code"], "tool_boundary")

    def test_stderr_is_drained_without_deadlocking_and_is_bounded(self):
        self.fake("sys.stderr.write('x' * 200000); sys.stderr.flush()\n" + self.success())
        self.assertEqual(self.ask()["status"], "completed")
        self.assertLessEqual((self.output / "stderr.log").stat().st_size, 64 * 1024)

    def test_reported_dollar_or_turn_overrun_does_not_pass(self):
        for extras, code in (({"total_cost_usd": 2.1}, "dollar_limit"), ({"num_turns": 4}, "turn_limit")):
            with self.subTest(code=code):
                self.fake(self.success(**extras))
                result = self.ask()
                self.assertEqual(result["status"], "inconclusive")
                self.assertEqual(result["errors"][0]["code"], code)

    def test_missing_binary_and_bad_budget_are_errors(self):
        self.assertEqual(self.ask()["errors"][0]["code"], "runtime_unavailable")
        for budget in (0, -1, float("nan"), float("inf")):
            with self.subTest(budget=budget):
                self.assertEqual(self.ask(max_budget_usd=budget)["errors"][0]["code"], "configuration")


if __name__ == "__main__":
    unittest.main()
