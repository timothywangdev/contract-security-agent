"""Small public CLI for the Solidity port: audit, replay, and supplied-fix retest."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import subprocess
import sys

from . import __version__
from .audit import new_output, reproduce_run, run_audit
from .config import load_config, load_requirements


def parser() -> argparse.ArgumentParser:
    root = argparse.ArgumentParser(description="Audit Solidity/Foundry projects with Claude Code and isolated security tools")
    root.add_argument("--version", action="version", version=__version__)
    commands = root.add_subparsers(dest="command", required=True)
    audit = commands.add_parser("audit", help="Audit a local compatible Foundry project")
    audit.add_argument("project", type=Path)
    audit.add_argument("--scope", action="append", help="Relative source file or directory; repeat for multiple scopes (default: src)")
    audit.add_argument("--requirements", type=Path, help="Reviewed requirements JSON; optional for discovery")
    audit.add_argument("--trusted-checks", type=Path, help="Independent reviewed outcome checks, kept hidden from discovery")
    audit.add_argument("--config", type=Path, help="Explicit operator-controlled JSON configuration")
    audit.add_argument("--output", type=Path, help="New output directory (must not exist)")
    audit.add_argument("--model")
    audit.add_argument("--max-budget-usd", type=float)
    audit.add_argument("--no-model", action="store_true", help="Run baseline tools only; report remains incomplete")
    for name, help_text in (("reproduce", "Replay a saved candidate against the frozen snapshot"), ("verify-fix", "Retest a supplied fixed project against frozen checks")):
        command = commands.add_parser(name, help=help_text)
        command.add_argument("run", type=Path)
        command.add_argument("--candidate")
        command.add_argument("--output", type=Path)
        if name == "verify-fix":
            command.add_argument("--fixed", required=True, type=Path)
    doctor = commands.add_parser("doctor", help="Check local prerequisites without running a model or project code")
    doctor.add_argument("--config", type=Path)
    return root


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    try:
        if args.command == "doctor":
            from .execution import ToolRunner
            config = load_config(args.config)
            state = ToolRunner(config).diagnostics()
            try:
                result = subprocess.run(["claude", "--version"], capture_output=True, text=True, timeout=10)
                state["claude_code"] = {"available": result.returncode == 0, "version": result.stdout.strip()}
            except (OSError, subprocess.TimeoutExpired) as exc:
                state["claude_code"] = {"available": False, "error": str(exc)}
            print(json.dumps(state, indent=2))
            return 0 if state["claude_code"]["available"] and state.get("status") == "passed" else 2
        if args.command == "audit":
            config = load_config(args.config, {"model": args.model, "max_budget_usd": args.max_budget_usd})
            requirements = load_requirements(args.requirements)
            output = new_output(args.output)
            record = run_audit(args.project, output, config, args.scope or ["src"], requirements, args.trusted_checks, no_model=args.no_model)
            print(f"Audit {record['status']}: {output / 'report.md'}")
            print(f"Evidence bundle: {output / 'bundle.tar.gz'}")
            return 0 if record["status"] == "completed" else 2
        output = new_output(args.output, "-retest" if args.command == "verify-fix" else "-replay")
        result = reproduce_run(args.run, args.candidate, output, fixed=getattr(args, "fixed", None))
        print(f"{args.command}: {result.get('status', 'unknown')} ({output / 'result.json'})")
        passed = result.get("passed", result.get("validated", False))
        return 0 if passed else 2
    except (ValueError, OSError, RuntimeError, json.JSONDecodeError) as exc:
        print(f"csa: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
