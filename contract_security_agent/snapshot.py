"""Bounded, secret-filtered source snapshots and content provenance."""
from __future__ import annotations

import hashlib
import os
import shutil
import subprocess
from pathlib import Path, PurePosixPath

EXCLUDED = {".git", ".hg", ".svn", ".venv", "venv", "node_modules", "out", "cache", "broadcast", "artifacts", "results", "__pycache__", ".pytest_cache", ".claude", ".codex", ".ssh", ".aws", ".gnupg"}
SECRET_SUFFIXES = {".pem", ".key", ".p12", ".pfx", ".keystore"}


def safe_scope(project: Path, scope: list[str]) -> list[str]:
    if not scope:
        scope = ["src"]
    result = []
    for name in scope:
        relative = PurePosixPath(name)
        if relative.is_absolute() or ".." in relative.parts or not relative.parts or "\\" in name:
            raise ValueError(f"Invalid scope path: {name}")
        if any(part in EXCLUDED or part.startswith(".env") for part in relative.parts):
            raise ValueError(f"Excluded path cannot be audited: {name}")
        target = project / name
        if not target.exists() or target.is_symlink() or not target.resolve().is_relative_to(project.resolve()):
            raise ValueError(f"Scope does not resolve inside the project: {name}")
        result.append(relative.as_posix())
    return result


def file_manifest(project: Path) -> dict:
    files = []
    total = 0
    for directory, dirs, names in os.walk(project, followlinks=False):
        dirs[:] = sorted(d for d in dirs if d not in EXCLUDED)
        for dirname in dirs:
            if (Path(directory) / dirname).is_symlink():
                raise ValueError("Symlinked source directories are unsupported")
        for name in sorted(names):
            path = Path(directory) / name
            if name.startswith(".env") or path.suffix.lower() in SECRET_SUFFIXES:
                continue
            if path.is_symlink() or not path.is_file():
                raise ValueError(f"Non-regular source file is unsupported: {path.relative_to(project)}")
            size = path.stat().st_size
            total += size
            if size > 5_000_000 or total > 50_000_000 or len(files) >= 5000:
                raise ValueError("Project exceeds the supported source snapshot limit (50 MB / 5000 files)")
            files.append({"path": path.relative_to(project).as_posix(), "sha256": hashlib.sha256(path.read_bytes()).hexdigest(), "size": size})
    digest = hashlib.sha256()
    for item in files:
        digest.update((item["path"] + "\0" + item["sha256"] + "\n").encode())
    return {"tree_sha256": digest.hexdigest(), "files": files, "total_bytes": total}


def copy_snapshot(project: Path, destination: Path, scope: list[str]) -> dict:
    project = project.resolve()
    if not project.is_dir():
        raise ValueError("Project must be an existing local directory")
    checked_scope = safe_scope(project, scope)
    if not (project / "foundry.toml").is_file():
        raise ValueError("Unsupported project: foundry.toml is required")
    manifest = file_manifest(project)
    destination.mkdir(parents=True, exist_ok=False)
    for item in manifest["files"]:
        target = destination / item["path"]
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(project / item["path"], target)
        target.chmod(0o644)
    copied = file_manifest(destination)
    if copied["tree_sha256"] != manifest["tree_sha256"]:
        raise ValueError("Source changed while capturing the snapshot")
    try:
        revision = subprocess.run(["git", "-C", str(project), "rev-parse", "HEAD"], capture_output=True, text=True, timeout=5).stdout.strip()
    except (OSError, subprocess.TimeoutExpired):
        revision = ""
    return manifest | {"original_path": str(project), "git_revision": revision or None, "scope": checked_scope, "snapshot": "source"}


def copy_trusted_checks(source: Path, destination: Path) -> None:
    """Keep pre-reviewed checks in the reproduction bundle, away from discovery."""
    source = source.resolve()
    if not source.is_dir() or not (source / "metadata.json").is_file():
        raise ValueError("Trusted checks require a directory containing metadata.json")
    manifest = file_manifest(source)
    allowed = [item for item in manifest["files"] if item["path"] == "metadata.json" or (item["path"].startswith("test/audit/") and item["path"].endswith(".sol"))]
    if len(allowed) != len(manifest["files"]):
        raise ValueError("Trusted check directory may contain only metadata.json and test/audit/*.sol")
    destination.mkdir(parents=True, exist_ok=False)
    for item in allowed:
        target = destination / item["path"]
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source / item["path"], target)

