from pathlib import Path

import pytest

from contract_security_agent.config import load_config, load_requirements
from contract_security_agent.snapshot import copy_snapshot, file_manifest


def project(tmp_path):
    root = tmp_path / "project"
    (root / "src").mkdir(parents=True)
    (root / "foundry.toml").write_text('[profile.default]\nsrc = "src"\n')
    (root / "src/Vault.sol").write_text("pragma solidity 0.8.26; contract Vault {}")
    return root


def test_snapshot_filters_credentials_and_preserves_source_hash(tmp_path):
    root = project(tmp_path)
    (root / ".env").write_text("PRIVATE_KEY=do-not-copy")
    (root / "private.pem").write_text("do-not-copy")
    (root / ".git").mkdir()
    (root / ".git/config").write_text("credentials")
    captured = copy_snapshot(root, tmp_path / "snapshot", ["src"])
    assert not (tmp_path / "snapshot/.env").exists()
    assert not (tmp_path / "snapshot/private.pem").exists()
    assert not (tmp_path / "snapshot/.git").exists()
    assert captured["tree_sha256"] == file_manifest(tmp_path / "snapshot")["tree_sha256"]
    (tmp_path / "snapshot/src/Vault.sol").write_text("tampered")
    assert captured["tree_sha256"] != file_manifest(tmp_path / "snapshot")["tree_sha256"]


def test_external_symlink_and_traversal_cannot_enter_bundle(tmp_path):
    root = project(tmp_path)
    (root / "src/Leak.sol").symlink_to(tmp_path / "outside")
    with pytest.raises(ValueError, match="Non-regular"):
        copy_snapshot(root, tmp_path / "snapshot", ["src"])
    with pytest.raises(ValueError, match="Invalid scope"):
        copy_snapshot(root, tmp_path / "snapshot2", ["../outside"])


@pytest.mark.parametrize("overrides", [{"max_budget_usd": float("nan")}, {"max_turns": 0}, {"model": "--tools"}, {"max_candidates": 1.5}])
def test_invalid_operator_limits_fail_before_execution(overrides):
    with pytest.raises(ValueError):
        load_config(overrides=overrides)


def test_duplicate_requirement_ids_are_rejected(tmp_path):
    path = tmp_path / "requirements.json"
    path.write_text('[{"id":"a","text":"one"},{"id":"a","text":"two"}]')
    with pytest.raises(ValueError, match="unique"):
        load_requirements(path)

