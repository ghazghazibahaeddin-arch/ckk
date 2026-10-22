"""Unit tests verifying Typer CLI commands."""

import json
from pathlib import Path

from typer.testing import CliRunner

from cck.cli.main import app

runner = CliRunner()


def test_cli_version() -> None:
    """CLI version command must output CCK version."""
    result = runner.invoke(app, ["version"])
    assert result.exit_code == 0
    assert "0.1.0" in result.stdout


def test_cli_info() -> None:
    """CLI info command must display environment and database settings."""
    result = runner.invoke(app, ["info"])
    assert result.exit_code == 0
    assert "CCK Control Plane Status" in result.stdout
    assert "SQLite Database Path" in result.stdout


def test_cli_init_db(tmp_path: Path) -> None:
    """CLI init-db command must create database file and load baseline policies."""
    test_db = tmp_path / "cli_test.db"
    result = runner.invoke(app, ["init-db", "--db-path", str(test_db)])
    assert result.exit_code == 0
    assert "Database initialized successfully" in result.stdout
    assert test_db.exists()


def test_cli_inspect_action(tmp_path: Path) -> None:
    """CLI inspect-action must evaluate a JSON scenario file and show verdict."""
    scenario_file = tmp_path / "test_action.json"
    scenario_data = {
        "action_id": "act-cli-test-01",
        "agent": {
            "agent_id": "test-bot",
            "name": "TestBot",
            "version": "1.0.0",
            "tenant_id": "default",
            "trust_tier": "standard",
        },
        "session_id": "sess-cli-1",
        "capability": "bash.execute",
        "target": "root",
        "parameters": {"command": "rm -rf /"},
        "severity": "DESTRUCTIVE",
    }
    scenario_file.write_text(json.dumps(scenario_data), encoding="utf-8")

    result = runner.invoke(app, ["inspect-action", str(scenario_file)])
    assert result.exit_code == 0
    assert "BLOCK" in result.stdout
    assert "POL-SEC-001" in result.stdout


def test_cli_init_workspace(tmp_path: Path) -> None:
    """CLI init command must bootstrap config, policies, scenarios, and database."""
    target_dir = tmp_path / "new_cck_project"
    result = runner.invoke(app, ["init", "--dir", str(target_dir)])
    assert result.exit_code == 0
    assert "CCK workspace initialized successfully" in result.stdout
    assert (target_dir / "cck.config.yaml").exists()
    assert (target_dir / "policies").is_dir()
    assert (target_dir / "scenarios").is_dir()
    assert (target_dir / "cck.db").exists()

