# ==============================================================================
# Product:       lh-threat-model (lh-threat)
# Module:        tests.test_cli
# Role:          Test Suite & Rule Verification
# Organization:  Logihertz Systems (OPC) Private Limited (logihertzsystems)
# Creator:       Sameer Tawade (Creator, Founder, Director & Whole and Sole Developer)
# Contact:       ops@logihertz.com | https://logihertz.com/
# License:       Apache License 2.0 (SPDX-License-Identifier: Apache-2.0)
# ==============================================================================

"""Unit and integration tests for the lh-threat CLI interface."""

from __future__ import annotations

import json
from pathlib import Path

from typer.testing import CliRunner

from lh_threat_model.cli import app

runner = CliRunner()
CLI_ENV = {"COLUMNS": "160", "NO_COLOR": "1", "TERM": "dumb"}


def test_cli_help() -> None:
    """Verify that --help exits cleanly with usage information."""
    result = runner.invoke(app, ["--help"], env=CLI_ENV)
    assert result.exit_code == 0
    assert "Declarative architecture and DFD threat modeling" in result.output
    assert "scan" in result.output
    assert "rules" in result.output


def test_cli_rules_list() -> None:
    """Verify that 'rules' command lists all 10 LH-THREAT rules."""
    result = runner.invoke(app, ["rules"], env=CLI_ENV)
    assert result.exit_code == 0
    assert "LH-THREAT STRIDE Threat Detection Rules" in result.output
    for i in range(1, 11):
        assert f"LH-THREAT-{i:03d}" in result.output


def test_cli_scan_clean_manifest(clean_manifest_file: Path) -> None:
    """Verify scanning clean architecture manifest returns exit code 0."""
    result = runner.invoke(app, ["scan", str(clean_manifest_file)], env=CLI_ENV)
    assert result.exit_code == 0
    assert "Clean Architecture" in result.output


def test_cli_scan_violations_manifest(violations_manifest_file: Path) -> None:
    """Verify scanning vulnerable architecture manifest returns exit code 1."""
    result = runner.invoke(app, ["scan", str(violations_manifest_file)], env=CLI_ENV)
    assert result.exit_code == 1
    assert "LH-THREAT-001" in result.output
    assert "LH-THREAT-003" in result.output
    assert "Threat Model Findings" in result.output


def test_cli_scan_json_output(clean_manifest_file: Path) -> None:
    """Verify scanning with --format json outputs valid JSON payload."""
    result = runner.invoke(
        app,
        ["scan", str(clean_manifest_file), "--format", "json"],
        env=CLI_ENV,
    )
    assert result.exit_code == 0
    parsed = json.loads(result.output)
    assert parsed["report_type"] == "threat_model_audit"
    assert parsed["summary"]["total_findings"] == 0


def test_cli_scan_sarif_output(violations_manifest_file: Path) -> None:
    """Verify scanning with --format sarif outputs valid OASIS SARIF."""
    result = runner.invoke(
        app,
        ["scan", str(violations_manifest_file), "--format", "sarif"],
        env=CLI_ENV,
    )
    assert result.exit_code == 1
    parsed = json.loads(result.output)
    assert parsed["version"] == "2.1.0"
    assert len(parsed["runs"][0]["results"]) > 0


def test_cli_scan_output_file(clean_manifest_file: Path, tmp_path: Path) -> None:
    """Verify that --output writes report to disk."""
    out_file = tmp_path / "out_report.json"
    result = runner.invoke(
        app,
        [
            "scan",
            str(clean_manifest_file),
            "--format",
            "json",
            "--output",
            str(out_file),
        ],
        env=CLI_ENV,
    )
    assert result.exit_code == 0
    assert out_file.exists()
    parsed = json.loads(out_file.read_text(encoding="utf-8"))
    assert parsed["report_type"] == "threat_model_audit"


def test_cli_scan_fail_on_threshold(tmp_path: Path) -> None:
    """Verify --fail-on allows passing when findings are below the threshold."""
    # Manifest with only LH-THREAT-010 (LOW)
    low_manifest = tmp_path / "low_only.yaml"
    low_manifest.write_text(
        """
components:
  - id: untagged_service
    type: process
""".strip(),
        encoding="utf-8",
    )
    # Default fail-on is HIGH -> should pass with exit code 0
    result = runner.invoke(app, ["scan", str(low_manifest)], env=CLI_ENV)
    assert result.exit_code == 0

    # Explicit fail-on LOW -> should fail with exit code 1
    result_fail = runner.invoke(
        app,
        ["scan", str(low_manifest), "--fail-on", "LOW"],
        env=CLI_ENV,
    )
    assert result_fail.exit_code == 1


def test_cli_scan_min_severity_filter(violations_manifest_file: Path) -> None:
    """Verify --min-severity filters out findings below the specified level."""
    result = runner.invoke(
        app,
        [
            "scan",
            str(violations_manifest_file),
            "--format",
            "json",
            "--min-severity",
            "CRITICAL",
        ],
        env=CLI_ENV,
    )
    assert result.exit_code == 1
    parsed = json.loads(result.output)
    for res in parsed["results"]:
        for f in res["findings"]:
            assert f["severity"] == "CRITICAL"


def test_cli_scan_directory(clean_manifest_file: Path, tmp_path: Path) -> None:
    """Verify scanning directory containing architecture manifests."""
    result = runner.invoke(app, ["scan", str(tmp_path)], env=CLI_ENV)
    assert result.exit_code == 0
    assert "Clean Architecture" in result.output


def test_cli_scan_nonexistent_target(tmp_path: Path) -> None:
    """Verify scanning nonexistent path returns exit code 2."""
    missing = tmp_path / "does_not_exist.yaml"
    result = runner.invoke(app, ["scan", str(missing)], env=CLI_ENV)
    assert result.exit_code == 2
    assert "does not exist" in result.output
