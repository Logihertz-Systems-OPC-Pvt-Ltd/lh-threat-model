# ==============================================================================
# Product:       lh-threat-model (lh-threat)
# Module:        tests.test_exporters
# Role:          Test Suite & Rule Verification
# Organization:  Logihertz Systems (OPC) Private Limited (logihertzsystems)
# Creator:       Sameer Tawade (Creator, Founder, Director & Whole and Sole Developer)
# Contact:       ops@logihertz.com | https://logihertz.com/
# License:       Apache License 2.0 (SPDX-License-Identifier: Apache-2.0)
# ==============================================================================

"""Unit tests for report exporters (Table, JSON, SARIF v2.1.0)."""

from __future__ import annotations

import json
from datetime import UTC, datetime

from rich.console import Console

from lh_threat_model.exporters import (
    OutputFormat,
    _get_severity_badge,
    export_json,
    export_sarif,
    render_table_report,
)
from lh_threat_model.models import (
    AuditReport,
    Finding,
    FindingSeverity,
    ScanTargetResult,
    StrideCategory,
)


def _sample_report_with_findings() -> AuditReport:
    """Build a mock AuditReport with findings across severity levels."""
    finding1 = Finding(
        rule_id="LH-THREAT-001",
        severity=FindingSeverity.CRITICAL,
        stride_category=StrideCategory.INFORMATION_DISCLOSURE,
        title="Unencrypted Data Flow Crossing Trust Boundary",
        message="Data flow 'f1' is unencrypted.",
        target="arch.yaml",
        element_id="f1",
        element_type="data_flow",
        source="actor1",
        destination="srv1",
        remediation="Enable TLS 1.3.",
        line_number=12,
    )
    finding2 = Finding(
        rule_id="LH-THREAT-007",
        severity=FindingSeverity.HIGH,
        stride_category=StrideCategory.DENIAL_OF_SERVICE,
        title="Internet-Facing Ingress Missing Rate Limiting",
        message="Ingress gateway 'gw' is missing rate limiting.",
        target="arch.yaml",
        element_id="gw",
        element_type="ingress",
        remediation="Configure rate limits.",
        line_number=24,
    )
    res = ScanTargetResult(
        target="arch.yaml",
        findings=[finding1, finding2],
        components_count=4,
        flows_count=2,
        trust_zones_count=2,
    )
    return AuditReport(
        report_type="threat_model_audit",
        generated_at=datetime.now(UTC),
        parameters={"path": "arch.yaml", "format": "table"},
        results=[res],
    )


def test_render_table_report_with_findings() -> None:
    """Verify terminal table rendering with findings."""
    report = _sample_report_with_findings()
    console = Console(record=True, width=120, color_system=None)
    render_table_report(report, console=console)
    text = console.export_text()

    assert "STRIDE Threat Model & Trust Boundary Audit" in text
    assert "Threat Model Executive Summary" in text
    assert "STRIDE Category Threat Breakdown" in text
    assert "LH-THREAT-001" in text
    assert "LH-THREAT-007" in text
    assert "CRITICAL" in text
    assert "HIGH" in text


def test_render_table_clean_report() -> None:
    """Verify terminal table rendering for clean compliant architecture."""
    report = AuditReport(
        report_type="threat_model_audit",
        generated_at=datetime.now(UTC),
        parameters={"path": "clean.yaml", "format": "table"},
        results=[
            ScanTargetResult(
                target="clean.yaml",
                findings=[],
                components_count=3,
                flows_count=1,
            )
        ],
    )
    console = Console(record=True, width=120, color_system=None)
    render_table_report(report, console=console)
    text = console.export_text()

    assert "Clean Architecture: Manifest complies with STRIDE threat baselines." in text


def test_export_json_valid() -> None:
    """Verify structured JSON exporter output and schema integrity."""
    report = _sample_report_with_findings()
    raw_json = export_json(report)
    parsed = json.loads(raw_json)

    assert parsed["report_type"] == "threat_model_audit"
    assert parsed["summary"]["total_findings"] == 2
    assert parsed["summary"]["critical"] == 1
    assert parsed["summary"]["high"] == 1
    assert "results" in parsed
    assert len(parsed["results"]) == 1
    assert parsed["results"][0]["findings"][0]["rule_id"] == "LH-THREAT-001"


def test_export_sarif_valid_v210() -> None:
    """Verify OASIS SARIF v2.1.0 schema compliance and findings mapping."""
    report = _sample_report_with_findings()
    raw_sarif = export_sarif(report)
    parsed = json.loads(raw_sarif)

    assert parsed["version"] == "2.1.0"
    assert "sarif-schema-2.1.0.json" in parsed["$schema"]
    assert len(parsed["runs"]) == 1

    driver = parsed["runs"][0]["tool"]["driver"]
    assert driver["name"] == "lh-threat-model"
    assert driver["version"] == "0.1.0"
    assert len(driver["rules"]) == 10

    sarif_results = parsed["runs"][0]["results"]
    assert len(sarif_results) == 2
    assert sarif_results[0]["ruleId"] == "LH-THREAT-001"
    assert sarif_results[0]["level"] == "error"
    assert (
        sarif_results[0]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
        == "arch.yaml"
    )


def test_severity_badges_and_output_formats() -> None:
    """Verify severity badges text representation and output format enum values."""
    assert _get_severity_badge(FindingSeverity.CRITICAL).plain == "CRITICAL"
    assert _get_severity_badge(FindingSeverity.HIGH).plain == "HIGH"
    assert _get_severity_badge(FindingSeverity.MEDIUM).plain == "MEDIUM"
    assert _get_severity_badge(FindingSeverity.LOW).plain == "LOW"

    assert OutputFormat.TABLE == "table"
    assert OutputFormat.JSON == "json"
    assert OutputFormat.SARIF == "sarif"
