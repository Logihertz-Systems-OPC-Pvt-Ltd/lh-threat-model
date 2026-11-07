# ==============================================================================
# Product:       lh-threat-model (lh-threat)
# Module:        tests.test_dfd_scanner
# Role:          Test Suite & Rule Verification
# Organization:  Logihertz Systems (OPC) Private Limited (logihertzsystems)
# Creator:       Sameer Tawade (Creator, Founder, Director & Whole and Sole Developer)
# Contact:       ops@logihertz.com | https://logihertz.com/
# License:       Apache License 2.0 (SPDX-License-Identifier: Apache-2.0)
# ==============================================================================

"""Unit tests for declarative architecture manifest and DFD scanner."""

from __future__ import annotations

import json
from pathlib import Path

from lh_threat_model.dfd_scanner import load_manifest, parse_manifest_dict, scan_dfd
from lh_threat_model.models import ComponentType


def test_load_clean_manifest(clean_manifest_file: Path) -> None:
    """Verify loading a compliant YAML architecture manifest."""
    model, error = load_manifest(clean_manifest_file)
    assert error is None
    assert model is not None
    assert model.name == "Hardened Enterprise E-Commerce Platform"
    assert len(model.trust_zones) == 5
    assert len(model.components) == 6
    assert len(model.flows) == 5
    assert model.components["customer_db"].type == ComponentType.DATASTORE


def test_load_json_manifest(tmp_path: Path) -> None:
    """Verify loading a JSON architecture manifest."""
    json_data = {
        "name": "JSON Architecture",
        "version": "2.0",
        "trust_zones": [{"id": "public"}, {"id": "private"}],
        "components": [
            {
                "id": "web_ui",
                "type": "process",
                "trust_zone": "public",
            },
            {
                "id": "sql_db",
                "type": "database",
                "trust_zone": "private",
                "data_classification": "restricted",
                "encryption_at_rest": True,
            },
        ],
        "data_flows": [
            {
                "id": "web_to_db",
                "source": "web_ui",
                "target": "sql_db",
                "protocol": "tls",
                "encrypted": True,
                "auth": "mtls",
                "integrity": "mtls",
            }
        ],
    }
    json_file = tmp_path / "architecture.json"
    json_file.write_text(json.dumps(json_data), encoding="utf-8")

    model, error = load_manifest(json_file)
    assert error is None
    assert model is not None
    assert model.name == "JSON Architecture"
    assert "web_ui" in model.components
    assert "sql_db" in model.components
    assert len(model.flows) == 1


def test_parse_manifest_dict_alternate_keys() -> None:
    """Verify parsing manifest using alternative schema aliases (nodes, edges, boundaries)."""
    data = {
        "boundaries": {"cloud": {"name": "Cloud VPC"}},
        "nodes": {
            "node_1": {"type": "microservice", "zone": "cloud"},
            "db_1": {"type": "storage", "zone": "cloud", "classification": "pii"},
        },
        "edges": [
            {
                "from": "node_1",
                "to": "db_1",
                "scheme": "tls",
                "tls": True,
                "auth_mechanism": "mtls",
                "message_integrity": "hmac",
            }
        ],
    }
    model = parse_manifest_dict(data)
    assert "cloud" in model.trust_zones
    assert "node_1" in model.components
    assert "db_1" in model.components
    assert model.components["db_1"].type == ComponentType.DATASTORE
    assert len(model.flows) == 1
    assert model.flows[0].source == "node_1"
    assert model.flows[0].target == "db_1"


def test_load_manifest_nonexistent(tmp_path: Path) -> None:
    """Verify handling when target manifest path does not exist."""
    missing = tmp_path / "missing.yaml"
    model, error = load_manifest(missing)
    assert model is None
    assert error is not None
    assert "does not exist" in error


def test_load_manifest_malformed_yaml(tmp_path: Path) -> None:
    """Verify handling of syntactically invalid YAML file."""
    bad_file = tmp_path / "corrupt.yaml"
    bad_file.write_text("key: [unclosed list", encoding="utf-8")
    model, error = load_manifest(bad_file)
    assert model is None
    assert error is not None
    assert "Failed to parse manifest" in error


def test_load_manifest_non_dict_root(tmp_path: Path) -> None:
    """Verify handling when YAML root is a list or scalar instead of a dict."""
    list_file = tmp_path / "list_root.yaml"
    list_file.write_text("- item1\n- item2", encoding="utf-8")
    model, error = load_manifest(list_file)
    assert model is None
    assert error is not None
    assert "root must be a mapping" in error


def test_scan_dfd_clean_result(clean_manifest_file: Path) -> None:
    """Verify scan_dfd returns 0 findings on a hardened architecture model."""
    result = scan_dfd(clean_manifest_file)
    assert result.error_message is None
    assert result.components_count == 6
    assert result.flows_count == 5
    assert len(result.findings) == 0


def test_scan_dfd_error_result(tmp_path: Path) -> None:
    """Verify scan_dfd records error_message when parsing fails."""
    broken = tmp_path / "broken.json"
    broken.write_text("{not valid json", encoding="utf-8")
    result = scan_dfd(broken)
    assert result.error_message is not None
    assert len(result.findings) == 0
