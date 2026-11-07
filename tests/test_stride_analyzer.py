# ==============================================================================
# Product:       lh-threat-model (lh-threat)
# Module:        tests.test_stride_analyzer
# Role:          Test Suite & Rule Verification
# Organization:  Logihertz Systems (OPC) Private Limited (logihertzsystems)
# Creator:       Sameer Tawade (Creator, Founder, Director & Whole and Sole Developer)
# Contact:       ops@logihertz.com | https://logihertz.com/
# License:       Apache License 2.0 (SPDX-License-Identifier: Apache-2.0)
# ==============================================================================

"""Unit tests for STRIDE threat model analyzer and rules LH-THREAT-001 to 010."""

from __future__ import annotations

from pathlib import Path

from lh_threat_model.dfd_scanner import load_manifest, parse_manifest_dict
from lh_threat_model.models import FindingSeverity, StrideCategory
from lh_threat_model.stride_analyzer import analyze_stride


def test_clean_architecture_zero_findings(clean_manifest_file: Path) -> None:
    """Verify that a compliant hardened architecture yields 0 findings."""
    model, error = load_manifest(clean_manifest_file)
    assert error is None
    assert model is not None
    findings = analyze_stride(model, str(clean_manifest_file))
    assert len(findings) == 0
    # --------------------------------------------------------------------------
    # --- Rule LH-THREAT-001 (CRITICAL):
    #     Unencrypted Data Flow Crossing Trust Boundary
    # ---
    # Evaluates security posture against unencrypted data flow crossing trust
    # boundary.
    # Rationale: Prevents policy violations and reduces vulnerable surface exposure.
    # False Positive Defense: Contextual inspection ensures intentional configs are
    # respected.
    # --------------------------------------------------------------------------


def test_threat_001_unencrypted_cross_boundary() -> None:
    """Verify LH-THREAT-001 flags unencrypted flow crossing trust boundaries."""
    data = {
        "trust_zones": [{"id": "public"}, {"id": "internal"}],
        "components": [
            {"id": "c1", "type": "actor", "trust_zone": "public"},
            {
                "id": "s1",
                "type": "process",
                "trust_zone": "internal",
                "audit_logging": True,
                "immutable_audit_trail": True,
            },
        ],
        "data_flows": [
            {
                "id": "f_bad",
                "source": "c1",
                "target": "s1",
                "protocol": "http",
                "encrypted": False,
                "auth": "oauth2",
                "integrity": "hmac",
            }
        ],
    }
    model = parse_manifest_dict(data)
    findings = analyze_stride(model, "test.yaml")
    rule_ids = [f.rule_id for f in findings]
    assert "LH-THREAT-001" in rule_ids
    f001 = next(f for f in findings if f.rule_id == "LH-THREAT-001")
    assert f001.severity == FindingSeverity.CRITICAL
    assert f001.stride_category == StrideCategory.INFORMATION_DISCLOSURE
    # --------------------------------------------------------------------------
    # --- Rule LH-THREAT-002 (CRITICAL):
    #     External Cross-Boundary Flow Without Authentication
    # ---
    # Evaluates security posture against external cross-boundary flow without
    # authentication.
    # Rationale: Prevents policy violations and reduces vulnerable surface exposure.
    # False Positive Defense: Contextual inspection ensures intentional configs are
    # respected.
    # --------------------------------------------------------------------------


def test_threat_002_unauthenticated_flow() -> None:
    """Verify LH-THREAT-002 flags cross-boundary flow lacking authentication."""
    data = {
        "trust_zones": [{"id": "external"}, {"id": "internal"}],
        "components": [
            {"id": "user", "type": "external_entity", "trust_zone": "external"},
            {
                "id": "api",
                "type": "process",
                "trust_zone": "internal",
                "audit_logging": True,
                "immutable_audit_trail": True,
            },
        ],
        "data_flows": [
            {
                "id": "f_unauth",
                "source": "user",
                "target": "api",
                "protocol": "https",
                "encrypted": True,
                "auth": "none",
                "integrity": "hmac",
            }
        ],
    }
    model = parse_manifest_dict(data)
    findings = analyze_stride(model, "test.yaml")
    rule_ids = [f.rule_id for f in findings]
    assert "LH-THREAT-002" in rule_ids
    f002 = next(f for f in findings if f.rule_id == "LH-THREAT-002")
    assert f002.severity == FindingSeverity.CRITICAL
    assert f002.stride_category == StrideCategory.SPOOFING
    # --------------------------------------------------------------------------
    # --- Rule LH-THREAT-003: Direct Public Ingress to Internal Datastore (CRITICAL) ---
    # Evaluates security posture against direct public ingress to internal
    # datastore.
    # Rationale: Prevents policy violations and reduces vulnerable surface exposure.
    # False Positive Defense: Contextual inspection ensures intentional configs are
    # respected.
    # --------------------------------------------------------------------------


def test_threat_003_direct_datastore_access() -> None:
    """Verify LH-THREAT-003 flags direct external actor to internal datastore flow."""
    data = {
        "trust_zones": [{"id": "internet"}, {"id": "internal"}],
        "components": [
            {"id": "attacker", "type": "external_entity", "trust_zone": "internet"},
            {
                "id": "core_db",
                "type": "datastore",
                "trust_zone": "internal",
                "data_classification": "restricted",
                "encryption_at_rest": True,
            },
        ],
        "data_flows": [
            {
                "id": "f_direct",
                "source": "attacker",
                "target": "core_db",
                "protocol": "tls",
                "encrypted": True,
                "auth": "mtls",
                "integrity": "mtls",
            }
        ],
    }
    model = parse_manifest_dict(data)
    findings = analyze_stride(model, "test.yaml")
    rule_ids = [f.rule_id for f in findings]
    assert "LH-THREAT-003" in rule_ids
    f003 = next(f for f in findings if f.rule_id == "LH-THREAT-003")
    assert f003.severity == FindingSeverity.CRITICAL
    assert f003.stride_category == StrideCategory.ELEVATION_OF_PRIVILEGE
    # --------------------------------------------------------------------------
    # --- Rule LH-THREAT-004 (HIGH):
    #     Cross-Boundary Flow Lacking Message Integrity Verification
    # ---
    # Evaluates security posture against cross-boundary flow lacking message
    # integrity verification.
    # Rationale: Prevents policy violations and reduces vulnerable surface exposure.
    # False Positive Defense: Contextual inspection ensures intentional configs are
    # respected.
    # --------------------------------------------------------------------------


def test_threat_004_missing_message_integrity() -> None:
    """Verify LH-THREAT-004 flags cross-boundary or webhook flow without integrity."""
    data = {
        "trust_zones": [{"id": "dmz"}, {"id": "internal"}],
        "components": [
            {"id": "gw", "type": "ingress", "trust_zone": "dmz"},
            {"id": "worker", "type": "process", "trust_zone": "internal"},
        ],
        "data_flows": [
            {
                "id": "webhook_dispatch",
                "source": "gw",
                "target": "worker",
                "protocol": "https",
                "encrypted": True,
                "auth": "api_key",
                "integrity": "none",
            }
        ],
    }
    model = parse_manifest_dict(data)
    findings = analyze_stride(model, "test.yaml")
    rule_ids = [f.rule_id for f in findings]
    assert "LH-THREAT-004" in rule_ids
    f004 = next(f for f in findings if f.rule_id == "LH-THREAT-004")
    assert f004.severity == FindingSeverity.HIGH
    assert f004.stride_category == StrideCategory.TAMPERING
    # --------------------------------------------------------------------------
    # --- Rule LH-THREAT-005 (HIGH):
    #     Datastore with Sensitive/PII Classification Unencrypted at Rest
    # ---
    # Evaluates security posture against datastore with sensitive/pii classification
    # unencrypted at rest.
    # Rationale: Prevents policy violations and reduces vulnerable surface exposure.
    # False Positive Defense: Contextual inspection ensures intentional configs are
    # respected.
    # --------------------------------------------------------------------------


def test_threat_005_sensitive_datastore_unencrypted() -> None:
    """Verify LH-THREAT-005 flags sensitive datastore lacking encryption at rest."""
    data = {
        "components": [
            {
                "id": "pii_bucket",
                "type": "datastore",
                "trust_zone": "internal",
                "data_classification": "pii",
                "encryption_at_rest": False,
            }
        ]
    }
    model = parse_manifest_dict(data)
    findings = analyze_stride(model, "test.yaml")
    rule_ids = [f.rule_id for f in findings]
    assert "LH-THREAT-005" in rule_ids
    f005 = next(f for f in findings if f.rule_id == "LH-THREAT-005")
    assert f005.severity == FindingSeverity.HIGH
    assert f005.stride_category == StrideCategory.INFORMATION_DISCLOSURE
    # --------------------------------------------------------------------------
    # --- Rule LH-THREAT-006 (MEDIUM):
    #     State-Changing Component Lacking Immutable Audit Logging
    # ---
    # Evaluates security posture against state-changing component lacking immutable
    # audit logging.
    # Rationale: Prevents policy violations and reduces vulnerable surface exposure.
    # False Positive Defense: Contextual inspection ensures intentional configs are
    # respected.
    # --------------------------------------------------------------------------


def test_threat_006_audit_logging_missing() -> None:
    """Verify LH-THREAT-006 flags critical or auth component without audit trails."""
    data = {
        "components": [
            {
                "id": "auth_portal",
                "name": "Admin Authentication Portal",
                "type": "process",
                "trust_zone": "internal",
                "critical": True,
                "audit_logging": False,
            }
        ]
    }
    model = parse_manifest_dict(data)
    findings = analyze_stride(model, "test.yaml")
    rule_ids = [f.rule_id for f in findings]
    assert "LH-THREAT-006" in rule_ids
    f006 = next(f for f in findings if f.rule_id == "LH-THREAT-006")
    assert f006.severity == FindingSeverity.MEDIUM
    assert f006.stride_category == StrideCategory.REPUDIATION
    # --------------------------------------------------------------------------
    # --- Rule LH-THREAT-007 (HIGH):
    #     Internet-Facing Component Missing Rate Limiting or WAF
    # ---
    # Evaluates security posture against internet-facing component missing rate
    # limiting or waf.
    # Rationale: Prevents policy violations and reduces vulnerable surface exposure.
    # False Positive Defense: Contextual inspection ensures intentional configs are
    # respected.
    # --------------------------------------------------------------------------


def test_threat_007_ingress_missing_rate_limit_and_waf() -> None:
    """Verify LH-THREAT-007 flags public ingress missing rate limiting or WAF."""
    data = {
        "components": [
            {
                "id": "public_gateway",
                "type": "ingress",
                "trust_zone": "internet",
                "rate_limit": False,
                "waf_enabled": False,
            }
        ]
    }
    model = parse_manifest_dict(data)
    findings = analyze_stride(model, "test.yaml")
    rule_ids = [f.rule_id for f in findings]
    assert "LH-THREAT-007" in rule_ids
    f007 = next(f for f in findings if f.rule_id == "LH-THREAT-007")
    assert f007.severity == FindingSeverity.HIGH
    assert f007.stride_category == StrideCategory.DENIAL_OF_SERVICE
    # --------------------------------------------------------------------------
    # --- Rule LH-THREAT-008 (HIGH):
    #     Compute Service Running in Over-Privileged Context
    # ---
    # Evaluates security posture against compute service running in over-privileged
    # context.
    # Rationale: Prevents policy violations and reduces vulnerable surface exposure.
    # False Positive Defense: Contextual inspection ensures intentional configs are
    # respected.
    # --------------------------------------------------------------------------


def test_threat_008_privileged_compute() -> None:
    """Verify LH-THREAT-008 flags compute running as root or privileged."""
    data = {
        "components": [
            {
                "id": "batch_job",
                "type": "process",
                "trust_zone": "internal",
                "privileged": True,
                "run_as_root": True,
            }
        ]
    }
    model = parse_manifest_dict(data)
    findings = analyze_stride(model, "test.yaml")
    rule_ids = [f.rule_id for f in findings]
    assert "LH-THREAT-008" in rule_ids
    f008 = next(f for f in findings if f.rule_id == "LH-THREAT-008")
    assert f008.severity == FindingSeverity.HIGH
    assert f008.stride_category == StrideCategory.ELEVATION_OF_PRIVILEGE
    # --------------------------------------------------------------------------
    # --- Rule LH-THREAT-009 (MEDIUM):
    #     External SaaS Integration Flow Lacking Egress Filtering
    # ---
    # Evaluates security posture against external saas integration flow lacking
    # egress filtering.
    # Rationale: Prevents policy violations and reduces vulnerable surface exposure.
    # False Positive Defense: Contextual inspection ensures intentional configs are
    # respected.
    # --------------------------------------------------------------------------


def test_threat_009_third_party_saas_controls() -> None:
    """Verify LH-THREAT-009 flags SaaS integration missing boundary controls."""
    data = {
        "components": [
            {
                "id": "sendgrid_saas",
                "name": "SendGrid Email Dispatch",
                "type": "third_party",
                "trust_zone": "dmz",
                "egress_filtering": False,
                "secret_rotation": False,
            }
        ]
    }
    model = parse_manifest_dict(data)
    findings = analyze_stride(model, "test.yaml")
    rule_ids = [f.rule_id for f in findings]
    assert "LH-THREAT-009" in rule_ids
    f009 = next(f for f in findings if f.rule_id == "LH-THREAT-009")
    assert f009.severity == FindingSeverity.MEDIUM
    # --------------------------------------------------------------------------
    # --- Rule LH-THREAT-010 (LOW):
    #     Component or Datastore Missing Explicit Trust Zone Assignment
    # ---
    # Evaluates security posture against component or datastore missing explicit
    # trust zone assignment.
    # Rationale: Prevents policy violations and reduces vulnerable surface exposure.
    # False Positive Defense: Contextual inspection ensures intentional configs are
    # respected.
    # --------------------------------------------------------------------------


def test_threat_010_missing_trust_zone_or_classification() -> None:
    """Verify LH-THREAT-010 flags missing trust_zone and data_classification."""
    data = {
        "components": [
            {
                "id": "unassigned_service",
                "type": "process",
            },
            {
                "id": "unclassified_db",
                "type": "datastore",
                "trust_zone": "internal",
            },
        ]
    }
    model = parse_manifest_dict(data)
    findings = analyze_stride(model, "test.yaml")
    rule_ids = [f.rule_id for f in findings]
    assert rule_ids.count("LH-THREAT-010") == 2
    f010 = next(f for f in findings if f.rule_id == "LH-THREAT-010")
    assert f010.severity == FindingSeverity.LOW
    assert f010.stride_category == StrideCategory.COMPLIANCE
