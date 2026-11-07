# ==============================================================================
# Product:       lh-threat-model (lh-threat)
# Module:        src.lh_threat_model.models
# Role:          Data Models & Rule Definitions
# Organization:  Logihertz Systems (OPC) Private Limited (logihertzsystems)
# Creator:       Sameer Tawade (Creator, Founder, Director & Whole and Sole Developer)
# Contact:       ops@logihertz.com | https://logihertz.com/
# License:       Apache License 2.0 (SPDX-License-Identifier: Apache-2.0)
# ==============================================================================

"""Data models and findings representations for lh-threat-model.

Provides structured types for architecture components, data flows, trust zones,
STRIDE categories, security findings, detection rule definitions, and audit reports.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any


class FindingSeverity(StrEnum):
    # --- Severity Rank & Weighting Structure ---
    # Defines discrete security tiers for findings and threshold gating.
    # Higher ordinal rankings enforce stricter build break / fail-on gates.
    """Severity classification for threat model findings."""

    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"

    @property
    def level(self) -> int:
        """Numeric rank for threshold comparisons."""
        order = {
            FindingSeverity.LOW: 1,
            FindingSeverity.MEDIUM: 2,
            FindingSeverity.HIGH: 3,
            FindingSeverity.CRITICAL: 4,
        }
        return order[self]

    def meets_threshold(self, threshold: FindingSeverity) -> bool:
        """Return True if this severity meets or exceeds threshold."""
        return self.level >= threshold.level


class StrideCategory(StrEnum):
    """Microsoft STRIDE threat classification categories."""

    SPOOFING = "Spoofing"
    TAMPERING = "Tampering"
    REPUDIATION = "Repudiation"
    INFORMATION_DISCLOSURE = "Information Disclosure"
    DENIAL_OF_SERVICE = "Denial of Service"
    ELEVATION_OF_PRIVILEGE = "Elevation of Privilege"
    COMPLIANCE = "Compliance"


class ComponentType(StrEnum):
    """Classification of architecture model components and actors."""

    PROCESS = "process"
    DATASTORE = "datastore"
    EXTERNAL_ENTITY = "external_entity"
    INGRESS = "ingress"
    THIRD_PARTY = "third_party"
    UNKNOWN = "unknown"

    @classmethod
    def from_str(cls, val: str | None) -> ComponentType:
        """Infer ComponentType from manifest string."""
        if not val:
            return cls.UNKNOWN
        clean = val.strip().lower()
        if clean in ("datastore", "database", "db", "storage", "bucket", "cache", "table", "rds"):
            return cls.DATASTORE
        if clean in ("external_entity", "actor", "user", "client", "customer"):
            return cls.EXTERNAL_ENTITY
        if clean in ("ingress", "gateway", "api_gateway", "load_balancer", "proxy", "alb"):
            return cls.INGRESS
        if clean in ("third_party", "saas", "external_service", "external_api"):
            return cls.THIRD_PARTY
        if clean in ("process", "service", "microservice", "compute", "container", "worker", "job"):
            return cls.PROCESS
        return cls.UNKNOWN


@dataclass
class TrustZone:
    """Defined trust boundary or zone within architecture."""

    id: str
    name: str = ""
    description: str = ""


@dataclass
class Component:
    """System component, process, datastore, or boundary entity."""

    id: str
    name: str = ""
    type: ComponentType = ComponentType.PROCESS
    trust_zone: str = ""
    data_classification: str = ""
    encryption_at_rest: bool | None = None
    audit_logging: bool | None = None
    immutable_audit_trail: bool | None = None
    rate_limit: bool | None = None
    waf_enabled: bool | None = None
    ddos_protection: bool | None = None
    privileged: bool | None = None
    run_as_root: bool | None = None
    admin_permissions: bool | None = None
    critical: bool | None = None
    state_changing: bool | None = None
    egress_filtering: bool | None = None
    secret_rotation: bool | None = None
    isolated_network_zone: bool | None = None
    raw_data: dict[str, Any] = field(default_factory=dict)
    line_number: int | None = None


@dataclass
class DataFlow:
    """Data communication channel between components crossing boundaries."""

    id: str
    source: str
    target: str
    name: str = ""
    protocol: str = ""
    encrypted: bool | None = None
    auth: str | None = None
    auth_mechanism: str | None = None
    authenticated: bool | None = None
    integrity: str | None = None
    egress_filtering: bool | None = None
    secret_rotation: bool | None = None
    isolated_network_zone: bool | None = None
    data_classification: str | None = None
    raw_data: dict[str, Any] = field(default_factory=dict)
    line_number: int | None = None


@dataclass
class DFDModel:
    """Parsed Data Flow Diagram and architecture manifest."""

    name: str = ""
    version: str = "1.0"
    description: str = ""
    trust_zones: dict[str, TrustZone] = field(default_factory=dict)
    components: dict[str, Component] = field(default_factory=dict)
    flows: list[DataFlow] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class RuleDefinition:
    """Formal definition and guidance for a threat model detection rule."""

    rule_id: str
    title: str
    severity: FindingSeverity
    stride_category: StrideCategory
    description: str
    remediation: str


@dataclass
class Finding:
    """Specific architectural risk or boundary violation finding."""

    rule_id: str
    severity: FindingSeverity
    stride_category: StrideCategory
    title: str
    message: str
    target: str
    element_id: str
    element_type: str
    remediation: str
    source: str | None = None
    destination: str | None = None
    line_number: int | None = None
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Convert finding to dictionary representation."""
        return {
            "rule_id": self.rule_id,
            "severity": self.severity.value,
            "stride_category": self.stride_category.value,
            "title": self.title,
            "message": self.message,
            "target": self.target,
            "element_id": self.element_id,
            "element_type": self.element_type,
            "source": self.source,
            "destination": self.destination,
            "remediation": self.remediation,
            "line_number": self.line_number,
            "metadata": self.metadata,
        }


@dataclass
class ScanTargetResult:
    """Threat model audit results for a single manifest or file."""

    target: str
    findings: list[Finding] = field(default_factory=list)
    components_count: int = 0
    flows_count: int = 0
    trust_zones_count: int = 0
    error_message: str | None = None

    def to_dict(self) -> dict[str, Any]:
        """Convert result to dictionary representation."""
        return {
            "target": self.target,
            "components_count": self.components_count,
            "flows_count": self.flows_count,
            "trust_zones_count": self.trust_zones_count,
            "error_message": self.error_message,
            "findings": [f.to_dict() for f in self.findings],
        }


@dataclass
class AuditReport:
    """Consolidated audit report across scanned architecture targets."""

    report_type: str = "threat_model_audit"
    generated_at: datetime = field(default_factory=lambda: datetime.now(UTC))
    parameters: dict[str, Any] = field(default_factory=dict)
    results: list[ScanTargetResult] = field(default_factory=list)
    summary: dict[str, int] = field(default_factory=dict)
    stride_breakdown: dict[str, int] = field(default_factory=dict)

    def compute_summary(self) -> None:
        """Compute aggregated findings counts by severity and STRIDE category."""
        counts = {
            "total_targets": len(self.results),
            "total_findings": 0,
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
            "components_scanned": sum(r.components_count for r in self.results),
            "flows_scanned": sum(r.flows_count for r in self.results),
        }
        stride_counts = {cat.value: 0 for cat in StrideCategory}

        for res in self.results:
            for f in res.findings:
                counts["total_findings"] += 1
                if f.severity == FindingSeverity.CRITICAL:
                    counts["critical"] += 1
                elif f.severity == FindingSeverity.HIGH:
                    counts["high"] += 1
                elif f.severity == FindingSeverity.MEDIUM:
                    counts["medium"] += 1
                elif f.severity == FindingSeverity.LOW:
                    counts["low"] += 1

                stride_counts[f.stride_category.value] = (
                    stride_counts.get(f.stride_category.value, 0) + 1
                )

        self.summary = counts
        self.stride_breakdown = stride_counts

    def has_failures(self, threshold: FindingSeverity | None) -> bool:
        """Check if any finding meets or exceeds the failure threshold."""
        if threshold is None:
            return False
        for res in self.results:
            for f in res.findings:
                if f.severity.meets_threshold(threshold):
                    return True
        return False

    def filter_min_severity(self, min_sev: FindingSeverity) -> None:
        """Filter out findings below the specified minimum severity."""
        for res in self.results:
            res.findings = [f for f in res.findings if f.severity.meets_threshold(min_sev)]
        self.compute_summary()

    def to_dict(self) -> dict[str, Any]:
        """Convert complete audit report to dictionary."""
        self.compute_summary()
        return {
            "report_type": self.report_type,
            "generated_at": self.generated_at.isoformat(),
            "parameters": self.parameters,
            "summary": self.summary,
            "stride_breakdown": self.stride_breakdown,
            "results": [r.to_dict() for r in self.results],
        }


RULES_REGISTRY: dict[str, RuleDefinition] = {
    "LH-THREAT-001": RuleDefinition(
        rule_id="LH-THREAT-001",
        title="Unencrypted Data Flow Crossing Trust Boundary",
        severity=FindingSeverity.CRITICAL,
        stride_category=StrideCategory.INFORMATION_DISCLOSURE,
        description=(
            "Data flow crossing trust boundaries transmits data in plaintext without TLS or "
            "valid encryption, exposing communications to passive eavesdropping and interception."
        ),
        remediation=(
            "Enforce TLS 1.3 or modern encryption (HTTPS, WSS, mTLS) for all cross-boundary flows."
        ),
    ),
    "LH-THREAT-002": RuleDefinition(
        rule_id="LH-THREAT-002",
        title="External or Cross-Boundary Flow Lacking Authentication",
        severity=FindingSeverity.CRITICAL,
        stride_category=StrideCategory.SPOOFING,
        description=(
            "Data flow entering from an external zone or across trust boundaries targets an "
            "internal service or API without verifying sender identity, enabling spoofing attacks."
        ),
        remediation=(
            "Require robust authentication mechanisms (OAuth 2.0, mTLS, JWT, or API keys)."
        ),
    ),
    "LH-THREAT-003": RuleDefinition(
        rule_id="LH-THREAT-003",
        title="Direct External Ingress to Internal Datastore",
        severity=FindingSeverity.CRITICAL,
        stride_category=StrideCategory.ELEVATION_OF_PRIVILEGE,
        description=(
            "Public external actor or internet-facing ingress connects directly to an internal "
            "datastore or database without an intermediary application or business logic tier."
        ),
        remediation=(
            "Isolate internal datastores behind dedicated backend API/application service tiers."
        ),
    ),
    "LH-THREAT-004": RuleDefinition(
        rule_id="LH-THREAT-004",
        title="Cross-Boundary or Queue/Webhook Flow Lacking Integrity Verification",
        severity=FindingSeverity.HIGH,
        stride_category=StrideCategory.TAMPERING,
        description=(
            "Cross-boundary data flow, queue consumer, or webhook receiver lacks cryptographic "
            "message integrity verification, exposing data to in-transit tampering or injection."
        ),
        remediation=(
            "Implement mTLS, HMAC payload signatures, or asymmetric signing on all cross-boundary "
            "and webhook flows."
        ),
    ),
    "LH-THREAT-005": RuleDefinition(
        rule_id="LH-THREAT-005",
        title="Sensitive or PII Datastore Unencrypted at Rest",
        severity=FindingSeverity.HIGH,
        stride_category=StrideCategory.INFORMATION_DISCLOSURE,
        description=(
            "Datastore containing sensitive, confidential, PII, or PCI data does not enable "
            "encryption at rest, leaving persisted data exposed to storage compromise."
        ),
        remediation=(
            "Enable encryption at rest with customer-managed or cloud KMS keys (AES-256 / XTS)."
        ),
    ),
    "LH-THREAT-006": RuleDefinition(
        rule_id="LH-THREAT-006",
        title="Critical State-Changing or Auth Component Missing Audit Logging",
        severity=FindingSeverity.MEDIUM,
        stride_category=StrideCategory.REPUDIATION,
        description=(
            "Critical state-changing component, authentication service, or admin portal lacks "
            "enabled audit logging or immutable audit trail configuration."
        ),
        remediation=(
            "Enable comprehensive audit logging with tamper-resistant immutable log destinations."
        ),
    ),
    "LH-THREAT-007": RuleDefinition(
        rule_id="LH-THREAT-007",
        title="Internet-Facing Ingress Missing Rate Limiting or WAF/DDoS Protection",
        severity=FindingSeverity.HIGH,
        stride_category=StrideCategory.DENIAL_OF_SERVICE,
        description=(
            "Public internet-facing ingress or gateway component lacks rate limiting, Web "
            "Application Firewall (WAF), or DDoS mitigation controls."
        ),
        remediation=(
            "Configure ingress rate limiting, request throttling, and managed WAF / DDoS controls."
        ),
    ),
    "LH-THREAT-008": RuleDefinition(
        rule_id="LH-THREAT-008",
        title="Compute Service Running with Over-Privileged Context",
        severity=FindingSeverity.HIGH,
        stride_category=StrideCategory.ELEVATION_OF_PRIVILEGE,
        description=(
            "Compute service or microservice executes with privileged containers, root user "
            "privileges, or full administrative capabilities."
        ),
        remediation=(
            "Run services under non-root unprivileged service accounts with dropped capabilities."
        ),
    ),
    "LH-THREAT-009": RuleDefinition(
        rule_id="LH-THREAT-009",
        title="Third-Party or SaaS Integration Lacking Boundary Controls",
        severity=FindingSeverity.MEDIUM,
        stride_category=StrideCategory.INFORMATION_DISCLOSURE,
        description=(
            "Third-party external SaaS service integration lacks egress traffic filtering, "
            "automated credential rotation, or isolated network zone containment."
        ),
        remediation=(
            "Enforce strict egress proxy filtering, automated secret rotation, and network DMZ."
        ),
    ),
    "LH-THREAT-010": RuleDefinition(
        rule_id="LH-THREAT-010",
        title="Component Missing Explicit Trust Zone or Data Classification Tag",
        severity=FindingSeverity.LOW,
        stride_category=StrideCategory.COMPLIANCE,
        description=(
            "Architecture component lacks explicit trust zone assignment or datastore lacks data "
            "classification tagging in the architecture specification manifest."
        ),
        remediation=(
            "Assign explicit trust_zone and data_classification attributes to all components."
        ),
    ),
}
