# Security Rules Reference: lh-threat-model

An enterprise architectural threat modeling & stride analyzer developed by **Logihertz Systems (OPC) Private Limited**.

This reference manual documents the complete 10-rule security detection registry enforced by `lh-threat-model`.

---

## Detection Catalog Overview

| Rule ID | Severity | Category | Title |
|:---|:---:|:---|:---|
| `LH-THREAT-001` | `CRITICAL` | Information Disclosure | Unencrypted Data Flow Crossing Trust Boundary |
| `LH-THREAT-002` | `CRITICAL` | Spoofing | External Cross-Boundary Flow Without Authentication |
| `LH-THREAT-003` | `CRITICAL` | Elevation of Privilege | Direct Public Ingress to Internal Datastore |
| `LH-THREAT-004` | `HIGH` | Tampering | Cross-Boundary Flow Lacking Message Integrity Verification |
| `LH-THREAT-005` | `HIGH` | Information Disclosure | Datastore with Sensitive/PII Classification Unencrypted at Rest |
| `LH-THREAT-006` | `MEDIUM` | Repudiation | State-Changing Component Lacking Immutable Audit Logging |
| `LH-THREAT-007` | `HIGH` | Denial of Service | Internet-Facing Component Missing Rate Limiting or WAF |
| `LH-THREAT-008` | `HIGH` | Elevation of Privilege | Compute Service Running in Over-Privileged Context |
| `LH-THREAT-009` | `MEDIUM` | Information Disclosure | External SaaS Integration Flow Lacking Egress Filtering |
| `LH-THREAT-010` | `LOW` | Governance | Component or Datastore Missing Explicit Trust Zone Assignment |

---

## Granular Rule Specifications

### `LH-THREAT-001`: Unencrypted Data Flow Crossing Trust Boundary

- **Severity**: `CRITICAL`
- **Category**: `Information Disclosure`
- **Description**: Data flow crosses trust boundary using unencrypted protocol (http, tcp, ftp, ws).
- **Remediation**: Enforce TLS encryption (https, tls, wss) across all cross-boundary network flows.

---

### `LH-THREAT-002`: External Cross-Boundary Flow Without Authentication

- **Severity**: `CRITICAL`
- **Category**: `Spoofing`
- **Description**: External actor or cross-boundary data flow targets service without authentication mechanism.
- **Remediation**: Enforce mutual authentication (OAuth2, mTLS, API key with signature) on endpoint.

---

### `LH-THREAT-003`: Direct Public Ingress to Internal Datastore

- **Severity**: `CRITICAL`
- **Category**: `Elevation of Privilege`
- **Description**: Public/external actor communicates directly with datastore bypassing application/API tier.
- **Remediation**: Isolate datastores behind private subnets and require mediation through API gateway layer.

---

### `LH-THREAT-004`: Cross-Boundary Flow Lacking Message Integrity Verification

- **Severity**: `HIGH`
- **Category**: `Tampering`
- **Description**: Cross-boundary flow or webhook consumer lacks HMAC signature or payload verification.
- **Remediation**: Implement cryptographic message signing (HMAC-SHA256) or mTLS message integrity verification.

---

### `LH-THREAT-005`: Datastore with Sensitive/PII Classification Unencrypted at Rest

- **Severity**: `HIGH`
- **Category**: `Information Disclosure`
- **Description**: Datastore with restricted or PII classification configured with encryption_at_rest: false.
- **Remediation**: Enable transparent database encryption or storage volume KMS encryption at rest.

---

### `LH-THREAT-006`: State-Changing Component Lacking Immutable Audit Logging

- **Severity**: `MEDIUM`
- **Category**: `Repudiation`
- **Description**: Critical authentication or state-modifying service configured with audit_logging: false.
- **Remediation**: Implement tamper-evident audit logging recording all administrative and state-changing events.

---

### `LH-THREAT-007`: Internet-Facing Component Missing Rate Limiting or WAF

- **Severity**: `HIGH`
- **Category**: `Denial of Service`
- **Description**: Public ingress component configured without rate limiting or edge WAF defenses.
- **Remediation**: Deploy edge rate limiting, DDoS mitigation, and Web Application Firewall rules.

---

### `LH-THREAT-008`: Compute Service Running in Over-Privileged Context

- **Severity**: `HIGH`
- **Category**: `Elevation of Privilege`
- **Description**: Workload configured with privileged: true, run_as_root: true, or admin permissions.
- **Remediation**: Drop root execution and apply least-privilege securityContext to compute workloads.

---

### `LH-THREAT-009`: External SaaS Integration Flow Lacking Egress Filtering

- **Severity**: `MEDIUM`
- **Category**: `Information Disclosure`
- **Description**: Third-party integration flow lacks egress filtering or isolated network routing zone.
- **Remediation**: Enforce egress network filtering and isolate third-party integrations to dedicated DMZ subnets.

---

### `LH-THREAT-010`: Component or Datastore Missing Explicit Trust Zone Assignment

- **Severity**: `LOW`
- **Category**: `Governance`
- **Description**: Architecture specification contains components without explicit trust_zone assignment.
- **Remediation**: Assign all components to explicit trust zones (e.g. public_internet, dmz, private_vpc, secure_enclave).

---
