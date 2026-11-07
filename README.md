# lh-threat-model

[![CI](https://github.com/Logihertz-Systems-OPC-Pvt-Ltd/lh-threat-model/actions/workflows/ci.yml/badge.svg)](https://github.com/Logihertz-Systems-OPC-Pvt-Ltd/lh-threat-model/actions/workflows/ci.yml)
[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)
[![Code style: ruff](https://img.shields.io/badge/code%20style-ruff-000000.svg)](https://github.com/astral-sh/ruff)
[![Security: bandit](https://img.shields.io/badge/security-bandit-yellow.svg)](https://github.com/PyCQA/bandit)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache--2.0-blue.svg)](LICENSE)

An enterprise declarative data-flow & stride threat engine developed by **Logihertz Systems (OPC) Private Limited**.

Parses declarative system architecture and Data-Flow Diagram (DFD) manifests (.yaml/.json) across trust boundaries to automatically enumerate STRIDE threats (Spoofing, Tampering, Repudiation, Info Disclosure, DoS, EoP).

---

## Key Features

- **Declarative DFD Parsing**: Models processes, datastores, actors, trust boundaries, and data flows from structured YAML/JSON manifests.
- **Automated STRIDE Threat Modeling**: Applies STRIDE methodology across trust boundary crossings to flag architectural vulnerabilities.
- **Boundary & Trust Zone Isolation**: Detects unauthenticated cross-boundary data flows, direct public ingress to databases, and unencrypted channels.
- **Data Classification & Sensitivity Mapping**: Evaluates restricted, confidential, and PII datastores for missing encryption at rest.
- **Multi-Format Reporting**: Outputs rich terminal tables, structured JSON, and OASIS SARIF v2.1.0.

---

## Core Detection Rules

| Rule ID | Severity | Description |
|:---|:---:|:---|
| `LH-THREAT-001` | `CRITICAL` | Unencrypted data flow crossing trust boundary (http, tcp, ws, or unencrypted flow) |
| `LH-THREAT-002` | `CRITICAL` | External or cross-boundary data flow targeting service without authentication |
| `LH-THREAT-003` | `CRITICAL` | Public/external actor communicating directly with internal datastore without API tier |
| `LH-THREAT-004` | `HIGH` | Cross-boundary data flow lacking message integrity verification (missing mTLS/HMAC) |
| `LH-THREAT-005` | `HIGH` | Datastore containing restricted/PII data configured with encryption_at_rest: false |
| `LH-THREAT-006` | `MEDIUM` | Critical state-changing component or auth service missing immutable audit logging |
| `LH-THREAT-007` | `HIGH` | Internet-facing public ingress component missing rate limiting or WAF defense |
| `LH-THREAT-008` | `HIGH` | Compute service running with over-privileged execution context (privileged: true) |
| `LH-THREAT-009` | `MEDIUM` | External SaaS integration flow lacking egress filtering or isolated network zone |
| `LH-THREAT-010` | `LOW` | Component or datastore missing explicit trust_zone or data_classification tag |

---

## Installation

### Using `uv` (Recommended)

```bash
# Clone the repository
git clone https://github.com/Logihertz-Systems-OPC-Pvt-Ltd/lh-threat-model.git
cd lh-threat-model

# Create virtual environment and install in editable mode with development tools
uv venv
source .venv/bin/activate
uv pip install -e ".[dev]"
```

### Using standard `pip`

```bash
pip install -e .
```

---

## CLI Usage

The primary executable entrypoint is `lh-threat` (also accessible via `lh-threat`, `lh-threat-model`).

```bash
# Scan an architectural threat model manifest
lh-threat scan architecture.yaml

# Export STRIDE threat model findings to JSON
lh-threat scan dfd.json --format json

# Export findings to OASIS SARIF v2.1.0
lh-threat scan ./models/ --format sarif --output threat-results.sarif

# List all STRIDE threat detection rules
lh-threat rules
```

---

## Exit Codes

| Exit Code | Meaning |
|:---:|:---|
| `0` | All audits and security checks passed; no policy violations detected. |
| `1` | One or more security findings, policy violations, or compliance failures detected. |
| `2` | Execution error (invalid arguments, missing input files, malformed syntax). |

---

## Documentation

Comprehensive enterprise documentation is available in the [`docs/`](docs/) directory and repository root:

- **[Architecture & Design](docs/ARCHITECTURE.md)**: Zero-daemon clean-room architecture, module responsibilities, domain models, and 0–100 risk score calculation formula.
- **[Security Rules Reference](docs/RULES.md)**: Exhaustive catalog of all 10 detection rules with threat models, severities, and remediation guides.
- **[CLI Usage Guide](docs/USAGE.md)**: Complete command-line manual, flags, exit codes, CI/CD SARIF upload workflows, and JSON pipelines.
- **[Test & Verification Declaration](docs/TESTING.md)**: Audited test inventory, AST security verification, SAST audit results, and per-module code coverage metrics.
- **[Changelog](CHANGELOG.md)**: Semantic release history and detailed changelog entries.
- **[Contributing Guidelines](CONTRIBUTING.md)**: Developer setup, coding standards, line length, typing, and PR requirements.
- **[Security Policy](SECURITY.md)**: Vulnerability disclosure procedure, reporting email, and 48-hour response SLA.
- **[Legal Notice & Attributions](NOTICE)**: Apache-2.0 Section 4 legal notice, trademark reservations, and third-party software attributions.

## Development & Testing

Run all project linters, security audits, and test suites:

```bash
# Run code style and lint checks
uv run ruff check src/ tests/

# Run static application security testing (SAST)
uv run bandit -r src/

# Run unit and integration tests with coverage
uv run pytest
```

---

## License

This project is licensed under the Apache-2.0 License - see the [LICENSE](LICENSE) and [NOTICE](NOTICE) files for details.

Developed with precision by **Logihertz Systems (OPC) Private Limited** (`logihertzsystems`).  
Created, architected, and engineered by **Sameer Tawade** (Creator, Founder, Director & Whole and Sole Developer — `ops@logihertz.com`).
