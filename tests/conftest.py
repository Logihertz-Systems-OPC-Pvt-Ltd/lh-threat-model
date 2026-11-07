# ==============================================================================
# Product:       lh-threat-model (lh-threat)
# Module:        tests.conftest
# Role:          Test Suite & Rule Verification
# Organization:  Logihertz Systems (OPC) Private Limited (logihertzsystems)
# Creator:       Sameer Tawade (Creator, Founder, Director & Whole and Sole Developer)
# Contact:       ops@logihertz.com | https://logihertz.com/
# License:       Apache License 2.0 (SPDX-License-Identifier: Apache-2.0)
# ==============================================================================

"""Pytest test configuration and fixtures for lh-threat-model.

Provides hardened and insecure system architecture manifests (YAML/JSON)
covering all 10 Logihertz STRIDE threat detection rules.
"""

from __future__ import annotations

from pathlib import Path

import pytest

CLEAN_HARDENED_MANIFEST = """
version: "1.0"
name: "Hardened Enterprise E-Commerce Platform"
description: "Compliant cloud-native architecture model with zero STRIDE violations."

trust_zones:
  - id: internet
    name: "Public Internet"
  - id: dmz
    name: "Perimeter DMZ"
  - id: internal
    name: "Secure Internal App Zone"
  - id: database_zone
    name: "Isolated Database Zone"
  - id: saas_zone
    name: "Third-Party SaaS Integration Zone"

components:
  - id: client_browser
    name: "Web Browser Client"
    type: external_entity
    trust_zone: internet

  - id: api_gateway
    name: "Enterprise Edge Gateway"
    type: ingress
    trust_zone: dmz
    rate_limit: true
    waf_enabled: true
    ddos_protection: true
    audit_logging: true
    immutable_audit_trail: true

  - id: auth_service
    name: "Central Authentication Service"
    type: process
    trust_zone: internal
    critical: true
    state_changing: true
    audit_logging: true
    immutable_audit_trail: true
    privileged: false
    run_as_root: false
    admin_permissions: false

  - id: order_service
    name: "Order Processing Microservice"
    type: process
    trust_zone: internal
    audit_logging: true
    immutable_audit_trail: true
    privileged: false
    run_as_root: false
    admin_permissions: false

  - id: payment_gateway
    name: "Stripe Payment SaaS"
    type: third_party
    trust_zone: saas_zone
    egress_filtering: true
    secret_rotation: true
    isolated_network_zone: true

  - id: customer_db
    name: "Customer Relational Database"
    type: datastore
    trust_zone: database_zone
    data_classification: restricted
    encryption_at_rest: true

data_flows:
  - id: flow_client_to_gw
    name: "Public HTTPS Client Traffic"
    source: client_browser
    target: api_gateway
    protocol: https
    encrypted: true
    auth_mechanism: oauth2
    integrity: hmac

  - id: flow_gw_to_auth
    name: "Internal Authenticated Ingress"
    source: api_gateway
    target: auth_service
    protocol: https
    encrypted: true
    auth_mechanism: mtls
    integrity: mtls

  - id: flow_gw_to_order
    name: "Internal Order API Ingress"
    source: api_gateway
    target: order_service
    protocol: https
    encrypted: true
    auth_mechanism: mtls
    integrity: mtls

  - id: flow_order_to_payment
    name: "Egress Payment Dispatch"
    source: order_service
    target: payment_gateway
    protocol: https
    encrypted: true
    auth_mechanism: api_key
    integrity: hmac
    egress_filtering: true
    secret_rotation: true
    isolated_network_zone: true

  - id: flow_order_to_db
    name: "Secure SQL Database Queries"
    source: order_service
    target: customer_db
    protocol: tls
    encrypted: true
    auth_mechanism: mtls
    integrity: mtls
"""

VIOLATIONS_MANIFEST = """
version: "1.0"
name: "Vulnerable System Architecture"
description: "Intentionally misconfigured architecture demonstrating STRIDE threats."

trust_zones:
  - id: internet
    name: "Public Internet"
  - id: dmz
    name: "Perimeter DMZ"
  - id: internal
    name: "Internal Zone"

components:
  - id: public_user
    name: "Untrusted Web User"
    type: external_entity
    trust_zone: internet

  - id: edge_gw
    name: "Edge Gateway Missing WAF"
    type: ingress
    trust_zone: dmz
    rate_limit: false
    waf_enabled: false

  - id: root_worker
    name: "Privileged Compute Worker"
    type: process
    trust_zone: internal
    privileged: true
    run_as_root: true

  - id: user_auth_service
    name: "User Auth Portal"
    type: process
    trust_zone: internal
    audit_logging: false
    immutable_audit_trail: false

  - id: stripe_saas
    name: "External Payment API"
    type: third_party
    trust_zone: dmz
    egress_filtering: false
    secret_rotation: false

  - id: sensitive_db
    name: "Unencrypted PII Datastore"
    type: datastore
    trust_zone: internal
    data_classification: pii
    encryption_at_rest: false

  - id: unclassified_store
    name: "Legacy Cache Datastore"
    type: datastore

data_flows:
  - id: flow_unencrypted_cross
    name: "Unencrypted Plaintext Flow"
    source: public_user
    target: edge_gw
    protocol: http
    encrypted: false
    auth: none
    integrity: none

  - id: flow_direct_to_db
    name: "Direct Ingress to Internal DB"
    source: public_user
    target: sensitive_db
    protocol: tcp
    encrypted: false
    auth: none

  - id: flow_webhook_unverified
    name: "Webhook Queue Consumer"
    source: edge_gw
    target: root_worker
    protocol: https
    encrypted: true
    auth: api_key
    integrity: none
"""


@pytest.fixture
def clean_manifest_file(tmp_path: Path) -> Path:
    """Fixture providing a temporary clean, fully compliant architecture manifest."""
    manifest_path = tmp_path / "clean_architecture.yaml"
    manifest_path.write_text(CLEAN_HARDENED_MANIFEST.strip(), encoding="utf-8")
    return manifest_path


@pytest.fixture
def violations_manifest_file(tmp_path: Path) -> Path:
    """Fixture providing an architecture manifest with intentional STRIDE violations."""
    manifest_path = tmp_path / "vulnerable_architecture.yaml"
    manifest_path.write_text(VIOLATIONS_MANIFEST.strip(), encoding="utf-8")
    return manifest_path
