# ==============================================================================
# Product:       lh-threat-model (lh-threat)
# Module:        src.lh_threat_model.stride_analyzer
# Role:          Security Analysis & Rule Evaluation Engine
# Organization:  Logihertz Systems (OPC) Private Limited (logihertzsystems)
# Creator:       Sameer Tawade (Creator, Founder, Director & Whole and Sole Developer)
# Contact:       ops@logihertz.com | https://logihertz.com/
# License:       Apache License 2.0 (SPDX-License-Identifier: Apache-2.0)
# ==============================================================================

"""STRIDE threat modeling and architectural risk analyzer.

Evaluates system architecture models and Data Flow Diagrams (DFDs) against
Microsoft STRIDE security categories and Logihertz detection rules (LH-THREAT-001 - 010).
"""

from __future__ import annotations

from lh_threat_model.models import (
    RULES_REGISTRY,
    Component,
    ComponentType,
    DataFlow,
    DFDModel,
    Finding,
)

UNENCRYPTED_PROTOCOLS = {"http", "tcp", "ftp", "ws", "telnet", "smtp", "ldap"}
ENCRYPTED_PROTOCOLS = {
    "https",
    "tls",
    "ssl",
    "wss",
    "sftp",
    "ssh",
    "ftps",
    "ldaps",
    "grpc+tls",
    "mtls",
}
EXTERNAL_ZONES = {"internet", "public", "external", "untrusted"}
INTERNAL_ZONES = {"internal", "private", "secure", "backend", "restricted", "database", "db_zone"}
SENSITIVE_CLASSIFICATIONS = {"restricted", "confidential", "pii", "pci", "sensitive", "secret"}
AUTH_KEYWORDS_INVALID = {
    "",
    "none",
    "unauthenticated",
    "anonymous",
    "null",
    "false",
    "no",
    "disabled",
    "missing",
}
INTEGRITY_KEYWORDS_SECURE = (
    "mtls",
    "hmac",
    "signature",
    "signing",
    "signed",
    "jws",
    "jwt",
    "sha256",
    "sha512",
)


def _is_cross_boundary(
    flow: DataFlow,
    comp_src: Component | None,
    comp_tgt: Component | None,
) -> bool:
    """Determine if a data flow crosses a trust boundary."""
    src_zone = (comp_src.trust_zone if comp_src else "").strip().lower()
    tgt_zone = (comp_tgt.trust_zone if comp_tgt else "").strip().lower()

    if src_zone and tgt_zone and src_zone != tgt_zone:
        return True
    if src_zone in EXTERNAL_ZONES and tgt_zone not in EXTERNAL_ZONES:
        return True
    if comp_src and comp_src.type == ComponentType.EXTERNAL_ENTITY:
        return True
    return False
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


def _check_threat_001(flow: DataFlow, model: DFDModel, target: str) -> Finding | None:
    """LH-THREAT-001: Unencrypted data flow crossing trust boundary."""
    comp_src = model.components.get(flow.source)
    comp_tgt = model.components.get(flow.target)

    if not _is_cross_boundary(flow, comp_src, comp_tgt):
        return None

    proto = flow.protocol.strip().lower() if flow.protocol else ""
    is_encrypted = flow.encrypted

    is_violating = False
    if is_encrypted is False:
        is_violating = True
    elif proto in UNENCRYPTED_PROTOCOLS:
        is_violating = True
    elif is_encrypted is not True and proto not in ENCRYPTED_PROTOCOLS:
        is_violating = True

    if is_violating:
        rule = RULES_REGISTRY["LH-THREAT-001"]
        src_zone = comp_src.trust_zone if comp_src else "unknown"
        tgt_zone = comp_tgt.trust_zone if comp_tgt else "unknown"
        proto_desc = proto or "unspecified"
        return Finding(
            rule_id=rule.rule_id,
            severity=rule.severity,
            stride_category=rule.stride_category,
            title=rule.title,
            message=(
                f"Data flow '{flow.id}' crossing trust boundary ({src_zone} -> {tgt_zone}) "
                f"is unencrypted (protocol: {proto_desc}, encrypted: {is_encrypted})."
            ),
            target=target,
            element_id=flow.id,
            element_type="data_flow",
            source=flow.source,
            destination=flow.target,
            remediation=rule.remediation,
            line_number=flow.line_number,
            metadata={"protocol": proto, "encrypted": is_encrypted},
        )
    return None
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


def _check_threat_002(flow: DataFlow, model: DFDModel, target: str) -> Finding | None:
    """LH-THREAT-002: External or cross-boundary flow lacking authentication."""
    comp_src = model.components.get(flow.source)
    comp_tgt = model.components.get(flow.target)

    src_zone = (comp_src.trust_zone if comp_src else "").strip().lower()
    is_external_or_cross = (
        _is_cross_boundary(flow, comp_src, comp_tgt)
        or src_zone in EXTERNAL_ZONES
        or (
            comp_src and comp_src.type in (ComponentType.EXTERNAL_ENTITY, ComponentType.THIRD_PARTY)
        )
    )

    if not is_external_or_cross:
        return None

    if comp_tgt and comp_tgt.type == ComponentType.EXTERNAL_ENTITY:
        return None

    auth_val = flow.auth or flow.auth_mechanism or flow.raw_data.get("auth")
    auth_str = str(auth_val).strip().lower() if auth_val is not None else ""
    is_authenticated = flow.authenticated

    is_unauthenticated = False
    if is_authenticated is False:
        is_unauthenticated = True
    elif auth_str in AUTH_KEYWORDS_INVALID:
        is_unauthenticated = True

    if is_unauthenticated:
        rule = RULES_REGISTRY["LH-THREAT-002"]
        return Finding(
            rule_id=rule.rule_id,
            severity=rule.severity,
            stride_category=rule.stride_category,
            title=rule.title,
            message=(
                f"External or cross-boundary data flow '{flow.id}' targeting '{flow.target}' "
                f"lacks an authentication mechanism (auth: '{auth_val}')."
            ),
            target=target,
            element_id=flow.id,
            element_type="data_flow",
            source=flow.source,
            destination=flow.target,
            remediation=rule.remediation,
            line_number=flow.line_number,
            metadata={"auth": auth_val, "authenticated": is_authenticated},
        )
    return None
    # --------------------------------------------------------------------------
    # --- Rule LH-THREAT-003: Direct Public Ingress to Internal Datastore (CRITICAL) ---
    # Evaluates security posture against direct public ingress to internal
    # datastore.
    # Rationale: Prevents policy violations and reduces vulnerable surface exposure.
    # False Positive Defense: Contextual inspection ensures intentional configs are
    # respected.
    # --------------------------------------------------------------------------


def _check_threat_003(flow: DataFlow, model: DFDModel, target: str) -> Finding | None:
    """LH-THREAT-003: Direct external ingress to internal datastore."""
    comp_src = model.components.get(flow.source)
    comp_tgt = model.components.get(flow.target)

    if not comp_src or not comp_tgt:
        return None

    src_zone = comp_src.trust_zone.strip().lower() if comp_src.trust_zone else ""
    tgt_zone = comp_tgt.trust_zone.strip().lower() if comp_tgt.trust_zone else ""

    is_public_ingress_or_actor = (
        comp_src.type in (ComponentType.EXTERNAL_ENTITY, ComponentType.INGRESS)
        or src_zone in EXTERNAL_ZONES
        or comp_src.raw_data.get("internet_facing") is True
        or comp_src.raw_data.get("public") is True
    )

    is_internal_datastore = comp_tgt.type == ComponentType.DATASTORE and (
        tgt_zone in INTERNAL_ZONES or tgt_zone not in EXTERNAL_ZONES
    )

    if is_public_ingress_or_actor and is_internal_datastore:
        rule = RULES_REGISTRY["LH-THREAT-003"]
        return Finding(
            rule_id=rule.rule_id,
            severity=rule.severity,
            stride_category=rule.stride_category,
            title=rule.title,
            message=(
                f"Direct flow '{flow.id}' from public/ingress '{flow.source}' to internal "
                f"datastore '{flow.target}' without an intermediary application/API tier."
            ),
            target=target,
            element_id=flow.id,
            element_type="data_flow",
            source=flow.source,
            destination=flow.target,
            remediation=rule.remediation,
            line_number=flow.line_number,
            metadata={"source_zone": src_zone, "target_zone": tgt_zone},
        )
    return None
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


def _check_threat_004(flow: DataFlow, model: DFDModel, target: str) -> Finding | None:
    """LH-THREAT-004: Missing message integrity on cross-boundary or queue/webhook flow."""
    comp_src = model.components.get(flow.source)
    comp_tgt = model.components.get(flow.target)

    flow_text = f"{flow.id} {flow.name} {flow.source} {flow.target}".lower()
    is_queue_or_webhook = any(
        k in flow_text
        for k in ("webhook", "queue", "consumer", "event", "pubsub", "kafka", "sqs", "amqp")
    )
    is_cross = _is_cross_boundary(flow, comp_src, comp_tgt)

    if not (is_cross or is_queue_or_webhook):
        return None

    integrity_val = (
        flow.integrity
        or flow.raw_data.get("integrity")
        or flow.raw_data.get("integrity_verification")
        or flow.raw_data.get("message_integrity")
    )

    has_integrity = False
    if integrity_val is True:
        has_integrity = True
    elif isinstance(integrity_val, str):
        lowered = integrity_val.lower()
        if any(sec in lowered for sec in INTEGRITY_KEYWORDS_SECURE):
            has_integrity = True

    if not has_integrity:
        rule = RULES_REGISTRY["LH-THREAT-004"]
        return Finding(
            rule_id=rule.rule_id,
            severity=rule.severity,
            stride_category=rule.stride_category,
            title=rule.title,
            message=(
                f"Cross-boundary or queue/webhook data flow '{flow.id}' lacks message integrity "
                f"verification (mTLS, HMAC, or payload signing)."
            ),
            target=target,
            element_id=flow.id,
            element_type="data_flow",
            source=flow.source,
            destination=flow.target,
            remediation=rule.remediation,
            line_number=flow.line_number,
            metadata={"integrity": integrity_val},
        )
    return None
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


def _check_threat_005(comp: Component, target: str) -> Finding | None:
    """LH-THREAT-005: Sensitive/PII datastore unencrypted at rest."""
    if comp.type != ComponentType.DATASTORE:
        return None

    cls_str = (
        (
            comp.data_classification
            or comp.raw_data.get("data_classification")
            or comp.raw_data.get("classification")
            or ""
        )
        .strip()
        .lower()
    )

    if not any(sen in cls_str for sen in SENSITIVE_CLASSIFICATIONS):
        return None

    enc = comp.encryption_at_rest
    if enc is None:
        enc = comp.raw_data.get("encryption_at_rest")

    if enc is not True:
        rule = RULES_REGISTRY["LH-THREAT-005"]
        return Finding(
            rule_id=rule.rule_id,
            severity=rule.severity,
            stride_category=rule.stride_category,
            title=rule.title,
            message=(
                f"Datastore '{comp.id}' with sensitive classification '{cls_str}' does not "
                f"have encryption at rest enabled (encryption_at_rest: {enc})."
            ),
            target=target,
            element_id=comp.id,
            element_type="datastore",
            remediation=rule.remediation,
            line_number=comp.line_number,
            metadata={"data_classification": cls_str, "encryption_at_rest": enc},
        )
    return None
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


def _check_threat_006(comp: Component, target: str) -> Finding | None:
    """LH-THREAT-006: Critical state-changing or auth component missing audit logging."""
    if comp.type in (ComponentType.THIRD_PARTY, ComponentType.EXTERNAL_ENTITY):
        return None

    comp_text = f"{comp.id} {comp.name}".lower()
    is_critical_or_auth = (
        comp.critical is True
        or comp.state_changing is True
        or any(
            k in comp_text
            for k in (
                "auth",
                "idp",
                "login",
                "admin",
                "portal",
                "payment",
                "billing",
                "order",
                "transaction",
                "crypto",
                "kms",
                "iam",
            )
        )
    )

    if not is_critical_or_auth:
        return None

    audit = comp.audit_logging
    if audit is None:
        audit = comp.raw_data.get("audit_logging")

    immutable = comp.immutable_audit_trail
    if immutable is None:
        immutable = comp.raw_data.get("immutable_audit_trail")

    if audit is not True or immutable is not True:
        rule = RULES_REGISTRY["LH-THREAT-006"]
        return Finding(
            rule_id=rule.rule_id,
            severity=rule.severity,
            stride_category=rule.stride_category,
            title=rule.title,
            message=(
                f"Critical/auth component '{comp.id}' lacks enabled audit logging or immutable "
                f"audit trail configuration (audit_logging: {audit}, immutable_audit: {immutable})."
            ),
            target=target,
            element_id=comp.id,
            element_type="component",
            remediation=rule.remediation,
            line_number=comp.line_number,
            metadata={"audit_logging": audit, "immutable_audit_trail": immutable},
        )
    return None
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


def _check_threat_007(comp: Component, target: str) -> Finding | None:
    """LH-THREAT-007: Internet-facing ingress missing rate limiting or WAF/DDoS."""
    if comp.type in (ComponentType.THIRD_PARTY, ComponentType.EXTERNAL_ENTITY):
        return None

    comp_text = f"{comp.id} {comp.name}".lower()
    zone = comp.trust_zone.strip().lower() if comp.trust_zone else ""

    is_ingress_or_public = (
        comp.type == ComponentType.INGRESS
        or zone in ("internet", "public", "dmz", "external")
        or comp.raw_data.get("internet_facing") is True
        or comp.raw_data.get("public") is True
        or any(
            k in comp_text for k in ("ingress", "gateway", "api_gateway", "load_balancer", "alb")
        )
    )

    if not is_ingress_or_public:
        return None

    rate_limit = comp.rate_limit
    if rate_limit is None:
        rate_limit = comp.raw_data.get("rate_limit") or comp.raw_data.get("rate_limiting")

    waf = comp.waf_enabled
    if waf is None:
        waf = comp.raw_data.get("waf_enabled") or comp.raw_data.get("waf")

    ddos = comp.ddos_protection
    if ddos is None:
        ddos = comp.raw_data.get("ddos_protection") or comp.raw_data.get("ddos")

    if rate_limit is not True or waf is not True or ddos is False:
        rule = RULES_REGISTRY["LH-THREAT-007"]
        return Finding(
            rule_id=rule.rule_id,
            severity=rule.severity,
            stride_category=rule.stride_category,
            title=rule.title,
            message=(
                f"Internet-facing component '{comp.id}' is missing rate limiting or WAF/DDoS "
                f"protections (rate_limit: {rate_limit}, waf_enabled: {waf})."
            ),
            target=target,
            element_id=comp.id,
            element_type="ingress",
            remediation=rule.remediation,
            line_number=comp.line_number,
            metadata={"rate_limit": rate_limit, "waf_enabled": waf, "ddos_protection": ddos},
        )
    return None
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


def _check_threat_008(comp: Component, target: str) -> Finding | None:
    """LH-THREAT-008: Compute service running with over-privileged context."""
    if comp.type not in (ComponentType.PROCESS, ComponentType.INGRESS, ComponentType.UNKNOWN):
        return None

    privileged = comp.privileged or comp.raw_data.get("privileged")
    run_as_root = comp.run_as_root or comp.raw_data.get("run_as_root")
    admin_perms = comp.admin_permissions or comp.raw_data.get("admin_permissions")

    sec_ctx = comp.raw_data.get("security_context", {})
    if isinstance(sec_ctx, dict):
        if sec_ctx.get("privileged") is True:
            privileged = True
        if sec_ctx.get("runAsRoot") is True or sec_ctx.get("run_as_root") is True:
            run_as_root = True

    if privileged is True or run_as_root is True or admin_perms is True:
        rule = RULES_REGISTRY["LH-THREAT-008"]
        return Finding(
            rule_id=rule.rule_id,
            severity=rule.severity,
            stride_category=rule.stride_category,
            title=rule.title,
            message=(
                f"Compute service '{comp.id}' executes with over-privileged context "
                f"(privileged: {privileged}, run_as_root: {run_as_root}, admin: {admin_perms})."
            ),
            target=target,
            element_id=comp.id,
            element_type="process",
            remediation=rule.remediation,
            line_number=comp.line_number,
            metadata={
                "privileged": privileged,
                "run_as_root": run_as_root,
                "admin_permissions": admin_perms,
            },
        )
    return None
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


def _check_threat_009_comp(comp: Component, target: str) -> Finding | None:
    """LH-THREAT-009: Third-party integration lacking boundary controls."""
    comp_text = f"{comp.id} {comp.name}".lower()
    is_third_party = comp.type == ComponentType.THIRD_PARTY or any(
        k in comp_text
        for k in (
            "third_party",
            "saas",
            "stripe",
            "twilio",
            "sendgrid",
            "auth0",
            "salesforce",
            "external_api",
        )
    )

    if not is_third_party:
        return None

    egress = comp.egress_filtering
    if egress is None:
        egress = comp.raw_data.get("egress_filtering")

    rotation = comp.secret_rotation
    if rotation is None:
        rotation = comp.raw_data.get("secret_rotation")

    isolated = comp.isolated_network_zone
    if isolated is None:
        isolated = comp.raw_data.get("isolated_network_zone")

    if egress is not True or rotation is not True or isolated is not True:
        rule = RULES_REGISTRY["LH-THREAT-009"]
        return Finding(
            rule_id=rule.rule_id,
            severity=rule.severity,
            stride_category=rule.stride_category,
            title=rule.title,
            message=(
                f"Third-party/SaaS integration '{comp.id}' lacks egress filtering, secret "
                f"rotation, or network isolation (egress: {egress}, rotation: {rotation}, "
                f"isolated: {isolated})."
            ),
            target=target,
            element_id=comp.id,
            element_type="third_party",
            remediation=rule.remediation,
            line_number=comp.line_number,
            metadata={
                "egress_filtering": egress,
                "secret_rotation": rotation,
                "isolated_network_zone": isolated,
            },
        )
    return None
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


def _check_threat_010(comp: Component, target: str) -> list[Finding]:
    """LH-THREAT-010: Component missing explicit trust zone or data classification tag."""
    findings: list[Finding] = []
    rule = RULES_REGISTRY["LH-THREAT-010"]

    zone = comp.trust_zone or comp.raw_data.get("trust_zone") or comp.raw_data.get("zone")
    if not zone or not str(zone).strip():
        findings.append(
            Finding(
                rule_id=rule.rule_id,
                severity=rule.severity,
                stride_category=rule.stride_category,
                title=rule.title,
                message=f"Component '{comp.id}' is missing an explicit trust_zone assignment.",
                target=target,
                element_id=comp.id,
                element_type="component",
                remediation=rule.remediation,
                line_number=comp.line_number,
                metadata={"missing": "trust_zone"},
            )
        )

    if comp.type == ComponentType.DATASTORE:
        cls_val = (
            comp.data_classification
            or comp.raw_data.get("data_classification")
            or comp.raw_data.get("classification")
        )
        if not cls_val or not str(cls_val).strip():
            findings.append(
                Finding(
                    rule_id=rule.rule_id,
                    severity=rule.severity,
                    stride_category=rule.stride_category,
                    title=rule.title,
                    message=f"Datastore '{comp.id}' missing explicit data_classification tag.",
                    target=target,
                    element_id=comp.id,
                    element_type="datastore",
                    remediation=rule.remediation,
                    line_number=comp.line_number,
                    metadata={"missing": "data_classification"},
                )
            )

    return findings


def analyze_stride(model: DFDModel, target: str) -> list[Finding]:
    """Analyze architecture model against STRIDE rules and return list of findings."""
    findings: list[Finding] = []

    # Check component-level rules (005, 006, 007, 008, 009, 010)
    for comp in model.components.values():
        f5 = _check_threat_005(comp, target)
        if f5:
            findings.append(f5)

        f6 = _check_threat_006(comp, target)
        if f6:
            findings.append(f6)

        f7 = _check_threat_007(comp, target)
        if f7:
            findings.append(f7)

        f8 = _check_threat_008(comp, target)
        if f8:
            findings.append(f8)

        f9 = _check_threat_009_comp(comp, target)
        if f9:
            findings.append(f9)

        f10_list = _check_threat_010(comp, target)
        findings.extend(f10_list)

    # Check flow-level rules (001, 002, 003, 004)
    for flow in model.flows:
        f1 = _check_threat_001(flow, model, target)
        if f1:
            findings.append(f1)

        f2 = _check_threat_002(flow, model, target)
        if f2:
            findings.append(f2)

        f3 = _check_threat_003(flow, model, target)
        if f3:
            findings.append(f3)

        f4 = _check_threat_004(flow, model, target)
        if f4:
            findings.append(f4)

    return findings
