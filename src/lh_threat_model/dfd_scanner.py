# ==============================================================================
# Product:       lh-threat-model (lh-threat)
# Module:        src.lh_threat_model.dfd_scanner
# Role:          Security Analysis & Rule Evaluation Engine
# Organization:  Logihertz Systems (OPC) Private Limited (logihertzsystems)
# Creator:       Sameer Tawade (Creator, Founder, Director & Whole and Sole Developer)
# Contact:       ops@logihertz.com | https://logihertz.com/
# License:       Apache License 2.0 (SPDX-License-Identifier: Apache-2.0)
# ==============================================================================

"""Declarative system architecture manifest and DFD parser.

Parses .yaml, .yml, and .json architecture manifests and Data Flow Diagrams (DFDs),
extracting trust zones, components, and data flows for STRIDE threat analysis.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import yaml

from lh_threat_model.models import (
    Component,
    ComponentType,
    DataFlow,
    DFDModel,
    ScanTargetResult,
    TrustZone,
)
from lh_threat_model.stride_analyzer import analyze_stride


def _find_line_number(lines: list[str], identifier: str, fallback_key: str = "id") -> int | None:
    """Attempt to locate the line number where an element or ID is declared."""
    search_terms = [
        f"id: {identifier}",
        f"id: '{identifier}'",
        f'id: "{identifier}"',
        f"- id: {identifier}",
        f"- id: '{identifier}'",
        f'- id: "{identifier}"',
        f"name: {identifier}",
        f"name: '{identifier}'",
        f'name: "{identifier}"',
        f"- name: {identifier}",
        f"- name: '{identifier}'",
        f'- name: "{identifier}"',
        f"{identifier}:",
    ]
    for idx, line in enumerate(lines, 1):
        stripped = line.strip()
        if any(term in stripped for term in search_terms):
            return idx
    return None


def parse_manifest_dict(data: dict[str, Any], raw_lines: list[str] | None = None) -> DFDModel:
    """Parse raw manifest dictionary into structured DFDModel."""
    lines = raw_lines or []
    model = DFDModel(
        name=str(data.get("name", "")),
        version=str(data.get("version", "1.0")),
        description=str(data.get("description", "")),
        metadata=data.get("metadata", {}),
    )

    # 1. Parse Trust Zones
    raw_zones = (
        data.get("trust_zones")
        or data.get("trust_boundaries")
        or data.get("zones")
        or data.get("boundaries")
        or []
    )
    if isinstance(raw_zones, list):
        for z in raw_zones:
            if isinstance(z, dict):
                zid = str(z.get("id") or z.get("name") or "")
                zname = str(z.get("name") or zid)
                zdesc = str(z.get("description") or "")
                if zid:
                    model.trust_zones[zid] = TrustZone(id=zid, name=zname, description=zdesc)
            elif isinstance(z, str):
                model.trust_zones[z] = TrustZone(id=z, name=z)
    elif isinstance(raw_zones, dict):
        for zid, zobj in raw_zones.items():
            if isinstance(zobj, dict):
                zname = str(zobj.get("name") or zid)
                zdesc = str(zobj.get("description") or "")
                model.trust_zones[zid] = TrustZone(id=zid, name=zname, description=zdesc)
            else:
                model.trust_zones[zid] = TrustZone(id=zid, name=str(zobj))

    # 2. Parse Components
    raw_components: list[dict[str, Any]] = []

    for key in ("components", "elements", "nodes", "services", "datastores", "processes"):
        val = data.get(key)
        if isinstance(val, list):
            for item in val:
                if isinstance(item, dict):
                    raw_components.append(item)
        elif isinstance(val, dict):
            for comp_id, comp_obj in val.items():
                if isinstance(comp_obj, dict):
                    entry = dict(comp_obj)
                    if "id" not in entry:
                        entry["id"] = comp_id
                    raw_components.append(entry)

    for item in raw_components:
        cid = str(item.get("id") or item.get("name") or "")
        if not cid:
            continue

        cname = str(item.get("name") or cid)
        ctype_str = item.get("type") or item.get("kind")
        ctype = ComponentType.from_str(ctype_str)
        czone = str(item.get("trust_zone") or item.get("zone") or item.get("boundary") or "")
        ccls = str(item.get("data_classification") or item.get("classification") or "")

        line_num = _find_line_number(lines, cid)

        comp = Component(
            id=cid,
            name=cname,
            type=ctype,
            trust_zone=czone,
            data_classification=ccls,
            encryption_at_rest=item.get("encryption_at_rest") or item.get("encrypted_at_rest"),
            audit_logging=item.get("audit_logging") or item.get("audit_trail"),
            immutable_audit_trail=item.get("immutable_audit_trail") or item.get("immutable_audit"),
            rate_limit=item.get("rate_limit") or item.get("rate_limiting"),
            waf_enabled=item.get("waf_enabled") or item.get("waf"),
            ddos_protection=item.get("ddos_protection") or item.get("ddos"),
            privileged=item.get("privileged"),
            run_as_root=item.get("run_as_root"),
            admin_permissions=item.get("admin_permissions"),
            critical=item.get("critical"),
            state_changing=item.get("state_changing"),
            egress_filtering=item.get("egress_filtering"),
            secret_rotation=item.get("secret_rotation"),
            isolated_network_zone=item.get("isolated_network_zone"),
            raw_data=item,
            line_number=line_num,
        )
        model.components[cid] = comp

    # 3. Parse Data Flows
    raw_flows: list[dict[str, Any]] = []
    for key in ("data_flows", "flows", "edges", "connections", "links"):
        val = data.get(key)
        if isinstance(val, list):
            for item in val:
                if isinstance(item, dict):
                    raw_flows.append(item)
        elif isinstance(val, dict):
            for flow_id, flow_obj in val.items():
                if isinstance(flow_obj, dict):
                    entry = dict(flow_obj)
                    if "id" not in entry:
                        entry["id"] = flow_id
                    raw_flows.append(entry)

    for item in raw_flows:
        src = str(item.get("source") or item.get("from") or item.get("src") or "")
        tgt = str(item.get("target") or item.get("to") or item.get("destination") or "")
        fid = str(item.get("id") or item.get("name") or f"{src}->{tgt}")

        fname = str(item.get("name") or fid)
        proto = str(item.get("protocol") or item.get("scheme") or "")
        enc = item.get("encrypted") or item.get("tls")

        auth_val = item.get("auth") or item.get("auth_mechanism") or item.get("authentication")
        auth_mech = str(item.get("auth_mechanism") or item.get("auth") or "")
        auth_bool = item.get("authenticated")

        integrity = (
            item.get("integrity")
            or item.get("message_integrity")
            or item.get("integrity_verification")
        )

        line_num = _find_line_number(lines, fid) or _find_line_number(lines, src)

        flow = DataFlow(
            id=fid,
            source=src,
            target=tgt,
            name=fname,
            protocol=proto,
            encrypted=enc,
            auth=str(auth_val) if auth_val is not None else None,
            auth_mechanism=auth_mech or None,
            authenticated=auth_bool,
            integrity=str(integrity) if integrity is not None else None,
            egress_filtering=item.get("egress_filtering"),
            secret_rotation=item.get("secret_rotation"),
            isolated_network_zone=item.get("isolated_network_zone"),
            data_classification=item.get("data_classification"),
            raw_data=item,
            line_number=line_num,
        )
        model.flows.append(flow)

    return model


def load_manifest(path: Path) -> tuple[DFDModel | None, str | None]:
    """Read and parse manifest file into DFDModel.

    Returns:
        Tuple of (DFDModel or None, error_message or None).
    """
    if not path.exists():
        return None, f"Manifest file '{path}' does not exist."

    try:
        content = path.read_text(encoding="utf-8")
        lines = content.splitlines()
    except Exception as e:
        return None, f"Failed to read file '{path}': {e}"

    suffix = path.suffix.lower()
    try:
        if suffix == ".json":
            data = json.loads(content)
        else:
            data = yaml.safe_load(content)
    except Exception as e:
        return None, f"Failed to parse manifest '{path}': {e}"

    if not isinstance(data, dict):
        return None, f"Manifest '{path}' root must be a mapping/dictionary."

    model = parse_manifest_dict(data, lines)
    return model, None


def scan_dfd(path: Path) -> ScanTargetResult:
    """Scan a single architecture manifest file and analyze STRIDE threats."""
    target_str = str(path)
    model, error = load_manifest(path)

    if error:
        return ScanTargetResult(
            target=target_str,
            findings=[],
            error_message=error,
        )

    if model is None:
        return ScanTargetResult(
            target=target_str,
            findings=[],
            error_message="Failed to load model.",
        )
    findings = analyze_stride(model, target_str)

    return ScanTargetResult(
        target=target_str,
        findings=findings,
        components_count=len(model.components),
        flows_count=len(model.flows),
        trust_zones_count=len(model.trust_zones),
    )
