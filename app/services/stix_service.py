"""
STIX 2.1 & TAXII Export Service (Task 10)
=========================================
Exports Threat Intelligence Platform data (Indicators, Malware, Reports, Relationships)
into the OASIS STIX 2.1 (Structured Threat Information Expression) open JSON standard.

Specifications:
- OASIS STIX 2.1: https://docs.oasis-open.org/cti/stix/v2.1/os/stix-v2.1-os.html
- STIX Cyber Observables: ipv4-addr, domain-name, url, file (hashes)
- STIX Domain Objects (SDOs): indicator, malware, report
- STIX Relationship Objects (SROs): relationship (indicates, related-to)
- TAXII 2.1 Collection Discovery Endpoint
"""

from datetime import datetime, timezone
import json
import logging
import re
from typing import Any, Dict, List, Optional, Tuple, Set
import uuid

from sqlalchemy import or_, func

from app import db
from app.models import (
    Malware,
    ThreatIndicator,
    ThreatReport,
)

logger = logging.getLogger(__name__)

# Deterministic namespace for TIP STIX 2.1 UUIDv5 generation
TIP_STIX_NAMESPACE = uuid.UUID("3d2b2f60-9fa1-4d32-9cb0-1a735071e626")


def _format_rfc3339(dt: Optional[datetime]) -> str:
    """Format datetime into standard ISO 8601 / RFC 3339 UTC timestamp."""
    if not dt:
        dt = datetime.now(timezone.utc)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def generate_stix_id(object_type: str, seed: str) -> str:
    """Generate deterministic STIX 2.1 identifier based on object type and unique seed."""
    unique_uuid = uuid.uuid5(TIP_STIX_NAMESPACE, f"{object_type}:{seed}")
    return f"{object_type}--{unique_uuid}"


def escape_stix_value(val: str) -> str:
    """Escape backslashes and single quotes within STIX 2.1 pattern expressions."""
    return str(val).replace("\\", "\\\\").replace("'", "\\'")


def build_stix_pattern(indicator_type: str, indicator_value: str) -> str:
    """
    Construct OASIS STIX 2.1 standard pattern string for cyber observables.
    Examples:
      - [ipv4-addr:value = '198.51.100.77']
      - [domain-name:value = 'malicious-domain.com']
      - [url:value = 'http://malicious.org/drop.exe']
      - [file:hashes.MD5 = '0123456789abcdef0123456789abcdef']
      - [file:hashes.'SHA-256' = '44d886...']
    """
    val = escape_stix_value(indicator_value)
    itype = str(indicator_type).strip().lower()

    if itype in ("ipv4", "ip"):
        return f"[ipv4-addr:value = '{val}']"
    elif itype in ("ipv6"):
        return f"[ipv6-addr:value = '{val}']"
    elif itype in ("domain", "hostname"):
        return f"[domain-name:value = '{val}']"
    elif itype in ("url"):
        return f"[url:value = '{val}']"
    elif itype in ("md5"):
        return f"[file:hashes.MD5 = '{val}']"
    elif itype in ("sha1", "sha-1"):
        return f"[file:hashes.'SHA-1' = '{val}']"
    elif itype in ("sha256", "sha-256"):
        return f"[file:hashes.'SHA-256' = '{val}']"
    elif itype in ("email", "email-address"):
        return f"[email-addr:value = '{val}']"
    else:
        # Fallback generic custom observable pattern
        return f"[artifact:payload_bin = '{val}']"


def indicator_to_stix(indicator: ThreatIndicator) -> Dict[str, Any]:
    """Convert ThreatIndicator ORM instance into a valid STIX 2.1 Indicator SDO."""
    stix_id = generate_stix_id("indicator", f"indicator-{indicator.id}")
    pattern = build_stix_pattern(indicator.indicator_type, indicator.indicator_value)

    created_time = _format_rfc3339(indicator.created_at)
    modified_time = _format_rfc3339(indicator.updated_at or indicator.created_at)
    valid_from = _format_rfc3339(indicator.first_seen_at or indicator.created_at)

    labels = []
    if indicator.severity:
        labels.append(indicator.severity.lower())
    if indicator.status:
        labels.append(indicator.status.lower().replace(" ", "-"))

    obj: Dict[str, Any] = {
        "type": "indicator",
        "spec_version": "2.1",
        "id": stix_id,
        "created": created_time,
        "modified": modified_time,
        "name": f"{indicator.indicator_type.upper()}: {indicator.indicator_value}",
        "description": indicator.context or f"Threat indicator ingested from {indicator.source}",
        "indicator_types": ["malicious-activity"],
        "pattern": pattern,
        "pattern_type": "stix",
        "pattern_version": "2.1",
        "valid_from": valid_from,
        "confidence": int(indicator.confidence_score or 50),
        "labels": labels,
        # Standard custom TIP extensions
        "x_tip_id": indicator.id,
        "x_tip_risk_score": indicator.risk_score,
        "x_tip_tlp": indicator.tlp_marking,
        "x_tip_severity": indicator.severity,
        "x_tip_status": indicator.status,
    }

    if indicator.last_seen_at:
        obj["valid_until"] = _format_rfc3339(indicator.last_seen_at)

    return obj


def malware_to_stix(malware: Malware) -> Dict[str, Any]:
    """Convert Malware ORM instance into a valid STIX 2.1 Malware SDO."""
    stix_id = generate_stix_id("malware", f"malware-{malware.id}")
    created_time = _format_rfc3339(malware.created_at)
    modified_time = _format_rfc3339(malware.last_seen_at or malware.created_at)

    # Normalize malware type to STIX malware-type-ov vocabulary
    raw_type = (malware.malware_type or "other").strip().lower()
    malware_types = [raw_type] if raw_type in (
        "adware", "backdoor", "botnet", "cryptominer", "keylogger",
        "ransomware", "rootkit", "spyware", "trojan", "virus", "worm"
    ) else ["unknown"]

    ext_refs = []
    if malware.mitre_attack_id:
        clean_id = malware.mitre_attack_id.strip()
        ext_refs.append({
            "source_name": "mitre-attack",
            "external_id": clean_id,
            "url": f"https://attack.mitre.org/techniques/{clean_id}",
        })
    if malware.cve_id:
        clean_cve = malware.cve_id.strip()
        ext_refs.append({
            "source_name": "cve",
            "external_id": clean_cve,
            "url": f"https://nvd.nist.gov/vuln/detail/{clean_cve}",
        })

    obj: Dict[str, Any] = {
        "type": "malware",
        "spec_version": "2.1",
        "id": stix_id,
        "created": created_time,
        "modified": modified_time,
        "name": malware.malware_name,
        "description": malware.description or f"Malware record: {malware.malware_name} ({malware.platform})",
        "is_family": True,
        "malware_types": malware_types,
        "architecture_execution_envs": [malware.platform] if malware.platform else ["x86-64"],
        "x_tip_id": malware.id,
        "x_tip_risk_score": malware.risk_score,
        "x_tip_severity": malware.severity,
        "x_tip_family": malware.malware_family,
    }

    if ext_refs:
        obj["external_references"] = ext_refs

    if malware.first_seen_at:
        obj["first_seen"] = _format_rfc3339(malware.first_seen_at)
    if malware.last_seen_at:
        obj["last_seen"] = _format_rfc3339(malware.last_seen_at)

    return obj


def report_to_stix(report: ThreatReport, object_refs: List[str]) -> Dict[str, Any]:
    """Convert ThreatReport ORM instance into a valid STIX 2.1 Report SDO."""
    stix_id = generate_stix_id("report", f"report-{report.id}")
    published_time = _format_rfc3339(report.created_at)
    modified_time = _format_rfc3339(report.updated_at or report.created_at)

    return {
        "type": "report",
        "spec_version": "2.1",
        "id": stix_id,
        "created": published_time,
        "modified": modified_time,
        "name": report.title,
        "description": report.description,
        "published": published_time,
        "report_types": [str(report.category).strip().lower()],
        "object_refs": object_refs,
        "x_tip_id": report.id,
        "x_tip_severity": report.severity,
        "x_tip_tlp": report.tlp_level,
        "x_tip_sector": report.target_sector,
    }


def create_stix_relationship(
    source_ref: str,
    target_ref: str,
    relationship_type: str = "indicates",
    description: Optional[str] = None
) -> Dict[str, Any]:
    """Create a STIX 2.1 Relationship SRO linking two STIX objects."""
    seed = f"{source_ref}:{relationship_type}:{target_ref}"
    stix_id = generate_stix_id("relationship", seed)
    now_str = _format_rfc3339(datetime.now(timezone.utc))

    obj: Dict[str, Any] = {
        "type": "relationship",
        "spec_version": "2.1",
        "id": stix_id,
        "created": now_str,
        "modified": now_str,
        "relationship_type": relationship_type,
        "source_ref": source_ref,
        "target_ref": target_ref,
    }
    if description:
        obj["description"] = description
    return obj


def build_stix_bundle(
    indicators: List[ThreatIndicator],
    malwares: Optional[List[Malware]] = None,
    reports: Optional[List[ThreatReport]] = None,
) -> Dict[str, Any]:
    """
    Construct a complete, spec-compliant OASIS STIX 2.1 Bundle containing
    Indicators, Malwares, Reports, and their relational SRO links.
    """
    bundle_id = generate_stix_id("bundle", f"bundle-{datetime.now(timezone.utc).isoformat()}-{len(indicators)}")
    stix_objects: List[Dict[str, Any]] = []
    seen_ids: Set[str] = set()

    # 1. Map Indicators to STIX
    indicator_stix_map: Dict[int, str] = {}
    for ind in indicators:
        stix_ind = indicator_to_stix(ind)
        if stix_ind["id"] not in seen_ids:
            seen_ids.add(stix_ind["id"])
            stix_objects.append(stix_ind)
        indicator_stix_map[ind.id] = stix_ind["id"]

    # 2. Map Malwares to STIX & create SROs for linked indicators
    malware_stix_map: Dict[int, str] = {}
    if malwares:
        for mal in malwares:
            stix_mal = malware_to_stix(mal)
            if stix_mal["id"] not in seen_ids:
                seen_ids.add(stix_mal["id"])
                stix_objects.append(stix_mal)
            malware_stix_map[mal.id] = stix_mal["id"]

            # Create 'indicates' relationship for linked indicators
            for linked_ind in mal.indicators:
                if linked_ind.id in indicator_stix_map:
                    rel = create_stix_relationship(
                        source_ref=indicator_stix_map[linked_ind.id],
                        target_ref=stix_mal["id"],
                        relationship_type="indicates",
                        description=f"Indicator {linked_ind.indicator_value} indicates malware {mal.malware_name}"
                    )
                    if rel["id"] not in seen_ids:
                        seen_ids.add(rel["id"])
                        stix_objects.append(rel)

    # 3. Map Reports to STIX with object_refs
    if reports:
        for rep in reports:
            # Collect references to all indicators and malwares in this report
            rep_refs: List[str] = []
            for linked_ind in rep.indicators:
                if linked_ind.id in indicator_stix_map:
                    rep_refs.append(indicator_stix_map[linked_ind.id])
            for linked_mal in rep.malwares:
                if linked_mal.id in malware_stix_map:
                    rep_refs.append(malware_stix_map[linked_mal.id])

            stix_rep = report_to_stix(rep, rep_refs)
            if stix_rep["id"] not in seen_ids:
                seen_ids.add(stix_rep["id"])
                stix_objects.append(stix_rep)

    return {
        "type": "bundle",
        "id": bundle_id,
        "spec_version": "2.1",
        "objects": stix_objects
    }


def export_stix_bundle(
    indicator_type: Optional[str] = None,
    min_risk: Optional[int] = None,
    severity: Optional[str] = None,
    status: Optional[str] = None,
    report_id: Optional[int] = None,
    malware_id: Optional[int] = None,
    limit: int = 500,
) -> Dict[str, Any]:
    """
    Query database based on filters and generate a full STIX 2.1 Bundle.
    """
    ind_query = ThreatIndicator.query

    # Direct association filters
    if report_id:
        rep = db.session.get(ThreatReport, report_id)
        if rep:
            indicators = rep.indicators[:limit]
            return build_stix_bundle(
                indicators=indicators,
                malwares=rep.malwares,
                reports=[rep]
            )

    if malware_id:
        mal = db.session.get(Malware, malware_id)
        if mal:
            indicators = mal.indicators[:limit]
            return build_stix_bundle(
                indicators=indicators,
                malwares=[mal],
                reports=None
            )

    # General indicators filter
    if indicator_type and indicator_type.lower() != "all":
        norm_type = indicator_type.lower()
        if norm_type in ("ip", "ipv4"):
            ind_query = ind_query.filter(func.lower(ThreatIndicator.indicator_type).in_(["ip", "ipv4"]))
        elif norm_type == "hash":
            ind_query = ind_query.filter(func.lower(ThreatIndicator.indicator_type).in_(["md5", "sha1", "sha256"]))
        else:
            ind_query = ind_query.filter(func.lower(ThreatIndicator.indicator_type) == norm_type)

    if min_risk is not None and min_risk > 0:
        ind_query = ind_query.filter(ThreatIndicator.risk_score >= min_risk)

    if severity and severity.lower() != "all":
        ind_query = ind_query.filter(ThreatIndicator.severity == severity.capitalize())

    if status and status.lower() != "all":
        ind_query = ind_query.filter(ThreatIndicator.status == status.title())

    indicators = ind_query.order_by(
        func.coalesce(ThreatIndicator.last_seen_at, ThreatIndicator.created_at).desc()
    ).limit(limit).all()

    # Collect associated malwares for complete STIX graph context
    associated_malware_ids: Set[int] = set()
    for ind in indicators:
        for m in ind.malwares:
            associated_malware_ids.add(m.id)

    malwares: List[Malware] = []
    if associated_malware_ids:
        malwares = Malware.query.filter(Malware.id.in_(list(associated_malware_ids))).all()

    return build_stix_bundle(indicators=indicators, malwares=malwares)


def get_taxii_collections_manifest() -> Dict[str, Any]:
    """
    TAXII 2.1 Collection Discovery Endpoint.
    Returns available STIX 2.1 threat feed collections for TAXII 2.1 clients
    (e.g., OpenCTI, MISP, Anomali, AlienVault OTX, OpenTAXII).
    """
    total_indicators = ThreatIndicator.query.count()
    return {
        "title": "ThreatIntel Platform TAXII 2.1 Server",
        "description": "Automated OASIS STIX 2.1 and TAXII 2.1 Threat Intelligence Sharing Feed",
        "collections": [
            {
                "id": "collection--c011ec71-0001-4000-8000-746872656174",
                "title": "Active Threat Indicators",
                "description": "High-confidence active Indicators of Compromise and Malicious Infrastructure",
                "can_read": True,
                "can_write": False,
                "media_types": [
                    "application/vnd.oasis.stix+json; version=2.1"
                ],
                "total_items": total_indicators,
                "url": "/api/v1/stix/bundle"
            },
            {
                "id": "collection--c011ec71-0002-4000-8000-626c6f636b6c",
                "title": "High-Risk Perimeter Blocklist",
                "description": "Critical and High risk indicators for firewall and sensor blocklists (risk >= 50)",
                "can_read": True,
                "can_write": False,
                "media_types": [
                    "application/vnd.oasis.stix+json; version=2.1"
                ],
                "url": "/api/v1/stix/bundle?min_risk=50"
            }
        ]
    }
