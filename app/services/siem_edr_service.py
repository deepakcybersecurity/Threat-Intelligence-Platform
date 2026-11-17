"""
SIEM & EDR Integration Service (Task 8)
=======================================
Provides bidirectional integration between the Threat Intelligence Platform
and enterprise detection systems (SIEMs like Splunk, Microsoft Sentinel, Elastic;
EDRs like CrowdStrike Falcon, Microsoft Defender for Endpoint, SentinelOne).

Core Capabilities:
1. API Authentication & Token Validation
2. Alert & Telemetry Ingestion (Webhook endpoint)
3. Automated IOC Extraction, Deduplication, & Risk Scoring
4. Bi-directional Real-Time IOC Lookup for SIEM / EDR Queries
5. Automated Firewall & EDR Sensor Blocklist Export
"""

from datetime import datetime, timezone
import hashlib
import hmac
import json
import logging
import re
import secrets
from typing import Any, Dict, List, Optional, Tuple

from flask import current_app, request
from sqlalchemy import or_

from app import db
from app.models import (
    Alert,
    AuditLog,
    Malware,
    ThreatIndicator,
    ThreatReport,
    User,
)
from app.services.alert_service import get_or_create_alert, get_risk_level
from app.services.audit_service import log_action
from app.services.ioc_correlation import correlate_indicator_by_id
from app.services.ioc_enrichment import get_provider_for_type, _get_cached_enrichment
from app.services.ioc_extractor import extract_iocs
from app.services.risk_scoring import calculate_indicator_risk_by_id, save_indicator_risk

logger = logging.getLogger(__name__)

SEVERITY_LEVELS = ["Low", "Medium", "High", "Critical"]


def verify_webhook_signature(req: Any) -> Tuple[bool, str]:
    """
    Verify optional or required HMAC-SHA256 webhook signature and timestamp freshness.
    Supported headers:
      - X-Webhook-Signature or X-Hub-Signature-256 (sha256=<hex> or <hex>)
      - X-Webhook-Timestamp (epoch seconds or ISO-8601 string)
    """
    sig_header = req.headers.get("X-Webhook-Signature") or req.headers.get("X-Hub-Signature-256")
    require_sig = current_app.config.get("SIEM_WEBHOOK_REQUIRE_SIGNATURE", False)

    if not sig_header:
        if require_sig:
            return False, "Missing required webhook signature header (X-Webhook-Signature)"
        return True, "Signature not required and not provided"

    secret = current_app.config.get("SIEM_WEBHOOK_SECRET") or current_app.config.get("SIEM_WEBHOOK_API_KEY")
    if not secret:
        return False, "Webhook signing secret is not configured on the server"

    # Check timestamp freshness if provided
    ts_header = req.headers.get("X-Webhook-Timestamp")
    if ts_header:
        try:
            req_time = float(ts_header)
            now_time = datetime.now(timezone.utc).timestamp()
            # 300 second (5 min) replay prevention window
            if abs(now_time - req_time) > 300:
                return False, "Webhook timestamp is outside the allowed 300-second replay window"
        except (ValueError, TypeError):
            return False, "Invalid X-Webhook-Timestamp format"

    # Compute expected HMAC
    raw_data = req.get_data() or b""
    if ts_header:
        payload_to_sign = f"{ts_header}.".encode("utf-8") + raw_data
    else:
        payload_to_sign = raw_data

    expected_sig = hmac.new(secret.encode("utf-8"), payload_to_sign, hashlib.sha256).hexdigest()

    clean_sig = sig_header.strip()
    if clean_sig.startswith("sha256="):
        clean_sig = clean_sig[7:].strip()

    if not secrets.compare_digest(clean_sig.lower(), expected_sig.lower()):
        return False, "Invalid webhook HMAC signature"

    return True, "Webhook signature valid"


def authenticate_api_request(req: Any) -> Tuple[bool, str, Optional[Dict[str, Any]]]:
    """
    Authenticate an inbound API or Webhook request.
    Inspects:
    1. X-API-Key header
    2. Authorization: Bearer <key> header
    
    Query parameters (?api_key=) are explicitly rejected for security (CWE-598).

    Validates against:
    - Configured SIEM_WEBHOOK_API_KEY (constant-time compare)
    - Active User with provisioned individual API key
    """
    api_key = None

    # 1. Header X-API-Key
    if "X-API-Key" in req.headers:
        api_key = req.headers.get("X-API-Key", "").strip()

    # 2. Authorization header (Bearer or Token)
    if not api_key and "Authorization" in req.headers:
        auth_header = req.headers.get("Authorization", "").strip()
        parts = auth_header.split(" ")
        if len(parts) == 2 and parts[0].lower() in ("bearer", "token", "apikey"):
            api_key = parts[1].strip()
        elif len(parts) == 1:
            api_key = parts[0].strip()

    # 3. Query parameter ?api_key= is strictly prohibited (Security Hardening: CWE-598)
    # Reject request unconditionally if any api_key query parameter is present,
    # even when an API key is also supplied in headers, to strictly prevent credential leakage.
    if "api_key" in req.args:
        logger.warning(
            "Rejected API request containing credentials in URL query parameter (?api_key=). "
            "Clients must supply credentials exclusively via X-API-Key or Authorization headers."
        )
        return (
            False,
            "API keys in URL query parameters are strictly prohibited. Use X-API-Key or Authorization: Bearer header.",
            None,
        )

    if not api_key:
        return False, "Missing API key in request headers (X-API-Key or Authorization: Bearer)", None

    configured_secret = current_app.config.get("SIEM_WEBHOOK_API_KEY")
    if configured_secret and secrets.compare_digest(api_key, configured_secret):
        return True, "Authenticated via system webhook key", {"type": "system", "name": "SIEM-EDR-Collector", "role": "admin"}

    # 1. Match against individual active User API keys (Phase 3)
    user_by_key = User.query.filter_by(api_key=api_key, is_active=True).first()
    if user_by_key:
        return True, f"Authenticated via {user_by_key.role} API key ({user_by_key.username})", {
            "type": "user",
            "id": user_by_key.id,
            "name": user_by_key.username,
            "role": user_by_key.role,
        }

    return False, "Invalid API key provided", None


def normalize_severity(raw_sev: Any) -> str:
    """Normalize vendor severity strings or integers to platform enum."""
    if raw_sev is None:
        return "Medium"

    if isinstance(raw_sev, (int, float)):
        if raw_sev >= 4:
            return "Critical"
        elif raw_sev >= 3:
            return "High"
        elif raw_sev >= 2:
            return "Medium"
        return "Low"

    val = str(raw_sev).strip().lower()
    if any(k in val for k in ("crit", "sev1", "p1", "fatal", "4")):
        return "Critical"
    elif any(k in val for k in ("high", "sev2", "p2", "major", "3")):
        return "High"
    elif any(k in val for k in ("med", "sev3", "p3", "moderate", "2")):
        return "Medium"
    elif any(k in val for k in ("low", "info", "sev4", "p4", "minor", "1", "0")):
        return "Low"

    return "Medium"


def normalize_alert_payload(raw_json: Dict[str, Any]) -> Dict[str, Any]:
    """
    Parse vendor payloads (Splunk, Sentinel, CrowdStrike, Defender, or generic JSON)
    into a standardized structure with title, source, severity, description, and IOCs.
    """
    # 1. Title
    title = (
        raw_json.get("title")
        or raw_json.get("alert_name")
        or raw_json.get("incident_title")
        or raw_json.get("name")
        or raw_json.get("rule_name")
        or raw_json.get("displayName")
        or raw_json.get("DetectionName")
        or "SIEM/EDR Incident Alert"
    )
    title = str(title).strip()[:200]

    # 2. Source / Vendor
    source = (
        raw_json.get("source")
        or raw_json.get("vendor")
        or raw_json.get("product")
        or raw_json.get("siem_source")
        or raw_json.get("edr_vendor")
        or raw_json.get("origin")
        or "SIEM/EDR Ingest"
    )
    source = str(source).strip()[:100]

    # 3. Severity
    raw_sev = (
        raw_json.get("severity")
        or raw_json.get("severity_level")
        or raw_json.get("alert_severity")
        or raw_json.get("priority")
        or raw_json.get("Severity")
    )
    severity = normalize_severity(raw_sev)

    # 4. Description / Details (capped to 50k chars to prevent ReDoS / CPU exhaustion)
    description = (
        raw_json.get("description")
        or raw_json.get("details")
        or raw_json.get("summary")
        or raw_json.get("message")
        or raw_json.get("comment")
        or ""
    )
    description = str(description).strip()[:50000]

    # 5. Extract IOCs from explicit fields and embedded text
    text_corpus = f"{title}\n{description}\n"
    explicit_iocs = raw_json.get("iocs") or raw_json.get("indicators") or raw_json.get("artifacts") or []

    # Handle string or list of dicts for explicit iocs (capped at 500 items)
    if isinstance(explicit_iocs, list):
        for item in explicit_iocs[:500]:
            if isinstance(item, str):
                text_corpus += f" {item} "
            elif isinstance(item, dict):
                text_corpus += f" {item.get('value', '')} {item.get('indicator', '')} "
    elif isinstance(explicit_iocs, str):
        text_corpus += f" {explicit_iocs[:50000]} "

    # Check for direct entity fields common in SIEM/EDR
    for key in ("ip", "ipv4", "destination_ip", "source_ip", "src_ip", "dest_ip", "domain", "url", "hash", "sha256", "md5"):
        if key in raw_json and isinstance(raw_json[key], str):
            text_corpus += f" {raw_json[key]} "

    extracted = extract_iocs(text_corpus)

    return {
        "title": title,
        "source": source,
        "severity": severity,
        "description": description,
        "extracted_iocs": extracted,
    }


def ingest_siem_edr_alert(payload: Dict[str, Any], actor_info: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """
    Ingest a SIEM / EDR alert payload:
    1. Normalizes fields and extracts IOCs (IP, domain, URL, MD5, SHA1, SHA256).
    2. Persists or reuses ThreatIndicator records.
    3. Executes deterministic Risk Scoring on each indicator.
    4. Triggers automatic alert creation in Alert Center for high/critical threats.
    5. Creates a primary incident Alert linked to the SIEM/EDR source.
    6. Returns structured ingestion telemetry.
    """
    if not isinstance(payload, dict):
        raise ValueError("Invalid payload: must be a JSON object.")

    normalized = normalize_alert_payload(payload)
    title = normalized["title"]
    source = normalized["source"]
    severity = normalized["severity"]
    description = normalized["description"]
    extracted = normalized["extracted_iocs"]

    # Resolve acting user ID for ThreatIndicator.added_by_user_id foreign key constraint
    system_user_id = None
    if actor_info and actor_info.get("id"):
        system_user_id = actor_info["id"]
    else:
        fallback_user = User.query.filter(User.role.in_(["admin", "analyst"])).first() or User.query.first()
        if fallback_user:
            system_user_id = fallback_user.id

    now = datetime.utcnow()
    processed_indicators: List[Dict[str, Any]] = []
    created_count = 0
    reused_count = 0
    max_risk_score = 0

    # Ingest each extracted IOC (extract_iocs returns List[Dict[str, str]])
    for item in extracted:
        ioc_type = (item.get("type") or "").strip().lower()
        val = (item.get("value") or "").strip()
        if not val or not ioc_type:
            continue

        clean_val = val

        existing = ThreatIndicator.query.filter_by(
            indicator_value=clean_val,
            indicator_type=ioc_type
        ).first()

        if existing:
            existing.last_seen_at = now
            existing.updated_at = now
            indicator = existing
            is_created = False
            reused_count += 1
        else:
            indicator = ThreatIndicator(
                indicator_value=clean_val,
                indicator_type=ioc_type,
                confidence_score=70,
                severity=severity,
                status="Active",
                source=f"SIEM/EDR: {source}",
                first_seen_at=now,
                last_seen_at=now,
                created_at=now,
                updated_at=now,
                added_by_user_id=system_user_id,
                tlp_marking="WHITE"
            )
            db.session.add(indicator)
            db.session.flush()
            is_created = True
            created_count += 1

        # Run deterministic risk scoring & auto alert trigger
        risk_res = save_indicator_risk(indicator.id)
        score = indicator.risk_score or 0
        if score > max_risk_score:
            max_risk_score = score

        processed_indicators.append({
            "id": indicator.id,
            "value": indicator.indicator_value,
            "type": indicator.indicator_type,
            "risk_score": score,
            "risk_level": get_risk_level(score),
            "severity": indicator.severity,
            "created": is_created,
        })

    # Elevate incident severity if an ingested indicator has CRITICAL or HIGH risk
    final_incident_severity = severity
    if max_risk_score >= 75:
        final_incident_severity = "Critical"
    elif max_risk_score >= 50 and severity in ("Low", "Medium"):
        final_incident_severity = "High"

    # Build primary Incident Alert in Alert Center
    first_indicator_id = processed_indicators[0]["id"] if processed_indicators else None
    alert_title = f"[{source}] {title}"[:200]
    alert_desc = (
        f"Alert ingested from {source}. Severity: {final_incident_severity}. "
        f"IOCs extracted: {len(processed_indicators)} "
        f"({', '.join(p['value'] for p in processed_indicators[:5])}"
        f"{', ...' if len(processed_indicators) > 5 else ''}). "
        f"Description: {description}"
    )

    incident_alert, alert_created = get_or_create_alert(
        title=alert_title,
        alert_type="SIEM/EDR",
        severity=final_incident_severity,
        description=alert_desc,
        indicator_id=first_indicator_id,
        user_id=actor_info.get("id") if (actor_info and actor_info.get("type") == "user") else None
    )

    # Security Audit Logging for inbound webhook event (without logging secrets or raw payloads)
    log_action(
        user_id=system_user_id,
        action=f"siem_webhook_ingest:{source}:{incident_alert.id}",
        target_table="alerts",
        target_id=incident_alert.id,
    )

    db.session.commit()

    return {
        "success": True,
        "message": "SIEM/EDR alert ingested and analyzed successfully",
        "alert": {
            "id": incident_alert.id,
            "title": incident_alert.title,
            "severity": incident_alert.severity,
            "status": incident_alert.status,
            "alert_type": incident_alert.alert_type,
            "created": alert_created,
        },
        "source": source,
        "total_iocs_found": len(processed_indicators),
        "indicators_created": created_count,
        "indicators_reused": reused_count,
        "max_risk_score": max_risk_score,
        "indicators": processed_indicators,
    }


def lookup_ioc(indicator_val: str, indicator_type: Optional[str] = None) -> Dict[str, Any]:
    """
    Real-time IOC lookup for SIEM / EDR queries:
    Returns reputation score, risk level, campaign correlation,
    cached threat enrichment, and actionable SOC recommendation.
    """
    clean_val = indicator_val.strip() if indicator_val else ""
    if not clean_val:
        return {"known": False, "error": "Indicator value cannot be empty"}

    query = ThreatIndicator.query.filter_by(indicator_value=clean_val)
    if indicator_type:
        query = query.filter_by(indicator_type=indicator_type.strip().lower())

    indicator = query.first()

    if not indicator:
        return {
            "known": False,
            "indicator_value": clean_val,
            "recommendation": "UNKNOWN",
            "message": "Indicator is not present in local threat intelligence database.",
        }

    # Retrieve or calculate risk score
    score = indicator.risk_score
    if score is None:
        risk_calc = calculate_indicator_risk_by_id(indicator.id)
        score = risk_calc.get("risk_score", 0) if risk_calc.get("success") else 0
    level = get_risk_level(score)

    # Relational correlation
    corr = correlate_indicator_by_id(indicator.id)
    report_list = [r.get("title") for r in corr.get("reports", [])] if corr.get("success") else []
    malware_list = [m.get("name") for m in corr.get("malware", [])] if corr.get("success") else []
    related_iocs = [i.get("value") for i in corr.get("related_indicators", [])] if corr.get("success") else []

    # Cached external enrichment
    provider = get_provider_for_type(indicator.indicator_type)
    cached_enrichment = _get_cached_enrichment(provider, clean_val) if provider else None

    # SOC Action Recommendation
    if indicator.status == "False Positive":
        rec = "ALLOW_BENIGN"
    elif score >= 75 or indicator.severity == "Critical":
        rec = "BLOCK"
    elif score >= 50 or indicator.severity == "High":
        rec = "INVESTIGATE"
    elif score >= 25:
        rec = "MONITOR"
    else:
        rec = "LOW_RISK"

    return {
        "known": True,
        "indicator": {
            "id": indicator.id,
            "value": indicator.indicator_value,
            "type": indicator.indicator_type,
            "severity": indicator.severity,
            "confidence_score": indicator.confidence_score,
            "risk_score": score,
            "risk_level": level,
            "status": indicator.status,
            "source": indicator.source,
            "first_seen_at": indicator.first_seen_at.isoformat() if indicator.first_seen_at else None,
            "last_seen_at": indicator.last_seen_at.isoformat() if indicator.last_seen_at else None,
        },
        "recommendation": rec,
        "correlation": {
            "threat_reports_count": len(report_list),
            "threat_reports": report_list,
            "malware_families_count": len(malware_list),
            "malware_families": malware_list,
            "related_iocs_count": len(related_iocs),
            "related_iocs": related_iocs[:10],
        },
        "enrichment": {
            "provider": provider,
            "cached": bool(cached_enrichment),
            "data": cached_enrichment,
        },
    }


def get_blocklist_data(
    indicator_type: Optional[str] = None,
    min_risk: int = 50,
    limit: int = 1000,
) -> List[Dict[str, Any]]:
    """
    Extract active high-risk indicators for automated firewall / EDR blocklist feeds.
    Only includes indicators marked Active and meeting the risk threshold.
    """
    query = ThreatIndicator.query.filter(
        ThreatIndicator.status == "Active",
        or_(
            ThreatIndicator.risk_score >= min_risk,
            ThreatIndicator.severity.in_(["Critical", "High"])
        )
    )

    if indicator_type:
        query = query.filter(ThreatIndicator.indicator_type == indicator_type.strip().lower())

    indicators = query.order_by(ThreatIndicator.risk_score.desc()).limit(limit).all()

    results = []
    for ind in indicators:
        results.append({
            "id": ind.id,
            "value": ind.indicator_value,
            "type": ind.indicator_type,
            "risk_score": ind.risk_score or 50,
            "severity": ind.severity,
            "source": ind.source,
            "last_seen": ind.last_seen_at.isoformat() if ind.last_seen_at else None,
        })

    return results
