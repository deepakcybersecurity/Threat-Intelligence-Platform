"""
Dedicated EDR Alert & Telemetry Ingestion Service (Task 9)
===========================================================
Specialized ingestion pipeline for Endpoint Detection & Response (EDR) sensors:
- CrowdStrike Falcon
- Microsoft Defender for Endpoint (MDE)
- SentinelOne Singularity
- VMware Carbon Black
- Generic EDR Telemetry Agents

Key Capabilities:
1. Endpoint Sensor Context Extraction (Hostname, IP, OS, Agent ID)
2. Process Execution Tree & Command-Line Obfuscation Analysis
3. Binary Artifact & Hash Correlation (SHA256, MD5, SHA1)
4. Relational Malware Family Graph Matching (links to Malware records)
5. MITRE ATT&CK TTP Mapping (Tactics & Techniques)
6. Automated Endpoint Containment & Remediation Recommendation
7. Incident Alert Center Synchronization (alert_type='EDR')
"""

from datetime import datetime
import json
import logging
import re
from typing import Any, Dict, List, Optional, Tuple

from flask import current_app
from sqlalchemy import func, or_

from app import db
from app.models import (
    Alert,
    Malware,
    ThreatIndicator,
    ThreatReport,
    User,
)
from app.services.alert_service import get_or_create_alert, get_risk_level
from app.services.audit_service import log_action
from app.services.ioc_extractor import extract_iocs
from app.services.risk_scoring import save_indicator_risk
from app.services.siem_edr_service import normalize_severity

logger = logging.getLogger(__name__)


def normalize_edr_payload(raw_json: Dict[str, Any]) -> Dict[str, Any]:
    """
    Normalize diverse vendor EDR payloads (CrowdStrike, MDE, SentinelOne, Carbon Black)
    into a standardized endpoint security telemetry schema.
    """
    if not isinstance(raw_json, dict):
        raise ValueError("EDR payload must be a JSON object.")

    # 1. Endpoint Identity
    hostname = (
        raw_json.get("hostname")
        or raw_json.get("ComputerName")
        or raw_json.get("DeviceName")
        or raw_json.get("endpoint_name")
        or raw_json.get("host")
        or raw_json.get("device_name")
        or "UNKNOWN-ENDPOINT"
    )
    hostname = str(hostname).strip()[:100]

    host_ip = (
        raw_json.get("host_ip")
        or raw_json.get("local_ip")
        or raw_json.get("PublicIP")
        or raw_json.get("ip_address")
        or raw_json.get("ip")
        or "N/A"
    )
    host_ip = str(host_ip).strip()[:45]

    agent_id = (
        raw_json.get("agent_id")
        or raw_json.get("aid")
        or raw_json.get("DeviceId")
        or raw_json.get("sensor_id")
        or "N/A"
    )
    agent_id = str(agent_id).strip()[:100]

    os_platform = (
        raw_json.get("os_platform")
        or raw_json.get("os_type")
        or raw_json.get("OS")
        or raw_json.get("platform")
        or "Windows"
    )
    os_platform = str(os_platform).strip()[:50]

    # 2. Sensor Vendor Identification
    sensor_vendor = (
        raw_json.get("sensor_vendor")
        or raw_json.get("vendor")
        or raw_json.get("product")
        or raw_json.get("edr_vendor")
        or "EDR Sensor"
    )
    # Infer vendor if standard payload markers present
    if "DetectionName" in raw_json or "aid" in raw_json:
        sensor_vendor = "CrowdStrike Falcon"
    elif "DeviceId" in raw_json or "MitreTechniques" in raw_json:
        sensor_vendor = "Microsoft Defender for Endpoint"
    elif "endpoint_name" in raw_json and "agent_id" in raw_json:
        sensor_vendor = "SentinelOne"

    sensor_vendor = str(sensor_vendor).strip()[:100]

    # 3. Alert / Detection Name & Severity
    alert_title = (
        raw_json.get("title")
        or raw_json.get("DetectionName")
        or raw_json.get("Title")
        or raw_json.get("alert_name")
        or raw_json.get("threat_name")
        or f"Suspicious Activity Detected on {hostname}"
    )
    alert_title = str(alert_title).strip()[:200]

    raw_sev = (
        raw_json.get("severity")
        or raw_json.get("Severity")
        or raw_json.get("severity_level")
        or raw_json.get("priority")
    )
    severity = normalize_severity(raw_sev)

    # 4. Process Tree Context
    process_name = (
        raw_json.get("process_name")
        or raw_json.get("FileName")
        or raw_json.get("process")
        or raw_json.get("image_name")
        or "N/A"
    )
    process_name = str(process_name).strip()[:100]

    process_id = (
        raw_json.get("process_id")
        or raw_json.get("pid")
        or raw_json.get("ProcessId")
        or "N/A"
    )

    parent_process = (
        raw_json.get("parent_process")
        or raw_json.get("ParentCommandLine")
        or raw_json.get("parent_process_name")
        or "N/A"
    )

    command_line = (
        raw_json.get("command_line")
        or raw_json.get("CommandLine")
        or raw_json.get("ProcessCommandLine")
        or raw_json.get("cmdline")
        or ""
    )
    command_line = str(command_line).strip()

    file_path = (
        raw_json.get("file_path")
        or raw_json.get("FilePath")
        or raw_json.get("FolderPath")
        or raw_json.get("path")
        or "N/A"
    )

    # 5. MITRE ATT&CK TTP Context
    mitre_techniques: List[str] = []
    raw_techniques = raw_json.get("mitre_techniques") or raw_json.get("MitreTechniques") or raw_json.get("Technique")
    if isinstance(raw_techniques, list):
        mitre_techniques = [str(t).strip() for t in raw_techniques if str(t).strip()]
    elif isinstance(raw_techniques, str):
        # Extract technique IDs matching T[0-9]{4}(\.[0-9]{3})?
        found = re.findall(r"T\d{4}(?:\.\d{3})?", raw_techniques)
        mitre_techniques = found if found else [raw_techniques.strip()]

    mitre_tactic = str(raw_json.get("mitre_tactic") or raw_json.get("Tactic") or "Execution").strip()[:50]

    # 6. EDR Action Taken
    edr_action = (
        raw_json.get("edr_action")
        or raw_json.get("Action")
        or raw_json.get("status")
        or raw_json.get("remediation_status")
        or "Detected"
    )
    edr_action = str(edr_action).strip()[:50]

    # 7. Collect and Extract All IOCs (Hashes, IPs, Domains, URLs)
    corpus_parts = [
        alert_title,
        command_line[:10000],
        file_path[:1000],
        str(raw_json.get("description", ""))[:50000],
        str(raw_json.get("details", ""))[:50000],
    ]

    # Explicit hash inputs
    for h_field in ("sha256", "SHA256", "SHA256HashData", "md5", "MD5", "MD5HashData", "sha1", "SHA1", "hash"):
        if h_field in raw_json and isinstance(raw_json[h_field], str):
            corpus_parts.append(raw_json[h_field].strip()[:256])

    # Explicit network inputs
    for n_field in ("destination_ip", "dest_ip", "c2_ip", "RemoteIP", "domain", "url", "RemoteUrl"):
        if n_field in raw_json and isinstance(raw_json[n_field], str):
            corpus_parts.append(raw_json[n_field].strip()[:1000])

    # Explicit ioc list (capped to 500 items)
    explicit_iocs = raw_json.get("iocs") or raw_json.get("indicators") or []
    if isinstance(explicit_iocs, list):
        for item in explicit_iocs[:500]:
            if isinstance(item, str):
                corpus_parts.append(item[:1000])
            elif isinstance(item, dict):
                corpus_parts.append(str(item.get("value", ""))[:1000])

    full_corpus = "\n".join(corpus_parts)
    extracted = extract_iocs(full_corpus)

    return {
        "hostname": hostname,
        "host_ip": host_ip,
        "agent_id": agent_id,
        "os_platform": os_platform,
        "sensor_vendor": sensor_vendor,
        "alert_title": alert_title,
        "severity": severity,
        "process_name": process_name,
        "process_id": process_id,
        "parent_process": parent_process,
        "command_line": command_line,
        "file_path": file_path,
        "mitre_techniques": mitre_techniques,
        "mitre_tactic": mitre_tactic,
        "edr_action": edr_action,
        "extracted_iocs": extracted,
        "raw_description": str(raw_json.get("description", "")).strip(),
        "threat_name": str(raw_json.get("threat_name") or raw_json.get("malware_family") or "").strip(),
    }


def find_matching_malware(
    extracted_iocs: List[Dict[str, str]],
    threat_name: str = "",
) -> Optional[Malware]:
    """
    Correlate EDR alert artifacts against the TIP Malware database:
    1. By binary file hash match against existing ThreatIndicators linked to Malware.
    2. By matching threat / malware family name.
    """
    # 1. Match by hash indicator relationship
    hash_values = [
        item["value"].lower() for item in extracted_iocs
        if item.get("type") in ("sha256", "md5", "sha1")
    ]

    if hash_values:
        matched_indicator = ThreatIndicator.query.filter(
            func.lower(ThreatIndicator.indicator_value).in_(hash_values)
        ).first()

        if matched_indicator and matched_indicator.malwares:
            return matched_indicator.malwares[0]

    # 2. Match by threat / malware family name
    if threat_name:
        clean_name = threat_name.lower()
        matched = Malware.query.filter(
            or_(
                func.lower(Malware.malware_name).contains(clean_name),
                func.lower(Malware.malware_family).contains(clean_name)
            )
        ).first()
        if matched:
            return matched

    return None


def calculate_containment_action(
    max_risk_score: int,
    severity: str,
    hostname: str,
    process_name: str,
    process_id: Any,
    file_path: str,
    c2_destinations: List[str],
) -> Dict[str, Any]:
    """
    Determine automated endpoint containment and response recommendations:
    - CRITICAL / HIGH -> Network isolation + process termination + hash block
    - MEDIUM -> Process termination & file quarantine
    - LOW -> Monitor and investigate
    """
    is_critical = max_risk_score >= 75 or severity == "Critical"
    is_high = max_risk_score >= 50 or severity == "High"

    if is_critical:
        action = "ISOLATE_HOST"
        summary = f"CRITICAL incident on {hostname}. Immediate network isolation and host containment recommended."
        steps = [
            f"1. Isolate host '{hostname}' from internal network via EDR isolation command.",
            f"2. Terminate malicious process '{process_name}' (PID: {process_id}).",
            f"3. Quarantine malicious binary at '{file_path}'.",
            f"4. Block C2 communication to: {', '.join(c2_destinations[:5]) if c2_destinations else 'identified destinations'} on perimeter firewall.",
            f"5. Capture forensic memory dump and initiate incident response runbook."
        ]
    elif is_high:
        action = "KILL_PROCESS_AND_QUARANTINE"
        summary = f"HIGH threat activity on {hostname}. Process termination and binary quarantine recommended."
        steps = [
            f"1. Terminate suspicious process '{process_name}' (PID: {process_id}).",
            f"2. Quarantine binary at '{file_path}'.",
            f"3. Run full endpoint disk & memory antimalware scan.",
            f"4. Monitor host '{hostname}' for lateral movement attempts."
        ]
    else:
        action = "MONITOR_AND_INVESTIGATE"
        summary = f"Low/Medium anomaly on {hostname}. Retain telemetry and investigate if repeated."
        steps = [
            f"1. Verify legitimacy of execution for process '{process_name}'.",
            f"2. Inspect parent process and user login context.",
            f"3. Keep indicator under active observation."
        ]

    return {
        "containment_action": action,
        "is_containment_recommended": is_critical or is_high,
        "summary": summary,
        "remediation_steps": steps,
    }


def ingest_edr_alert(
    raw_payload: Dict[str, Any],
    actor_info: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """
    Process inbound EDR alert and synchronize across TIP modules:
    1. Normalizes EDR endpoint context (host, process, hash, command line, MITRE).
    2. Extracts, deduplicates, and saves ThreatIndicators.
    3. Runs deterministic Risk Scoring on all indicators.
    4. Correlates against Malware database records.
    5. Computes automated Host Containment recommendations.
    6. Creates prioritized EDR incident in Alert Center.
    7. Returns complete EDR intelligence response payload.
    """
    normalized = normalize_edr_payload(raw_payload)
    hostname = normalized["hostname"]
    host_ip = normalized["host_ip"]
    sensor_vendor = normalized["sensor_vendor"]
    alert_title = normalized["alert_title"]
    severity = normalized["severity"]
    process_name = normalized["process_name"]
    process_id = normalized["process_id"]
    command_line = normalized["command_line"]
    file_path = normalized["file_path"]
    mitre_techniques = normalized["mitre_techniques"]
    mitre_tactic = normalized["mitre_tactic"]
    edr_action = normalized["edr_action"]
    extracted = normalized["extracted_iocs"]
    threat_name = normalized["threat_name"]

    now = datetime.utcnow()

    # Determine acting user ID for ThreatIndicator.added_by_user_id foreign key
    system_user_id = None
    if actor_info and actor_info.get("id"):
        system_user_id = actor_info["id"]
    else:
        fallback_user = User.query.filter(User.role.in_(["admin", "analyst"])).first() or User.query.first()
        if fallback_user:
            system_user_id = fallback_user.id

    processed_indicators: List[Dict[str, Any]] = []
    c2_destinations: List[str] = []
    created_count = 0
    reused_count = 0
    max_risk_score = 0

    # 1. Ingest Extracted IOCs
    for item in extracted:
        ioc_type = (item.get("type") or "").strip().lower()
        val = (item.get("value") or "").strip()
        if not val or not ioc_type:
            continue

        if ioc_type in ("ipv4", "domain", "url"):
            c2_destinations.append(val)

        existing = ThreatIndicator.query.filter_by(
            indicator_value=val,
            indicator_type=ioc_type
        ).first()

        if existing:
            existing.last_seen_at = now
            existing.updated_at = now
            if existing.status == "Expired":
                existing.status = "Active"
                if system_user_id:
                    log_action(
                        user_id=system_user_id,
                        action="ioc_auto_revive_edr",
                        target_table="threat_indicators",
                        target_id=existing.id,
                    )
            indicator = existing
            is_created = False
            reused_count += 1
        else:
            indicator = ThreatIndicator(
                indicator_value=val,
                indicator_type=ioc_type,
                confidence_score=75,
                severity=severity,
                status="Active",
                source=f"EDR: {sensor_vendor} ({hostname})",
                first_seen_at=now,
                last_seen_at=now,
                created_at=now,
                updated_at=now,
                added_by_user_id=system_user_id,
                tlp_marking="WHITE",
                context=f"Process: {process_name} (PID {process_id}) on host {hostname}"
            )
            db.session.add(indicator)
            db.session.flush()
            is_created = True
            created_count += 1

        # Run deterministic risk scoring
        save_indicator_risk(indicator.id)
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

    # 2. Correlate with Malware Database
    matched_malware = find_matching_malware(extracted, threat_name)
    matched_malware_id = matched_malware.id if matched_malware else None
    matched_malware_name = matched_malware.malware_name if matched_malware else None

    # If matched malware, link newly ingested indicators to that malware record
    if matched_malware:
        for ind_info in processed_indicators:
            ind_obj = db.session.get(ThreatIndicator, ind_info["id"])
            if ind_obj and ind_obj not in matched_malware.indicators:
                matched_malware.indicators.append(ind_obj)

    # 3. Elevate incident severity based on max indicator risk score
    final_severity = severity
    if max_risk_score >= 75:
        final_severity = "Critical"
    elif max_risk_score >= 50 and severity in ("Low", "Medium"):
        final_severity = "High"

    # 4. Calculate Containment & Remediation Action
    containment = calculate_containment_action(
        max_risk_score=max_risk_score,
        severity=final_severity,
        hostname=hostname,
        process_name=process_name,
        process_id=process_id,
        file_path=file_path,
        c2_destinations=c2_destinations,
    )

    # 5. Create EDR Incident Alert in Alert Center
    first_indicator_id = processed_indicators[0]["id"] if processed_indicators else None
    mitre_summary = f"MITRE: {', '.join(mitre_techniques)} ({mitre_tactic})" if mitre_techniques else "MITRE: Unspecified"
    alert_title_formatted = f"[{sensor_vendor}] {alert_title} on {hostname}"[:200]
    
    alert_description = (
        f"EDR Host Incident on {hostname} (IP: {host_ip}, OS: {normalized['os_platform']}).\n"
        f"Process: {process_name} (PID: {process_id}, Parent: {normalized['parent_process']}).\n"
        f"Command Line: {command_line[:300] if command_line else 'N/A'}\n"
        f"Path: {file_path}\n"
        f"{mitre_summary}\n"
        f"EDR Sensor Action: {edr_action}\n"
        f"Matched Malware: {matched_malware_name or 'None'}\n"
        f"Recommended Action: {containment['containment_action']}\n"
        f"IOCs: {len(processed_indicators)} detected."
    )

    incident_alert, is_alert_new = get_or_create_alert(
        title=alert_title_formatted,
        alert_type="EDR",
        severity=final_severity,
        description=alert_description,
        indicator_id=first_indicator_id,
        malware_id=matched_malware_id,
        user_id=actor_info.get("id") if (actor_info and actor_info.get("type") == "user") else None
    )

    if system_user_id:
        log_action(
            user_id=system_user_id,
            action=f"edr_alert_ingest:{sensor_vendor}:{hostname}",
            target_table="alerts",
            target_id=incident_alert.id,
        )

    db.session.commit()

    return {
        "success": True,
        "message": "EDR alert analyzed and ingested successfully",
        "endpoint": {
            "hostname": hostname,
            "host_ip": host_ip,
            "os_platform": normalized["os_platform"],
            "agent_id": normalized["agent_id"],
            "sensor_vendor": sensor_vendor,
        },
        "execution": {
            "process_name": process_name,
            "process_id": process_id,
            "parent_process": normalized["parent_process"],
            "command_line": command_line,
            "file_path": file_path,
        },
        "mitre_attack": {
            "tactic": mitre_tactic,
            "techniques": mitre_techniques,
        },
        "alert": {
            "id": incident_alert.id,
            "title": incident_alert.title,
            "severity": incident_alert.severity,
            "status": incident_alert.status,
            "alert_type": incident_alert.alert_type,
            "created": is_alert_new,
        },
        "malware_correlation": {
            "matched": bool(matched_malware),
            "malware_id": matched_malware_id,
            "malware_name": matched_malware_name,
        },
        "containment": containment,
        "iocs": {
            "total_found": len(processed_indicators),
            "created": created_count,
            "reused": reused_count,
            "max_risk_score": max_risk_score,
            "indicators": processed_indicators,
        },
    }
