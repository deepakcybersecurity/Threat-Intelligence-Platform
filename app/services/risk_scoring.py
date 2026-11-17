"""
IOC Risk Scoring Engine
========================
Deterministic, explainable risk scoring service for Threat Indicators.

Combines:
- Severity (max 50)
- Confidence score (max 20)
- Relational correlation (max 20)
- Cached external enrichment (max 10)
- Recency / last_seen_at (max 5)
- Operational status (max 5)

Score normalization:
- Clamped between 0 and 100
- Risk levels:
    0–24   -> LOW
    25–49  -> MEDIUM
    50–74  -> HIGH
    75–100 -> CRITICAL

Guarantees:
- Purely deterministic, NO AI/ML
- Does NOT mutate confidence_score, severity, status, or source
- Zero external HTTP calls during scoring (relies exclusively on APICache)
- Zero automated alert creation
"""

from datetime import datetime
from typing import Dict, Any, Optional
from sqlalchemy.orm import selectinload

from app import db
from app.models.threat_indicator import ThreatIndicator
from app.models.threat_report import ThreatReport
from app.models.malware import Malware
from app.services.ioc_correlation import correlate_indicator
from app.services.ioc_enrichment import get_provider_for_type, _get_cached_enrichment


# Severity points mapping
SEVERITY_POINTS = {
    "Critical": 50,
    "High": 40,
    "Medium": 25,
    "Low": 10,
}


def get_risk_level(score: int) -> str:
    """
    Map normalized numeric risk score (0–100) to human-readable risk level:
    - 0–24   -> LOW
    - 25–49  -> MEDIUM
    - 50–74  -> HIGH
    - 75–100 -> CRITICAL
    """
    if score >= 75:
        return "CRITICAL"
    elif score >= 50:
        return "HIGH"
    elif score >= 25:
        return "MEDIUM"
    return "LOW"


def _calculate_severity_component(severity: Optional[str]) -> tuple[int, str]:
    """Map ThreatIndicator severity to points (max 50)."""
    if not severity:
        return 0, "No severity specified (+0)"

    norm_sev = severity.strip().capitalize()
    points = SEVERITY_POINTS.get(norm_sev, 0)
    explanation = f"{norm_sev} severity (+{points})"
    return points, explanation


def _calculate_confidence_component(confidence_score: Optional[int]) -> tuple[int, str]:
    """Convert confidence score (0–100) into weighted contribution (max 20)."""
    if confidence_score is None:
        confidence_score = 50

    clamped_conf = max(0, min(100, int(confidence_score)))
    points = int(round(clamped_conf * 0.20))
    explanation = f"Analyst confidence {clamped_conf}% weighted at 20% (+{points})"
    return points, explanation


def _calculate_correlation_component(indicator: ThreatIndicator) -> tuple[int, str]:
    """
    Calculate correlation contribution using Task 4 correlation engine (max 20).
    - Shared Threat Report = +5
    - Shared Malware = +10
    - Shared Threat Report + Shared Malware = +15
    """
    try:
        corr_data = correlate_indicator(indicator)
        related = corr_data.get("related_indicators", [])
    except Exception:
        return 0, "Correlation analysis unavailable (+0)"

    if not related:
        return 0, "No correlated threat entities (+0)"

    points = 0
    shared_report_count = 0
    shared_malware_count = 0

    for item in related:
        reason = item.get("relationship_reason", "")
        has_rep = "Threat Report" in reason
        has_mal = "Malware" in reason

        if has_rep and has_mal:
            points += 15
            shared_report_count += 1
            shared_malware_count += 1
        elif has_mal:
            points += 10
            shared_malware_count += 1
        elif has_rep:
            points += 5
            shared_report_count += 1

    clamped_points = min(20, points)
    reasons_summary = []
    if shared_report_count > 0:
        reasons_summary.append(f"{shared_report_count} shared report links")
    if shared_malware_count > 0:
        reasons_summary.append(f"{shared_malware_count} shared malware links")

    explanation = f"Correlated with {len(related)} IOCs ({', '.join(reasons_summary)}) (+{clamped_points})"
    return clamped_points, explanation


def _calculate_enrichment_component(indicator_value: str, indicator_type: str) -> tuple[int, str]:
    """
    Calculate external enrichment score from local APICache (max 10).
    Never performs live external network calls.
    """
    if not indicator_value or not indicator_type:
        return 0, "No enrichment available (+0)"

    clean_type = indicator_type.strip().lower()
    clean_val = indicator_value.strip()

    provider = get_provider_for_type(clean_type)
    if not provider:
        return 0, f"Unsupported enrichment type '{clean_type}' (+0)"

    cache_key = f"{clean_type}:{clean_val}"
    cached_data = _get_cached_enrichment(provider, cache_key)
    if not cached_data or not isinstance(cached_data, dict):
        return 0, "No cached enrichment intelligence (+0)"

    points = 0
    explanation = "No significant external threat signals (+0)"

    if provider == "AbuseIPDB":
        abuse_score = cached_data.get("abuse_confidence_score", 0)
        try:
            abuse_score = int(abuse_score)
        except (ValueError, TypeError):
            abuse_score = 0

        if abuse_score > 80:
            points = 10
            explanation = f"AbuseIPDB confidence {abuse_score}% > 80 (+10)"
        elif abuse_score >= 50:
            points = 7
            explanation = f"AbuseIPDB confidence {abuse_score}% (50–80) (+7)"
        elif abuse_score >= 20:
            points = 4
            explanation = f"AbuseIPDB confidence {abuse_score}% (20–49) (+4)"
        else:
            points = 0
            explanation = f"AbuseIPDB confidence {abuse_score}% < 20 (+0)"

    elif provider == "VirusTotal":
        malicious = cached_data.get("malicious_count", 0)
        suspicious = cached_data.get("suspicious_count", 0)
        harmless = cached_data.get("harmless_count", 0)
        undetected = cached_data.get("undetected_count", 0)

        try:
            malicious = int(malicious)
            suspicious = int(suspicious)
            total = malicious + suspicious + int(harmless) + int(undetected)
        except (ValueError, TypeError):
            malicious = 0
            suspicious = 0
            total = 0

        ratio = (malicious + suspicious) / total if total > 0 else 0.0

        if ratio >= 0.20 or malicious >= 10:
            points = 10
            explanation = f"VirusTotal high detections ({malicious} malicious vendors) (+10)"
        elif ratio >= 0.05 or malicious >= 3:
            points = 7
            explanation = f"VirusTotal medium detections ({malicious} malicious vendors) (+7)"
        elif malicious >= 1 or suspicious >= 1:
            points = 3
            explanation = f"VirusTotal low detections ({malicious} malicious vendors) (+3)"
        else:
            points = 0
            explanation = "VirusTotal zero malicious detections (+0)"

    elif provider == "AlienVault OTX":
        pulse_count = cached_data.get("pulse_count", 0)
        try:
            pulse_count = int(pulse_count)
        except (ValueError, TypeError):
            pulse_count = 0

        if pulse_count >= 10:
            points = 5
            explanation = f"AlienVault OTX high activity ({pulse_count} pulses) (+5)"
        elif pulse_count >= 1:
            points = 3
            explanation = f"AlienVault OTX moderate activity ({pulse_count} pulses) (+3)"
        else:
            points = 0
            explanation = "AlienVault OTX zero pulses (+0)"

    clamped_points = min(10, points)
    return clamped_points, explanation


def _calculate_recency_component(last_seen_at: Optional[datetime]) -> tuple[int, str]:
    """
    Calculate recency contribution from last_seen_at (max 5).
    - <= 7 days: +5
    - 8–30 days: +3
    - 31–90 days: +1
    - > 90 days or None: +0
    """
    if not last_seen_at:
        return 0, "No observation timestamp recorded (+0)"

    now = datetime.utcnow()
    delta_days = (now - last_seen_at).days

    if delta_days <= 7:
        return 5, f"Observed within last 7 days ({max(0, delta_days)}d ago) (+5)"
    elif delta_days <= 30:
        return 3, f"Observed within 8–30 days ({delta_days}d ago) (+3)"
    elif delta_days <= 90:
        return 1, f"Observed within 31–90 days ({delta_days}d ago) (+1)"
    else:
        return 0, f"Observed over 90 days ago ({delta_days}d ago) (+0)"


def _calculate_status_component(status: Optional[str]) -> tuple[int, str]:
    """
    Calculate status contribution (max 5).
    - Active: +5
    - Inactive / other: +0
    """
    if not status:
        return 0, "Status not specified (+0)"

    if status.strip().lower() == "active":
        return 5, "Status is Active (+5)"
    return 0, f"Status is {status} (+0)"


def calculate_indicator_risk(indicator: ThreatIndicator) -> Dict[str, Any]:
    """
    Deterministically calculate the risk score for a ThreatIndicator instance.
    Guarantees no modifications to indicator fields or external API calls.
    """
    if not indicator:
        return {
            "success": False,
            "indicator_id": None,
            "indicator": None,
            "risk_score": 0,
            "risk_level": "LOW",
            "breakdown": {
                "severity": 0,
                "confidence": 0,
                "correlation": 0,
                "enrichment": 0,
                "recency": 0,
                "status": 0
            },
            "explanation": {
                "severity": "N/A",
                "confidence": "N/A",
                "correlation": "N/A",
                "enrichment": "N/A",
                "recency": "N/A",
                "status": "N/A"
            },
            "error": "No indicator provided"
        }

    # 1. Severity Contribution (max 50)
    sev_points, sev_exp = _calculate_severity_component(getattr(indicator, "severity", None))

    # 2. Confidence Contribution (max 20)
    conf_points, conf_exp = _calculate_confidence_component(getattr(indicator, "confidence_score", None))

    # 3. Correlation Contribution (max 20)
    corr_points, corr_exp = _calculate_correlation_component(indicator)

    # 4. External Enrichment Contribution (max 10)
    val = getattr(indicator, "indicator_value", "")
    typ = getattr(indicator, "indicator_type", "")
    enrich_points, enrich_exp = _calculate_enrichment_component(val, typ)

    # 5. Recency Contribution (max 5)
    recency_points, recency_exp = _calculate_recency_component(getattr(indicator, "last_seen_at", None))

    # 6. Status Contribution (max 5)
    status_points, status_exp = _calculate_status_component(getattr(indicator, "status", None))

    # 7. Final Score (clamped 0–100)
    raw_score = sev_points + conf_points + corr_points + enrich_points + recency_points + status_points
    final_score = max(0, min(100, int(round(raw_score))))
    risk_level = get_risk_level(final_score)

    last_seen = getattr(indicator, "last_seen_at", None)

    return {
        "success": True,
        "indicator_id": getattr(indicator, "id", None),
        "indicator": {
            "id": getattr(indicator, "id", None),
            "value": val,
            "type": typ,
            "severity": getattr(indicator, "severity", None),
            "confidence_score": getattr(indicator, "confidence_score", None),
            "status": getattr(indicator, "status", None),
            "source": getattr(indicator, "source", None),
            "last_seen_at": last_seen.strftime("%Y-%m-%d %H:%M:%S") if last_seen else None
        },
        "risk_score": final_score,
        "risk_level": risk_level,
        "breakdown": {
            "severity": sev_points,
            "confidence": conf_points,
            "correlation": corr_points,
            "enrichment": enrich_points,
            "recency": recency_points,
            "status": status_points
        },
        "explanation": {
            "severity": sev_exp,
            "confidence": conf_exp,
            "correlation": corr_exp,
            "enrichment": enrich_exp,
            "recency": recency_exp,
            "status": status_exp
        },
        "error": None
    }


def calculate_indicator_risk_by_id(indicator_id: int) -> Dict[str, Any]:
    """
    Retrieve indicator by ID with eager loading and calculate its risk score.
    """
    if not indicator_id:
        return {
            "success": False,
            "indicator_id": None,
            "risk_score": 0,
            "risk_level": "LOW",
            "breakdown": {},
            "explanation": {},
            "error": "Invalid indicator ID provided"
        }

    indicator = (
        db.session.query(ThreatIndicator)
        .options(
            selectinload(ThreatIndicator.reports).selectinload(ThreatReport.indicators),
            selectinload(ThreatIndicator.malwares).selectinload(Malware.indicators)
        )
        .filter(ThreatIndicator.id == indicator_id)
        .first()
    )

    if not indicator:
        return {
            "success": False,
            "indicator_id": indicator_id,
            "risk_score": 0,
            "risk_level": "LOW",
            "breakdown": {},
            "explanation": {},
            "error": f"ThreatIndicator with ID {indicator_id} not found"
        }

    return calculate_indicator_risk(indicator)


def save_indicator_risk(indicator_id: int) -> Dict[str, Any]:
    """
    Explicitly calculate and persist the risk score into ThreatIndicator.risk_score.
    Automatically evaluates alert conditions and creates alerts if thresholds are met.
    """
    calc_result = calculate_indicator_risk_by_id(indicator_id)
    if not calc_result.get("success"):
        return calc_result

    indicator = ThreatIndicator.query.get(indicator_id)
    if indicator:
        indicator.risk_score = calc_result["risk_score"]
        db.session.commit()
        calc_result["saved"] = True

        # Automatically evaluate alert conditions and generate alerts
        # ONLY AFTER the database risk_score has been successfully committed/persisted.
        try:
            from app.services.alert_service import generate_indicator_alerts
            alerts = generate_indicator_alerts(indicator.id)
            calc_result["alerts_generated"] = len(alerts) if alerts else 0
        except Exception as e:
            import logging
            logger = logging.getLogger(__name__)
            logger.error(f"Error automatically generating alerts for indicator {indicator_id}: {str(e)}")
            calc_result["alerts_error"] = "Failed to evaluate alert conditions"
    else:
        calc_result["saved"] = False

    return calc_result
