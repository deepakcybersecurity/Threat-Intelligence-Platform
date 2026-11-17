"""
Alert Service
=============
Manages security alerts lifecycle, deterministic rule-based alert generation,
deduplication, search, and filtering for the Threat Intelligence Platform.

Alert Lifecycle:
- Open (New / Active)
- In Progress (Acknowledged / Under Investigation)
- Resolved (Mitigated)
- Closed (Archived)
- is_read (Read / Unread tracking)

Guarantees:
- Zero AI/ML.
- Zero live external API calls during alert generation.
- Strict deduplication: identical unresolved alerts are never duplicated.
- Validated state transitions.
- Preserves ThreatIndicator, Malware, and User relationships.
"""

from datetime import datetime
from typing import Optional, List, Tuple, Dict, Any
from sqlalchemy import or_, and_
from sqlalchemy.orm import selectinload

from app import db
from app.models.alert import Alert
from app.models.threat_indicator import ThreatIndicator
from app.models.malware import Malware
from app.models.api_cache import APICache
from app.services.risk_scoring import calculate_indicator_risk_by_id, get_risk_level
from app.services.ioc_correlation import correlate_indicator_by_id
from app.services.ioc_enrichment import get_provider_for_type, _get_cached_enrichment

VALID_SEVERITIES = {"Low", "Medium", "High", "Critical"}
VALID_STATUSES = {"Open", "In Progress", "Resolved", "Closed"}


def create_alert(
    title: str,
    description: Optional[str] = None,
    severity: str = "Medium",
    alert_type: str = "General",
    status: str = "Open",
    indicator_id: Optional[int] = None,
    malware_id: Optional[int] = None,
    user_id: Optional[int] = None,
    is_read: bool = False
) -> Alert:
    """
    Create and persist a new Alert record using SQLAlchemy ORM.
    """
    if not title:
        raise ValueError("Alert title is required.")

    norm_sev = severity.strip().capitalize()
    if norm_sev not in VALID_SEVERITIES:
        norm_sev = "Medium"

    norm_stat = status.strip().title()
    if norm_stat not in VALID_STATUSES:
        norm_stat = "Open"

    alert = Alert(
        title=title.strip(),
        description=description.strip() if description else None,
        severity=norm_sev,
        status=norm_stat,
        alert_type=alert_type.strip() if alert_type else "General",
        indicator_id=indicator_id,
        malware_id=malware_id,
        user_id=user_id,
        is_read=is_read,
        created_at=datetime.utcnow(),
        updated_at=datetime.utcnow()
    )
    db.session.add(alert)
    db.session.commit()
    return alert


def get_or_create_alert(
    title: str,
    alert_type: str,
    severity: str = "Medium",
    description: Optional[str] = None,
    indicator_id: Optional[int] = None,
    malware_id: Optional[int] = None,
    user_id: Optional[int] = None
) -> Tuple[Alert, bool]:
    """
    Retrieve existing unresolved alert matching the entity and alert type,
    or create a new one. Prevents duplicate alerts.
    
    Returns:
        (Alert, created_bool)
    """
    query = Alert.query.filter(
        Alert.status.in_(["Open", "In Progress"]),
        Alert.alert_type == alert_type
    )

    if indicator_id is not None:
        query = query.filter(Alert.indicator_id == indicator_id)
    elif malware_id is not None:
        query = query.filter(Alert.malware_id == malware_id)
    else:
        query = query.filter(Alert.title == title)

    existing = query.first()
    if existing:
        return existing, False

    new_alert = create_alert(
        title=title,
        description=description,
        severity=severity,
        alert_type=alert_type,
        status="Open",
        indicator_id=indicator_id,
        malware_id=malware_id,
        user_id=user_id,
        is_read=False
    )
    return new_alert, True


def generate_risk_alert(indicator_id: int) -> Optional[Alert]:
    """
    Generate an alert based on Task 5 IOC Risk Scoring.
    - Critical Risk (75–100) -> Critical severity alert
    - High Risk (50–74)      -> High severity alert
    - Medium / Low           -> No alert
    """
    indicator = ThreatIndicator.query.get(indicator_id)
    if not indicator:
        return None

    try:
        risk_res = calculate_indicator_risk_by_id(indicator_id)
    except Exception:
        risk_res = None

    if indicator.risk_score is not None:
        score = indicator.risk_score
        bd = risk_res.get("breakdown", {}) if (risk_res and risk_res.get("success")) else {}
    elif risk_res and risk_res.get("success"):
        score = risk_res.get("risk_score", 0)
        bd = risk_res.get("breakdown", {})
    else:
        return None

    level = get_risk_level(score)

    if level == "CRITICAL":
        sev = "Critical"
        title = f"CRITICAL Risk IOC: {indicator.indicator_value}"
        desc = (
            f"Threat indicator {indicator.indicator_value} ({indicator.indicator_type}) "
            f"has reached a CRITICAL risk score of {score}/100. "
            f"Breakdown: Severity +{bd.get('severity', 0)}, Confidence +{bd.get('confidence', 0)}, "
            f"Correlation +{bd.get('correlation', 0)}, Enrichment +{bd.get('enrichment', 0)}, "
            f"Recency +{bd.get('recency', 0)}, Status +{bd.get('status', 0)}."
        )
        alert, created = get_or_create_alert(
            title=title,
            alert_type="Risk Score",
            severity=sev,
            description=desc,
            indicator_id=indicator.id
        )
        return alert

    elif level == "HIGH":
        sev = "High"
        title = f"High Risk IOC: {indicator.indicator_value}"
        desc = (
            f"Threat indicator {indicator.indicator_value} ({indicator.indicator_type}) "
            f"has reached a HIGH risk score of {score}/100. "
            f"Breakdown: Severity +{bd.get('severity', 0)}, Confidence +{bd.get('confidence', 0)}, "
            f"Correlation +{bd.get('correlation', 0)}, Enrichment +{bd.get('enrichment', 0)}, "
            f"Recency +{bd.get('recency', 0)}, Status +{bd.get('status', 0)}."
        )
        alert, created = get_or_create_alert(
            title=title,
            alert_type="Risk Score",
            severity=sev,
            description=desc,
            indicator_id=indicator.id
        )
        return alert

    return None


def generate_enrichment_alert(indicator_id: int) -> Optional[Alert]:
    """
    Generate an alert based on Task 3 cached external enrichment intelligence.
    Zero external HTTP calls.
    """
    indicator = ThreatIndicator.query.get(indicator_id)
    if not indicator:
        return None

    clean_type = indicator.indicator_type.strip().lower() if indicator.indicator_type else ""
    clean_val = indicator.indicator_value.strip() if indicator.indicator_value else ""

    provider = get_provider_for_type(clean_type)
    if not provider:
        return None

    cache_key = f"{clean_type}:{clean_val}"
    cached_data = _get_cached_enrichment(provider, cache_key)
    if not cached_data or not isinstance(cached_data, dict):
        return None

    if provider == "AbuseIPDB":
        abuse_score = cached_data.get("abuse_confidence_score", 0)
        total_reports = cached_data.get("total_reports", 0)
        try:
            abuse_score = int(abuse_score)
        except (ValueError, TypeError):
            abuse_score = 0

        if abuse_score >= 80:
            sev = "Critical" if abuse_score >= 95 else "High"
            title = f"High Abuse Confidence IP: {clean_val}"
            desc = (
                f"AbuseIPDB intelligence flagged IP {clean_val} with an abuse confidence score "
                f"of {abuse_score}% across {total_reports} reports. Country: {cached_data.get('country_name') or 'N/A'}, "
                f"ISP: {cached_data.get('isp') or 'N/A'}, Tor: {cached_data.get('is_tor', False)}."
            )
            alert, created = get_or_create_alert(
                title=title,
                alert_type="Enrichment",
                severity=sev,
                description=desc,
                indicator_id=indicator.id
            )
            return alert

    elif provider == "VirusTotal":
        malicious = cached_data.get("malicious_count", 0)
        suspicious = cached_data.get("suspicious_count", 0)
        try:
            malicious = int(malicious)
            suspicious = int(suspicious)
        except (ValueError, TypeError):
            malicious = 0
            suspicious = 0

        if malicious >= 5 or (malicious >= 1 and suspicious >= 2):
            sev = "Critical" if malicious >= 15 else "High"
            title = f"Malicious Binary Hash: {clean_val[:16]}..."
            desc = (
                f"VirusTotal intelligence flagged file hash {clean_val} with {malicious} malicious "
                f"vendor detections and {suspicious} suspicious detections. Meaningful name: {cached_data.get('meaningful_name') or 'N/A'}."
            )
            alert, created = get_or_create_alert(
                title=title,
                alert_type="Enrichment",
                severity=sev,
                description=desc,
                indicator_id=indicator.id
            )
            return alert

    elif provider == "AlienVault OTX":
        pulse_count = cached_data.get("pulse_count", 0)
        try:
            pulse_count = int(pulse_count)
        except (ValueError, TypeError):
            pulse_count = 0

        if pulse_count >= 5:
            sev = "Critical" if pulse_count >= 20 else "High"
            title = f"Threat Pulse Association: {clean_val}"
            desc = (
                f"AlienVault OTX associates indicator {clean_val} with {pulse_count} active threat pulses. "
                f"Threat actor campaigns and IOC associations are active."
            )
            alert, created = get_or_create_alert(
                title=title,
                alert_type="Enrichment",
                severity=sev,
                description=desc,
                indicator_id=indicator.id
            )
            return alert

    return None


def generate_correlation_alert(indicator_id: int) -> Optional[Alert]:
    """
    Generate an alert based on Task 4 IOC Correlation relationships.
    - Linked Malware
    - Multi-campaign co-occurrence (>= 3 reports or >= 3 connected IOCs)
    """
    indicator = ThreatIndicator.query.get(indicator_id)
    if not indicator:
        return None

    try:
        corr_data = correlate_indicator_by_id(indicator_id)
    except Exception:
        return None

    if not corr_data or not corr_data.get("success"):
        return None

    malwares = corr_data.get("malware", [])
    reports = corr_data.get("reports", [])
    related = corr_data.get("related_indicators", [])

    if malwares:
        first_mal = malwares[0]
        mal_names = ", ".join(m.get("name", "Unknown") for m in malwares)
        sev = "Critical" if len(malwares) > 1 else "High"
        title = f"IOC Linked to Malware: {indicator.indicator_value}"
        desc = (
            f"Indicator {indicator.indicator_value} ({indicator.indicator_type}) is directly correlated "
            f"with {len(malwares)} malware record(s): {mal_names}."
        )
        alert, created = get_or_create_alert(
            title=title,
            alert_type="Correlation",
            severity=sev,
            description=desc,
            indicator_id=indicator.id,
            malware_id=first_mal.get("id")
        )
        return alert

    elif len(reports) >= 3 or len(related) >= 3:
        sev = "High"
        title = f"Multi-Campaign Correlated IOC: {indicator.indicator_value}"
        desc = (
            f"Indicator {indicator.indicator_value} co-occurs across {len(reports)} threat reports "
            f"and connects with {len(related)} related indicators in active threat intelligence graph."
        )
        alert, created = get_or_create_alert(
            title=title,
            alert_type="Correlation",
            severity=sev,
            description=desc,
            indicator_id=indicator.id
        )
        return alert

    return None


def generate_indicator_alerts(indicator_id: int) -> List[Alert]:
    """
    Evaluate an indicator across Risk, Enrichment, and Correlation rules.
    Returns any active alerts (new or deduplicated existing).
    """
    alerts = []
    r_alert = generate_risk_alert(indicator_id)
    if r_alert:
        alerts.append(r_alert)

    e_alert = generate_enrichment_alert(indicator_id)
    if e_alert:
        alerts.append(e_alert)

    c_alert = generate_correlation_alert(indicator_id)
    if c_alert:
        alerts.append(c_alert)

    return alerts


# -------------------------------------------------------------------------
# Lifecycle Transition Functions
# -------------------------------------------------------------------------
def mark_alert_read(alert_id: int, user: Optional[Any] = None) -> Alert:
    """Mark alert as read (is_read=True). Valid in any state."""
    alert = Alert.query.get(alert_id)
    if not alert:
        raise ValueError(f"Alert with ID {alert_id} not found.")

    alert.is_read = True
    alert.updated_at = datetime.utcnow()
    db.session.commit()
    return alert


def acknowledge_alert(alert_id: int, user: Optional[Any] = None) -> Alert:
    """
    Acknowledge alert. Transitions status: Open -> In Progress.
    Valid only when current status is Open (or already In Progress).
    """
    alert = Alert.query.get(alert_id)
    if not alert:
        raise ValueError(f"Alert with ID {alert_id} not found.")

    if alert.status in ("Resolved", "Closed"):
        raise ValueError(f"Cannot acknowledge alert in '{alert.status}' state.")

    alert.status = "In Progress"
    alert.is_read = True
    alert.updated_at = datetime.utcnow()
    if user and hasattr(user, "id"):
        alert.user_id = user.id

    db.session.commit()
    return alert


def resolve_alert(alert_id: int, user: Optional[Any] = None) -> Alert:
    """
    Resolve alert. Transitions status: Open / In Progress -> Resolved.
    Valid only when current status is Open or In Progress.
    """
    alert = Alert.query.get(alert_id)
    if not alert:
        raise ValueError(f"Alert with ID {alert_id} not found.")

    if alert.status == "Closed":
        raise ValueError("Cannot resolve an already closed alert.")

    alert.status = "Resolved"
    alert.is_read = True
    alert.updated_at = datetime.utcnow()
    db.session.commit()
    return alert


def reopen_alert(alert_id: int, user: Optional[Any] = None) -> Alert:
    """
    Reopen alert. Transitions status: Resolved / Closed -> Open.
    Valid only when current status is Resolved or Closed.
    """
    alert = Alert.query.get(alert_id)
    if not alert:
        raise ValueError(f"Alert with ID {alert_id} not found.")

    if alert.status in ("Open", "In Progress"):
        raise ValueError(f"Alert is already active ('{alert.status}').")

    alert.status = "Open"
    alert.is_read = False
    alert.updated_at = datetime.utcnow()
    db.session.commit()
    return alert


def close_alert(alert_id: int, user: Optional[Any] = None) -> Alert:
    """
    Close alert. Transitions status: Resolved -> Closed.
    """
    alert = Alert.query.get(alert_id)
    if not alert:
        raise ValueError(f"Alert with ID {alert_id} not found.")

    alert.status = "Closed"
    alert.updated_at = datetime.utcnow()
    db.session.commit()
    return alert


# -------------------------------------------------------------------------
# Search and Filter Queries
# -------------------------------------------------------------------------
def get_alerts_filtered(
    query_text: Optional[str] = None,
    severity: Optional[str] = None,
    status: Optional[str] = None,
    alert_type: Optional[str] = None,
    limit: Optional[int] = None,
    offset: Optional[int] = None
) -> List[Alert]:
    """
    Filter and search alerts using SQLAlchemy ORM with eager loading.
    """
    query = Alert.query.options(
        selectinload(Alert.indicator),
        selectinload(Alert.malware),
        selectinload(Alert.user)
    )

    if query_text:
        term = f"%{query_text.strip()}%"
        query = query.outerjoin(Alert.indicator).filter(
            or_(
                Alert.title.ilike(term),
                Alert.description.ilike(term),
                Alert.alert_type.ilike(term),
                ThreatIndicator.indicator_value.ilike(term)
            )
        )

    if severity and severity.strip().lower() != "all":
        query = query.filter(Alert.severity == severity.strip().capitalize())

    if status and status.strip().lower() != "all":
        norm_stat = status.strip().lower()
        if norm_stat == "active":
            query = query.filter(Alert.status.in_(["Open", "In Progress"]))
        else:
            query = query.filter(Alert.status == status.strip().title())

    if alert_type and alert_type.strip().lower() != "all":
        query = query.filter(Alert.alert_type == alert_type.strip())

    query = query.order_by(Alert.created_at.desc())

    if limit is not None:
        query = query.limit(limit)
    if offset is not None:
        query = query.offset(offset)

    return query.all()


def get_alert_counts() -> Dict[str, int]:
    """
    Get aggregated alert statistics efficiently.
    """
    total = Alert.query.count()
    critical = Alert.query.filter_by(severity="Critical").count()
    high = Alert.query.filter_by(severity="High").count()
    medium = Alert.query.filter_by(severity="Medium").count()
    low = Alert.query.filter_by(severity="Low").count()

    open_cnt = Alert.query.filter_by(status="Open").count()
    in_prog = Alert.query.filter_by(status="In Progress").count()
    resolved = Alert.query.filter_by(status="Resolved").count()
    closed = Alert.query.filter_by(status="Closed").count()

    unread = Alert.query.filter_by(is_read=False).count()
    active = open_cnt + in_prog

    return {
        "total": total,
        "critical": critical,
        "high": high,
        "medium": medium,
        "low": low,
        "open": open_cnt,
        "in_progress": in_prog,
        "resolved": resolved,
        "closed": closed,
        "active": active,
        "unread": unread
    }
