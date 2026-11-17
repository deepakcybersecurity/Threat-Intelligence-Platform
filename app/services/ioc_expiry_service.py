"""
Automated IOC Expiry Service (Task 13)
=======================================
Manages the automated aging, lifecycle transition, and renewal of Indicators of
Compromise (IOCs) across the Threat Intelligence Platform.

Key Capabilities:
1. Type-Specific TTL Aging Policies:
   - IP / IPv4 / IPv6 : 30 days
   - Domain / Hostname : 60 days
   - URL               : 30 days
   - Hashes (MD5/SHA)  : 180 days
   - CVE Vulnerability : 365 days
   - Default / Fallback: 90 days
2. Indicator Expiry Evaluation & Transition (status: 'Active' -> 'Expired')
3. Dry-Run Simulation Mode (audit without database mutation)
4. Audit Trail Logging (action='ioc_auto_expire', target_table='threat_indicators')
5. One-Click & Bulk Indicator Reactivation (status: 'Expired' -> 'Active')
6. Automated Telemetry Revival (re-activating expired IOCs when freshly observed)
7. Approaching Expiry & Aging Statistics Queries
8. Recurring Background Thread Scheduler
"""

from datetime import datetime, timezone, timedelta
import logging
import threading
import time
from typing import Any, Dict, List, Optional, Tuple, Union

from sqlalchemy import func, or_

from app import db
from app.models import ThreatIndicator, AuditLog, User
from app.services.audit_service import log_action

logger = logging.getLogger(__name__)

# Standard Type-Specific TTL Policies (in days)
DEFAULT_TTL_POLICIES: Dict[str, int] = {
    "ip": 30,
    "ipv4": 30,
    "ipv6": 30,
    "domain": 60,
    "hostname": 60,
    "url": 30,
    "md5": 180,
    "sha1": 180,
    "sha256": 180,
    "hash": 180,
    "cve": 365,
}

DEFAULT_FALLBACK_TTL_DAYS: int = 90


def get_ttl_for_type(indicator_type: str, custom_policies: Optional[Dict[str, int]] = None) -> int:
    """
    Resolve the Time-To-Live (TTL) in days for a specific indicator type.
    Checks custom policies first, then built-in defaults, falling back to 90 days.
    """
    if not indicator_type:
        return DEFAULT_FALLBACK_TTL_DAYS

    norm_type = indicator_type.strip().lower()

    if custom_policies and norm_type in custom_policies:
        try:
            return max(1, int(custom_policies[norm_type]))
        except (ValueError, TypeError):
            pass

    if norm_type in DEFAULT_TTL_POLICIES:
        return DEFAULT_TTL_POLICIES[norm_type]

    return DEFAULT_FALLBACK_TTL_DAYS


def _get_system_user_id(preferred_user_id: Optional[int] = None) -> int:
    """
    Resolve a valid user ID for AuditLog foreign key requirement.
    Falls back to first admin/analyst or any User row.
    """
    if preferred_user_id:
        return preferred_user_id

    fallback_user = (
        User.query.filter(User.role.in_(["admin", "analyst"])).first()
        or User.query.first()
    )
    return fallback_user.id if fallback_user else 1


def calculate_indicator_age_days(indicator: ThreatIndicator, now_utc: Optional[datetime] = None) -> float:
    """
    Calculate the elapsed age of an indicator in fractional days based on
    the most recent effective timestamp (last_seen_at or created_at).
    """
    if now_utc is None:
        now_utc = datetime.now(timezone.utc)

    effective_dt = indicator.last_seen_at or indicator.created_at or now_utc

    # Normalize to timezone-aware UTC if naive
    if effective_dt.tzinfo is None:
        effective_dt = effective_dt.replace(tzinfo=timezone.utc)

    delta = now_utc - effective_dt
    return max(0.0, delta.total_seconds() / 86400.0)


def evaluate_and_expire_iocs(
    ttl_policies: Optional[Dict[str, int]] = None,
    dry_run: bool = False,
    user_id: Optional[int] = None,
    filter_type: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Scan all Active threat indicators, evaluate their age against type-specific TTLs,
    and transition aged indicators from 'Active' to 'Expired'.

    Parameters:
    -----------
    ttl_policies : Optional dict mapping indicator types to TTL days.
    dry_run      : If True, identifies expiring indicators without database writes.
    user_id      : User ID credited for audit logging.
    filter_type  : Optional filter to restrict expiration to a specific indicator type.

    Returns:
    --------
    Dict containing execution summary, expired indicators count, and detailed records.
    """
    now_utc = datetime.now(timezone.utc)
    naive_now = datetime.utcnow()

    # Query all active indicators
    query = ThreatIndicator.query.filter(ThreatIndicator.status == "Active")

    if filter_type and filter_type.strip().lower() != "all":
        norm_filter = filter_type.strip().lower()
        if norm_filter in ("ip", "ipv4"):
            query = query.filter(func.lower(ThreatIndicator.indicator_type).in_(["ip", "ipv4"]))
        elif norm_filter == "hash":
            query = query.filter(func.lower(ThreatIndicator.indicator_type).in_(["md5", "sha1", "sha256"]))
        else:
            query = query.filter(func.lower(ThreatIndicator.indicator_type) == norm_filter)

    active_indicators = query.all()
    total_evaluated = len(active_indicators)

    expiring_indicators: List[ThreatIndicator] = []
    expired_details: List[Dict[str, Any]] = []
    type_counts: Dict[str, int] = {}

    for ind in active_indicators:
        ttl_days = get_ttl_for_type(ind.indicator_type, ttl_policies)
        age_days = calculate_indicator_age_days(ind, now_utc)

        if age_days >= ttl_days:
            expiring_indicators.append(ind)
            t_key = (ind.indicator_type or "unknown").lower()
            type_counts[t_key] = type_counts.get(t_key, 0) + 1

            expired_details.append({
                "id": ind.id,
                "value": ind.indicator_value,
                "type": ind.indicator_type,
                "severity": ind.severity,
                "confidence_score": ind.confidence_score,
                "age_days": round(age_days, 1),
                "ttl_days": ttl_days,
                "last_seen_at": (ind.last_seen_at or ind.created_at).isoformat() if (ind.last_seen_at or ind.created_at) else None,
            })

    if not dry_run and expiring_indicators:
        acting_user_id = _get_system_user_id(user_id)

        for ind in expiring_indicators:
            ind.status = "Expired"
            ind.updated_at = naive_now

            log_action(
                user_id=acting_user_id,
                action="ioc_auto_expire",
                target_table="threat_indicators",
                target_id=ind.id,
            )

        db.session.commit()
        logger.info(
            "Automated IOC Expiry completed: %d indicators expired out of %d evaluated.",
            len(expiring_indicators),
            total_evaluated,
        )

    return {
        "success": True,
        "dry_run": dry_run,
        "evaluated_count": total_evaluated,
        "expired_count": len(expiring_indicators),
        "breakdown_by_type": type_counts,
        "expired_indicators": expired_details,
        "timestamp": now_utc.isoformat(),
    }


def reactivate_indicator(
    indicator_id: int,
    user_id: Optional[int] = None,
    reason: str = "Manual Analyst Reactivation",
) -> Dict[str, Any]:
    """
    Reactivate a previously Expired or Inactive indicator back to 'Active',
    resetting its last_seen_at timestamp to now and recording an audit log entry.
    """
    indicator = db.session.get(ThreatIndicator, indicator_id)
    if not indicator:
        return {
            "success": False,
            "error": "NotFound",
            "message": f"ThreatIndicator ID {indicator_id} does not exist.",
        }

    now = datetime.utcnow()
    old_status = indicator.status
    indicator.status = "Active"
    indicator.last_seen_at = now
    indicator.updated_at = now

    acting_user_id = _get_system_user_id(user_id or indicator.added_by_user_id)

    log_action(
        user_id=acting_user_id,
        action=f"ioc_reactivate:{old_status}->Active",
        target_table="threat_indicators",
        target_id=indicator.id,
    )

    db.session.commit()

    return {
        "success": True,
        "message": f"Indicator '{indicator.indicator_value}' successfully reactivated.",
        "indicator": {
            "id": indicator.id,
            "value": indicator.indicator_value,
            "type": indicator.indicator_type,
            "status": indicator.status,
            "severity": indicator.severity,
            "last_seen_at": indicator.last_seen_at.isoformat() if indicator.last_seen_at else None,
        },
    }


def bulk_reactivate_indicators(
    indicator_ids: List[int],
    user_id: Optional[int] = None,
    reason: str = "Bulk Analyst Reactivation",
) -> Dict[str, Any]:
    """
    Reactivate multiple indicators back to 'Active' in a single transaction.
    """
    if not indicator_ids:
        return {
            "success": True,
            "reactivated_count": 0,
            "message": "No indicator IDs provided.",
            "reactivated_ids": [],
        }

    indicators = ThreatIndicator.query.filter(ThreatIndicator.id.in_(indicator_ids)).all()
    if not indicators:
        return {
            "success": False,
            "error": "NotFound",
            "message": "None of the specified indicators were found.",
            "reactivated_count": 0,
        }

    now = datetime.utcnow()
    acting_user_id = _get_system_user_id(user_id)
    reactivated_ids: List[int] = []

    for ind in indicators:
        ind.status = "Active"
        ind.last_seen_at = now
        ind.updated_at = now
        reactivated_ids.append(ind.id)

        log_action(
            user_id=acting_user_id,
            action="ioc_reactivate:bulk",
            target_table="threat_indicators",
            target_id=ind.id,
        )

    db.session.commit()

    return {
        "success": True,
        "message": f"Successfully reactivated {len(reactivated_ids)} indicators.",
        "reactivated_count": len(reactivated_ids),
        "reactivated_ids": reactivated_ids,
    }


def auto_revive_on_telemetry(
    indicator_value: str,
    user_id: Optional[int] = None,
) -> Optional[ThreatIndicator]:
    """
    When telemetry, reports, or EDR alerts re-observe an indicator:
    If the indicator currently has status='Expired', automatically revive it
    to 'Active', refresh last_seen_at, and record an audit log.
    Returns the refreshed ThreatIndicator instance, or None if not found.
    """
    if not indicator_value:
        return None

    norm_val = indicator_value.strip()
    indicator = ThreatIndicator.query.filter(
        func.lower(ThreatIndicator.indicator_value) == norm_val.lower()
    ).first()

    if not indicator:
        return None

    now = datetime.utcnow()
    indicator.last_seen_at = now
    indicator.updated_at = now

    if indicator.status == "Expired":
        indicator.status = "Active"
        acting_user_id = _get_system_user_id(user_id or indicator.added_by_user_id)
        log_action(
            user_id=acting_user_id,
            action="ioc_auto_revive_telemetry",
            target_table="threat_indicators",
            target_id=indicator.id,
        )

    db.session.commit()
    return indicator


def get_expiring_soon_indicators(
    days_threshold: int = 7,
    limit: int = 50,
    ttl_policies: Optional[Dict[str, int]] = None,
) -> List[Dict[str, Any]]:
    """
    Retrieve Active indicators that are nearing their TTL expiration
    within the next `days_threshold` days (default 7 days).
    """
    now_utc = datetime.now(timezone.utc)
    active_indicators = ThreatIndicator.query.filter(ThreatIndicator.status == "Active").all()

    expiring_soon: List[Dict[str, Any]] = []

    for ind in active_indicators:
        ttl = get_ttl_for_type(ind.indicator_type, ttl_policies)
        age_days = calculate_indicator_age_days(ind, now_utc)
        days_remaining = ttl - age_days

        # Approaching expiry: not yet expired, but expires within threshold
        if 0 < days_remaining <= days_threshold:
            effective_dt = ind.last_seen_at or ind.created_at or now_utc
            if effective_dt.tzinfo is None:
                effective_dt = effective_dt.replace(tzinfo=timezone.utc)

            expiry_dt = effective_dt + timedelta(days=ttl)

            expiring_soon.append({
                "id": ind.id,
                "value": ind.indicator_value,
                "type": ind.indicator_type,
                "severity": ind.severity,
                "confidence_score": ind.confidence_score,
                "age_days": round(age_days, 1),
                "ttl_days": ttl,
                "days_remaining": round(days_remaining, 1),
                "estimated_expiry": expiry_dt.strftime("%Y-%m-%d %H:%M:%S UTC"),
            })

    # Sort by nearest to expiry first
    expiring_soon.sort(key=lambda x: x["days_remaining"])
    return expiring_soon[:limit]


def get_expiry_statistics(ttl_policies: Optional[Dict[str, int]] = None) -> Dict[str, Any]:
    """
    Generate comprehensive IOC lifecycle, aging, and expiration statistics
    across the entire database.
    """
    total_count = ThreatIndicator.query.count()
    active_count = ThreatIndicator.query.filter(ThreatIndicator.status == "Active").count()
    expired_count = ThreatIndicator.query.filter(ThreatIndicator.status == "Expired").count()
    inactive_count = ThreatIndicator.query.filter(ThreatIndicator.status == "Inactive").count()
    fp_count = ThreatIndicator.query.filter(ThreatIndicator.status == "False Positive").count()

    expiring_soon_count = len(get_expiring_soon_indicators(days_threshold=7, limit=10000, ttl_policies=ttl_policies))

    # Breakdown by indicator type: counts of Active vs Expired
    types_query = db.session.query(
        func.lower(ThreatIndicator.indicator_type).label("type_name"),
        ThreatIndicator.status,
        func.count(ThreatIndicator.id)
    ).group_by(func.lower(ThreatIndicator.indicator_type), ThreatIndicator.status).all()

    type_summary: Dict[str, Dict[str, int]] = {}
    for t_name, status, count in types_query:
        if not t_name:
            t_name = "unknown"
        if t_name not in type_summary:
            type_summary[t_name] = {"active": 0, "expired": 0, "other": 0, "ttl_days": get_ttl_for_type(t_name, ttl_policies)}
        if status == "Active":
            type_summary[t_name]["active"] += count
        elif status == "Expired":
            type_summary[t_name]["expired"] += count
        else:
            type_summary[t_name]["other"] += count

    return {
        "total_indicators": total_count,
        "active_indicators": active_count,
        "expired_indicators": expired_count,
        "inactive_indicators": inactive_count,
        "false_positive_indicators": fp_count,
        "expiring_soon_7d": expiring_soon_count,
        "type_summary": type_summary,
        "policies": ttl_policies or DEFAULT_TTL_POLICIES,
    }


# -----------------------------------------------------------------------------
# Background Scheduler
# -----------------------------------------------------------------------------
_scheduler_thread: Optional[threading.Thread] = None
_scheduler_running: bool = False


def _expiry_worker_loop(app, interval_seconds: int):
    """Background worker daemon thread that runs evaluate_and_expire_iocs periodically."""
    global _scheduler_running
    logger.info("IOC Expiry Background Scheduler thread started (interval: %d s).", interval_seconds)

    while _scheduler_running:
        try:
            with app.app_context():
                res = evaluate_and_expire_iocs(dry_run=False)
                if res.get("expired_count", 0) > 0:
                    logger.info("Scheduler expired %d aged IOCs.", res["expired_count"])
        except Exception as exc:
            logger.error("Error in IOC Expiry scheduler loop: %s", exc, exc_info=True)

        # Sleep in small increments so shutdown is prompt
        for _ in range(int(interval_seconds)):
            if not _scheduler_running:
                break
            time.sleep(1)

    logger.info("IOC Expiry Background Scheduler thread stopped.")


def start_ioc_expiry_scheduler(app, interval_hours: int = 24) -> bool:
    """
    Start the background recurring IOC Expiry scheduler daemon.
    """
    global _scheduler_thread, _scheduler_running
    if _scheduler_running and _scheduler_thread and _scheduler_thread.is_alive():
        logger.info("IOC Expiry Scheduler is already running.")
        return False

    _scheduler_running = True
    interval_seconds = max(60, int(interval_hours * 3600))
    _scheduler_thread = threading.Thread(
        target=_expiry_worker_loop,
        args=(app, interval_seconds),
        daemon=True,
        name="IOCExpiryScheduler",
    )
    _scheduler_thread.start()
    return True


def stop_ioc_expiry_scheduler():
    """Stop the background recurring IOC Expiry scheduler."""
    global _scheduler_running
    _scheduler_running = False
