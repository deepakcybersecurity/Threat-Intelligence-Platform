"""
Audit Service — Task 10: Audit Logging & Remediation G-5 / G-7
Writes AuditLog entries for sensitive actions, provides search, filtering,
pagination, and CSV export capabilities.
All functions are safe to call inside an existing DB transaction.
"""

import csv
from datetime import datetime, timedelta
import io
import logging
import math
from typing import Any
from flask import request as flask_request
from sqlalchemy import or_
from app import db
from app.models.audit_log import AuditLog
from app.models.user import User

logger = logging.getLogger(__name__)


def log_action(
    user_id: int,
    action: str,
    target_table: str,
    target_id: int | None = None,
    ip_address: str | None = None,
) -> AuditLog | None:
    """
    Write an audit log entry.

    Parameters
    ----------
    user_id     : ID of the user performing the action
    action      : Human-readable verb, e.g. "update_role", "suspend_user"
    target_table: DB table name of the affected object, e.g. "users"
    target_id   : PK of the affected row (optional)
    ip_address  : Client IP — auto-resolved from Flask request if omitted

    Returns the AuditLog instance (already added to session, NOT committed).
    Returns None and logs an error on failure.
    """
    try:
        # Auto-detect IP from Flask request context if available and not supplied
        if ip_address is None:
            try:
                ip_address = flask_request.remote_addr
            except RuntimeError:
                # Outside request context (e.g. CLI / tests)
                ip_address = None

        entry = AuditLog(
            user_id=user_id,
            action=action,
            target_table=target_table,
            target_id=target_id,
            ip_address=ip_address,
        )
        db.session.add(entry)
        return entry

    except Exception as exc:
        logger.error("audit_service.log_action failed: %s", exc, exc_info=True)
        return None


def get_recent_audit_logs(limit: int = 100) -> list[AuditLog]:
    """Return the most recent audit log entries, newest first."""
    return (
        AuditLog.query.order_by(AuditLog.created_at.desc())
        .limit(limit)
        .all()
    )


# ---------------------------------------------------------------------------
# G-5: Audit Log Search, Filter & Pagination
# ---------------------------------------------------------------------------

def _parse_date(date_str: str | None, end_of_day: bool = False) -> datetime | None:
    """Safely parse user-supplied date string into a datetime object."""
    if not date_str or not date_str.strip():
        return None
    cleaned = date_str.strip()
    for fmt in ("%Y-%m-%d", "%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%dT%H:%M"):
        try:
            dt = datetime.strptime(cleaned, fmt)
            if fmt == "%Y-%m-%d" and end_of_day:
                dt = dt.replace(hour=23, minute=59, second=59, microsecond=999999)
            return dt
        except ValueError:
            continue
    return None


def _build_audit_filter_query(
    q: str | None = None,
    user_id: int | None = None,
    action: str | None = None,
    target_table: str | None = None,
    date_from: str | None = None,
    date_to: str | None = None,
):
    """Construct filtered AuditLog SQLAlchemy query joined with User."""
    query = AuditLog.query.outerjoin(User, AuditLog.user_id == User.id)

    if q and q.strip():
        search_term = f"%{q.strip()}%"
        query = query.filter(
            or_(
                AuditLog.action.ilike(search_term),
                AuditLog.target_table.ilike(search_term),
                AuditLog.ip_address.ilike(search_term),
                User.username.ilike(search_term),
            )
        )

    if user_id is not None:
        query = query.filter(AuditLog.user_id == user_id)

    if action and action.strip():
        query = query.filter(AuditLog.action.ilike(f"%{action.strip()}%"))

    if target_table and target_table.strip():
        query = query.filter(AuditLog.target_table == target_table.strip())

    start_dt = _parse_date(date_from, end_of_day=False)
    if start_dt:
        query = query.filter(AuditLog.created_at >= start_dt)

    end_dt = _parse_date(date_to, end_of_day=True)
    if end_dt:
        query = query.filter(AuditLog.created_at <= end_dt)

    return query


def filter_audit_logs(
    q: str | None = None,
    user_id: int | None = None,
    action: str | None = None,
    target_table: str | None = None,
    date_from: str | None = None,
    date_to: str | None = None,
    page: int = 1,
    per_page: int = 25,
) -> dict[str, Any]:
    """
    Search, filter, and paginate audit log entries (G-5).
    Returns a dictionary containing items, page counters, and filter state.
    """
    try:
        page = max(1, int(page))
    except (ValueError, TypeError):
        page = 1

    try:
        per_page = min(max(5, int(per_page)), 100)
    except (ValueError, TypeError):
        per_page = 25

    query = _build_audit_filter_query(
        q=q,
        user_id=user_id,
        action=action,
        target_table=target_table,
        date_from=date_from,
        date_to=date_to,
    )

    total_count = query.count()
    total_pages = max(1, math.ceil(total_count / per_page)) if total_count > 0 else 1
    if page > total_pages and total_count > 0:
        page = total_pages

    items = (
        query.order_by(AuditLog.created_at.desc(), AuditLog.id.desc())
        .offset((page - 1) * per_page)
        .limit(per_page)
        .all()
    )

    return {
        "items": items,
        "logs": items,
        "page": page,
        "per_page": per_page,
        "total_count": total_count,
        "total_pages": total_pages,
        "has_prev": page > 1,
        "has_next": page < total_pages,
        "prev_num": page - 1 if page > 1 else None,
        "next_num": page + 1 if page < total_pages else None,
        "filters": {
            "q": q or "",
            "user_id": user_id if user_id is not None else "",
            "action": action or "",
            "target_table": target_table or "",
            "date_from": date_from or "",
            "date_to": date_to or "",
        },
    }


# ---------------------------------------------------------------------------
# G-7: Audit Log CSV Export
# ---------------------------------------------------------------------------

def export_audit_logs_csv_data(
    q: str | None = None,
    user_id: int | None = None,
    action: str | None = None,
    target_table: str | None = None,
    date_from: str | None = None,
    date_to: str | None = None,
    limit: int = 5000,
) -> str:
    """
    Export audit logs matching filter parameters as RFC 4180 compliant CSV (G-7).
    """
    query = _build_audit_filter_query(
        q=q,
        user_id=user_id,
        action=action,
        target_table=target_table,
        date_from=date_from,
        date_to=date_to,
    )

    records = (
        query.order_by(AuditLog.created_at.desc(), AuditLog.id.desc())
        .limit(limit)
        .all()
    )

    output = io.StringIO()
    writer = csv.writer(output, dialect="excel")

    # CSV Header
    writer.writerow([
        "Timestamp (UTC)",
        "Log ID",
        "Actor User ID",
        "Actor Username",
        "Action Verb",
        "Target Table",
        "Target ID",
        "Client IP Address",
    ])

    for log in records:
        actor_name = log.user.username if log.user else f"User #{log.user_id}"
        ts_str = log.created_at.strftime("%Y-%m-%d %H:%M:%S") if log.created_at else ""
        writer.writerow([
            ts_str,
            log.id,
            log.user_id,
            actor_name,
            log.action,
            log.target_table,
            log.target_id if log.target_id is not None else "",
            log.ip_address or "",
        ])

    return output.getvalue()


def get_audit_tables_and_actions() -> tuple[list[str], list[str]]:
    """Return sorted distinct target tables and common action verbs for UI dropdowns."""
    try:
        tables = [
            row[0]
            for row in db.session.query(AuditLog.target_table).distinct().all()
            if row[0]
        ]
        tables.sort()
    except Exception:
        tables = ["users", "threat_indicators", "threat_reports", "malware_info", "alerts", "audit_logs"]

    try:
        actions = [
            row[0]
            for row in db.session.query(AuditLog.action).distinct().all()
            if row[0]
        ]
        actions.sort()
    except Exception:
        actions = []

    return tables, actions

