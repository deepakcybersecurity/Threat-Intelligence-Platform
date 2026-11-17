"""
Comprehensive CRUD service layer for the REST API v2.

Provides serialization, validation, pagination, and CRUD operations
for all Threat Intelligence Platform resources.
"""

from datetime import datetime, timezone

from app import db
from app.models import User, ThreatIndicator, Alert, ThreatReport, Malware, AuditLog
from app.services.audit_service import log_action


# ---------------------------------------------------------------------------
# Valid enum values (used for input validation)
# ---------------------------------------------------------------------------

VALID_SEVERITIES = {"Low", "Medium", "High", "Critical"}
VALID_INDICATOR_STATUSES = {"Active", "Inactive", "Expired", "False Positive"}
VALID_TLP_MARKINGS = {"RED", "AMBER", "GREEN", "WHITE", "CLEAR"}
VALID_ALERT_STATUSES = {"Open", "In Progress", "Resolved", "Closed"}
VALID_MALWARE_TYPES = {
    "Virus", "Worm", "Trojan", "Ransomware", "Spyware", "Adware",
    "Rootkit", "Botnet", "Keylogger", "Backdoor", "Cryptominer", "Other",
}
VALID_PLATFORMS = {
    "Windows", "Linux", "macOS", "Android", "iOS", "Cross-Platform", "Other",
}

SORTABLE_FIELDS = {"created_at", "severity", "risk_score", "id"}


# ---------------------------------------------------------------------------
# Datetime helper
# ---------------------------------------------------------------------------

def _fmt_dt(dt_value) -> str | None:
    """Format a datetime to ISO 8601 UTC string, or return None."""
    if dt_value is None:
        return None
    return dt_value.isoformat() + "Z"


# ---------------------------------------------------------------------------
# Serializers (model → dict)
# ---------------------------------------------------------------------------

def serialize_indicator(ind) -> dict:
    """Serialize a ThreatIndicator instance to a dictionary."""
    return {
        "id": ind.id,
        "indicator_value": ind.indicator_value,
        "indicator_type": ind.indicator_type,
        "severity": ind.severity,
        "status": ind.status,
        "confidence_score": ind.confidence_score,
        "risk_score": ind.risk_score,
        "source": ind.source,
        "tlp_marking": ind.tlp_marking,
        "first_seen_at": _fmt_dt(ind.first_seen_at),
        "last_seen_at": _fmt_dt(ind.last_seen_at),
        "created_at": _fmt_dt(ind.created_at),
        "updated_at": _fmt_dt(ind.updated_at),
        "added_by_user_id": ind.added_by_user_id,
        "context": ind.context,
    }


def serialize_alert(alert) -> dict:
    """Serialize an Alert instance to a dictionary."""
    return {
        "id": alert.id,
        "title": alert.title,
        "description": alert.description,
        "severity": alert.severity,
        "status": alert.status,
        "alert_type": alert.alert_type,
        "is_read": alert.is_read,
        "indicator_id": alert.indicator_id,
        "malware_id": alert.malware_id,
        "user_id": alert.user_id,
        "created_at": _fmt_dt(alert.created_at),
        "updated_at": _fmt_dt(alert.updated_at),
    }


def serialize_report(report) -> dict:
    """Serialize a ThreatReport instance to a dictionary."""
    indicator_count = len(report.indicators) if report.indicators else 0
    return {
        "id": report.id,
        "title": report.title,
        "description": report.description,
        "category": report.category,
        "severity": report.severity,
        "status": report.status,
        "tlp_level": report.tlp_level,
        "target_sector": report.target_sector,
        "attachment": report.attachment,
        "user_id": report.user_id,
        "created_at": _fmt_dt(report.created_at),
        "updated_at": _fmt_dt(report.updated_at),
        "indicator_count": indicator_count,
    }


def serialize_malware(malware) -> dict:
    """Serialize a Malware instance to a dictionary."""
    indicator_count = len(malware.indicators) if malware.indicators else 0
    return {
        "id": malware.id,
        "malware_name": malware.malware_name,
        "malware_family": malware.malware_family,
        "malware_type": malware.malware_type,
        "platform": malware.platform,
        "severity": malware.severity,
        "risk_score": malware.risk_score,
        "description": malware.description,
        "mitre_attack_id": malware.mitre_attack_id,
        "cve_id": malware.cve_id,
        "first_seen_at": _fmt_dt(malware.first_seen_at),
        "last_seen_at": _fmt_dt(malware.last_seen_at),
        "created_by_user_id": malware.created_by_user_id,
        "created_at": _fmt_dt(malware.created_at),
        "updated_at": _fmt_dt(malware.updated_at),
        "indicator_count": indicator_count,
    }


def serialize_audit_log(log) -> dict:
    """Serialize an AuditLog instance to a dictionary."""
    username = log.user.username if log.user else None
    return {
        "id": log.id,
        "user_id": log.user_id,
        "username": username,
        "action": log.action,
        "target_table": log.target_table,
        "target_id": log.target_id,
        "ip_address": log.ip_address,
        "created_at": _fmt_dt(log.created_at),
    }


def serialize_user_safe(user) -> dict:
    """Serialize a User instance to a dictionary (no password_hash)."""
    return {
        "id": user.id,
        "username": user.username,
        "email": user.email,
        "role": user.role,
        "is_active": user.is_active,
        "created_at": _fmt_dt(user.created_at),
    }


# ---------------------------------------------------------------------------
# Pagination helper
# ---------------------------------------------------------------------------

def paginate_query(query, page: int = 1, per_page: int = 20,
                   max_per_page: int = 100) -> dict:
    """
    Paginate a SQLAlchemy query and return a standardised response dict.

    Returns:
        {
            "items": [<model instances>],
            "pagination": {
                "page": int,
                "per_page": int,
                "total": int,
                "pages": int,
                "has_next": bool,
                "has_prev": bool,
            }
        }
    """
    page = max(1, page)
    per_page = min(max(1, per_page), max_per_page)

    total = query.count()
    pages = max(1, (total + per_page - 1) // per_page)
    items = query.offset((page - 1) * per_page).limit(per_page).all()

    return {
        "items": items,
        "pagination": {
            "page": page,
            "per_page": per_page,
            "total": total,
            "pages": pages,
            "has_next": page < pages,
            "has_prev": page > 1,
        },
    }


# ---------------------------------------------------------------------------
# Sorting helper
# ---------------------------------------------------------------------------

def _apply_sort(query, model, sort_by: str | None, sort_order: str | None):
    """Apply ordering to a query. Defaults to created_at DESC."""
    if sort_by and sort_by in SORTABLE_FIELDS and hasattr(model, sort_by):
        col = getattr(model, sort_by)
    else:
        col = model.created_at

    if sort_order and sort_order.lower() == "asc":
        query = query.order_by(col.asc())
    else:
        query = query.order_by(col.desc())

    return query


# ---------------------------------------------------------------------------
# Indicator CRUD
# ---------------------------------------------------------------------------

def list_indicators(page: int, per_page: int, indicator_type: str | None = None,
                    severity: str | None = None, status: str | None = None,
                    q: str | None = None, min_risk: int | None = None,
                    sort_by: str | None = None,
                    sort_order: str | None = None) -> dict:
    """List threat indicators with filtering, search, and pagination."""
    query = ThreatIndicator.query

    if indicator_type:
        query = query.filter(ThreatIndicator.indicator_type == indicator_type)
    if severity:
        query = query.filter(ThreatIndicator.severity == severity)
    if status:
        query = query.filter(ThreatIndicator.status == status)
    if min_risk is not None:
        query = query.filter(ThreatIndicator.risk_score >= min_risk)
    if q:
        search = f"%{q}%"
        query = query.filter(
            db.or_(
                ThreatIndicator.indicator_value.ilike(search),
                ThreatIndicator.source.ilike(search),
                ThreatIndicator.context.ilike(search),
            )
        )

    query = _apply_sort(query, ThreatIndicator, sort_by, sort_order)
    result = paginate_query(query, page, per_page)
    result["items"] = [serialize_indicator(i) for i in result["items"]]
    return result


def get_indicator(indicator_id: int) -> dict | None:
    """Get a single threat indicator by ID."""
    ind = db.session.get(ThreatIndicator, indicator_id)
    if ind is None:
        return None
    data = serialize_indicator(ind)
    data["report_ids"] = [r.id for r in ind.reports] if ind.reports else []
    data["malware_ids"] = [m.id for m in ind.malwares] if ind.malwares else []
    return data


def create_indicator(data: dict, user_id: int) -> tuple[dict, str | None]:
    """
    Create a new threat indicator.

    Returns:
        (indicator_dict, error_message) — error_message is None on success.
    """
    # --- Validation ---
    indicator_value = data.get("indicator_value")
    if not indicator_value:
        return {}, "indicator_value is required"

    indicator_type = data.get("indicator_type")
    if not indicator_type:
        return {}, "indicator_type is required"

    severity = data.get("severity", "Medium")
    if severity not in VALID_SEVERITIES:
        return {}, f"severity must be one of: {', '.join(sorted(VALID_SEVERITIES))}"

    status = data.get("status", "Active")
    if status not in VALID_INDICATOR_STATUSES:
        return {}, f"status must be one of: {', '.join(sorted(VALID_INDICATOR_STATUSES))}"

    tlp_marking = data.get("tlp_marking", "WHITE")
    if tlp_marking not in VALID_TLP_MARKINGS:
        return {}, f"tlp_marking must be one of: {', '.join(sorted(VALID_TLP_MARKINGS))}"

    # --- Build model ---
    now = datetime.now(timezone.utc)
    ind = ThreatIndicator(
        indicator_value=indicator_value,
        indicator_type=indicator_type,
        severity=severity,
        status=status,
        tlp_marking=tlp_marking,
        confidence_score=data.get("confidence_score", 50),
        risk_score=data.get("risk_score"),
        source=data.get("source") or "API Ingest",
        context=data.get("context"),
        first_seen_at=data.get("first_seen_at", now),
        last_seen_at=data.get("last_seen_at"),
        added_by_user_id=user_id,
    )

    try:
        db.session.add(ind)
        db.session.flush()  # Obtain the id before logging
        log_action(
            user_id=user_id,
            action="CREATE",
            target_table="threat_indicators",
            target_id=ind.id,
        )
        db.session.commit()
        return serialize_indicator(ind), None
    except Exception as exc:
        db.session.rollback()
        return {}, f"Database error: {str(exc)}"


def update_indicator(indicator_id: int, data: dict,
                     user_id: int) -> tuple[dict | None, str | None]:
    """
    Update an existing threat indicator (partial update).

    Returns:
        (indicator_dict | None, error_message | None)
    """
    ind = db.session.get(ThreatIndicator, indicator_id)
    if ind is None:
        return None, "Indicator not found"

    # --- Validate optional fields if provided ---
    if "severity" in data and data["severity"] not in VALID_SEVERITIES:
        return None, f"severity must be one of: {', '.join(sorted(VALID_SEVERITIES))}"
    if "status" in data and data["status"] not in VALID_INDICATOR_STATUSES:
        return None, f"status must be one of: {', '.join(sorted(VALID_INDICATOR_STATUSES))}"
    if "tlp_marking" in data and data["tlp_marking"] not in VALID_TLP_MARKINGS:
        return None, f"tlp_marking must be one of: {', '.join(sorted(VALID_TLP_MARKINGS))}"

    # --- Apply provided fields ---
    updatable_fields = [
        "indicator_value", "indicator_type", "severity", "status",
        "confidence_score", "risk_score", "source", "tlp_marking",
        "context", "first_seen_at", "last_seen_at",
    ]
    for field in updatable_fields:
        if field in data:
            setattr(ind, field, data[field])

    ind.updated_at = datetime.now(timezone.utc)

    try:
        log_action(
            user_id=user_id,
            action="UPDATE",
            target_table="threat_indicators",
            target_id=ind.id,
        )
        db.session.commit()
        return serialize_indicator(ind), None
    except Exception as exc:
        db.session.rollback()
        return None, f"Database error: {str(exc)}"


def delete_indicator(indicator_id: int,
                     user_id: int) -> tuple[bool, str]:
    """
    Delete a threat indicator and cascade-delete associated alerts.

    Returns:
        (success: bool, message: str)
    """
    ind = db.session.get(ThreatIndicator, indicator_id)
    if ind is None:
        return False, "Indicator not found"

    try:
        # Cascade: delete associated alerts
        Alert.query.filter_by(indicator_id=indicator_id).delete()

        log_action(
            user_id=user_id,
            action="DELETE",
            target_table="threat_indicators",
            target_id=indicator_id,
        )
        db.session.delete(ind)
        db.session.commit()
        return True, "Indicator deleted successfully"
    except Exception as exc:
        db.session.rollback()
        return False, f"Database error: {str(exc)}"


# ---------------------------------------------------------------------------
# Alert CRUD
# ---------------------------------------------------------------------------

def list_alerts(page: int, per_page: int, severity: str | None = None,
                status: str | None = None, alert_type: str | None = None,
                q: str | None = None, is_read: bool | None = None,
                sort_by: str | None = None,
                sort_order: str | None = None) -> dict:
    """List alerts with filtering, search, and pagination."""
    query = Alert.query

    if severity:
        query = query.filter(Alert.severity == severity)
    if status:
        query = query.filter(Alert.status == status)
    if alert_type:
        query = query.filter(Alert.alert_type == alert_type)
    if is_read is not None:
        query = query.filter(Alert.is_read == is_read)
    if q:
        search = f"%{q}%"
        query = query.filter(
            db.or_(
                Alert.title.ilike(search),
                Alert.description.ilike(search),
            )
        )

    query = _apply_sort(query, Alert, sort_by, sort_order)
    result = paginate_query(query, page, per_page)
    result["items"] = [serialize_alert(a) for a in result["items"]]
    return result


def get_alert(alert_id: int) -> dict | None:
    """Get a single alert by ID."""
    alert = db.session.get(Alert, alert_id)
    if alert is None:
        return None
    data = serialize_alert(alert)
    if alert.indicator:
        data["indicator"] = serialize_indicator(alert.indicator)
    if alert.malware:
        data["malware"] = serialize_malware(alert.malware)
    return data


def update_alert_status(alert_id: int, new_status: str,
                        user_id: int) -> tuple[dict | None, str | None]:
    """
    Update the status of an alert.

    Returns:
        (alert_dict | None, error_message | None)
    """
    if new_status not in VALID_ALERT_STATUSES:
        return None, f"status must be one of: {', '.join(sorted(VALID_ALERT_STATUSES))}"

    alert = db.session.get(Alert, alert_id)
    if alert is None:
        return None, "Alert not found"

    alert.status = new_status
    alert.updated_at = datetime.now(timezone.utc)

    try:
        log_action(
            user_id=user_id,
            action="UPDATE",
            target_table="alerts",
            target_id=alert.id,
        )
        db.session.commit()
        return serialize_alert(alert), None
    except Exception as exc:
        db.session.rollback()
        return None, f"Database error: {str(exc)}"


# ---------------------------------------------------------------------------
# Report CRUD (read-only)
# ---------------------------------------------------------------------------

def list_reports(page: int, per_page: int, severity: str | None = None,
                 category: str | None = None, q: str | None = None,
                 sort_by: str | None = None,
                 sort_order: str | None = None) -> dict:
    """List threat reports with filtering, search, and pagination."""
    query = ThreatReport.query

    if severity:
        query = query.filter(ThreatReport.severity == severity)
    if category:
        query = query.filter(ThreatReport.category == category)
    if q:
        search = f"%{q}%"
        query = query.filter(
            db.or_(
                ThreatReport.title.ilike(search),
                ThreatReport.description.ilike(search),
            )
        )

    query = _apply_sort(query, ThreatReport, sort_by, sort_order)
    result = paginate_query(query, page, per_page)
    result["items"] = [serialize_report(r) for r in result["items"]]
    return result


def get_report(report_id: int) -> dict | None:
    """
    Get a single threat report by ID.

    Includes linked indicator_ids and malware_ids.
    """
    report = db.session.get(ThreatReport, report_id)
    if report is None:
        return None

    data = serialize_report(report)
    data["indicator_ids"] = [i.id for i in report.indicators] if report.indicators else []
    data["malware_ids"] = [m.id for m in report.malwares] if report.malwares else []
    return data


# ---------------------------------------------------------------------------
# Malware CRUD (read-only)
# ---------------------------------------------------------------------------

def list_malware(page: int, per_page: int, malware_type: str | None = None,
                 platform: str | None = None, severity: str | None = None,
                 q: str | None = None, sort_by: str | None = None,
                 sort_order: str | None = None) -> dict:
    """List malware entries with filtering, search, and pagination."""
    query = Malware.query

    if malware_type:
        query = query.filter(Malware.malware_type == malware_type)
    if platform:
        query = query.filter(Malware.platform == platform)
    if severity:
        query = query.filter(Malware.severity == severity)
    if q:
        search = f"%{q}%"
        query = query.filter(
            db.or_(
                Malware.malware_name.ilike(search),
                Malware.malware_family.ilike(search),
                Malware.description.ilike(search),
            )
        )

    query = _apply_sort(query, Malware, sort_by, sort_order)
    result = paginate_query(query, page, per_page)
    result["items"] = [serialize_malware(m) for m in result["items"]]
    return result


def get_malware(malware_id: int) -> dict | None:
    """
    Get a single malware entry by ID.

    Includes linked indicator_ids.
    """
    malware = db.session.get(Malware, malware_id)
    if malware is None:
        return None

    data = serialize_malware(malware)
    data["indicator_ids"] = [i.id for i in malware.indicators] if malware.indicators else []
    return data


# ---------------------------------------------------------------------------
# Audit Log Query
# ---------------------------------------------------------------------------

def list_audit_logs(page: int, per_page: int, user_id: int | None = None,
                    action: str | None = None,
                    target_table: str | None = None, q: str | None = None,
                    sort_by: str | None = None,
                    sort_order: str | None = None) -> dict:
    """List audit log entries with filtering, search, and pagination."""
    query = AuditLog.query

    if user_id is not None:
        query = query.filter(AuditLog.user_id == user_id)
    if action:
        query = query.filter(AuditLog.action == action)
    if target_table:
        query = query.filter(AuditLog.target_table == target_table)
    if q:
        search = f"%{q}%"
        query = query.filter(
            db.or_(
                AuditLog.action.ilike(search),
                AuditLog.target_table.ilike(search),
                AuditLog.ip_address.ilike(search),
            )
        )

    query = _apply_sort(query, AuditLog, sort_by, sort_order)
    result = paginate_query(query, page, per_page)
    result["items"] = [serialize_audit_log(log) for log in result["items"]]
    return result


# ---------------------------------------------------------------------------
# User Query (admin only)
# ---------------------------------------------------------------------------

def list_users(page: int, per_page: int) -> dict:
    """List users with pagination (admin-only endpoint)."""
    query = User.query.order_by(User.created_at.desc())
    result = paginate_query(query, page, per_page)
    result["items"] = [serialize_user_safe(u) for u in result["items"]]
    return result


# ---------------------------------------------------------------------------
# OpenAPI Schema Generator
# ---------------------------------------------------------------------------

def get_openapi_schema() -> dict:
    """
    Return a basic OpenAPI 3.0 schema describing all v2 API endpoints.

    Includes paths, methods, parameters, and response structure for every
    documented endpoint.
    """
    pagination_params = [
        {"name": "page", "in": "query", "schema": {"type": "integer", "default": 1}},
        {"name": "per_page", "in": "query", "schema": {"type": "integer", "default": 20}},
    ]
    sort_params = [
        {
            "name": "sort_by",
            "in": "query",
            "schema": {"type": "string", "enum": ["created_at", "severity", "risk_score", "id"]},
        },
        {
            "name": "sort_order",
            "in": "query",
            "schema": {"type": "string", "enum": ["asc", "desc"], "default": "desc"},
        },
    ]

    paginated_response = {
        "200": {
            "description": "Paginated list response",
            "content": {
                "application/json": {
                    "schema": {
                        "type": "object",
                        "properties": {
                            "items": {"type": "array", "items": {"type": "object"}},
                            "pagination": {
                                "type": "object",
                                "properties": {
                                    "page": {"type": "integer"},
                                    "per_page": {"type": "integer"},
                                    "total": {"type": "integer"},
                                    "pages": {"type": "integer"},
                                    "has_next": {"type": "boolean"},
                                    "has_prev": {"type": "boolean"},
                                },
                            },
                        },
                    }
                }
            },
        }
    }

    single_response = {
        "200": {
            "description": "Single resource response",
            "content": {"application/json": {"schema": {"type": "object"}}},
        },
        "404": {"description": "Resource not found"},
    }

    return {
        "openapi": "3.0.3",
        "info": {
            "title": "Threat Intelligence Platform API",
            "version": "2.0.0",
            "description": "REST API v2 for managing threat intelligence resources.",
        },
        "servers": [{"url": "/api/v2"}],
        "paths": {
            # ---- Indicators ----
            "/api/v2/indicators": {
                "get": {
                    "summary": "List threat indicators",
                    "tags": ["Indicators"],
                    "parameters": pagination_params + sort_params + [
                        {"name": "indicator_type", "in": "query", "schema": {"type": "string"}},
                        {"name": "severity", "in": "query", "schema": {"type": "string", "enum": list(VALID_SEVERITIES)}},
                        {"name": "status", "in": "query", "schema": {"type": "string", "enum": list(VALID_INDICATOR_STATUSES)}},
                        {"name": "q", "in": "query", "schema": {"type": "string"}, "description": "Search query"},
                        {"name": "min_risk", "in": "query", "schema": {"type": "integer"}},
                    ],
                    "responses": paginated_response,
                },
                "post": {
                    "summary": "Create a new threat indicator",
                    "tags": ["Indicators"],
                    "requestBody": {
                        "required": True,
                        "content": {
                            "application/json": {
                                "schema": {
                                    "type": "object",
                                    "required": ["indicator_value", "indicator_type"],
                                    "properties": {
                                        "indicator_value": {"type": "string"},
                                        "indicator_type": {"type": "string"},
                                        "severity": {"type": "string", "enum": list(VALID_SEVERITIES)},
                                        "status": {"type": "string", "enum": list(VALID_INDICATOR_STATUSES)},
                                        "tlp_marking": {"type": "string", "enum": list(VALID_TLP_MARKINGS)},
                                        "confidence_score": {"type": "integer", "default": 50},
                                        "risk_score": {"type": "integer"},
                                        "source": {"type": "string"},
                                        "context": {"type": "string"},
                                    },
                                }
                            }
                        },
                    },
                    "responses": {
                        "201": {
                            "description": "Indicator created",
                            "content": {"application/json": {"schema": {"type": "object"}}},
                        },
                        "400": {"description": "Validation error"},
                    },
                },
            },
            "/api/v2/indicators/{id}": {
                "get": {
                    "summary": "Get a threat indicator by ID",
                    "tags": ["Indicators"],
                    "parameters": [{"name": "id", "in": "path", "required": True, "schema": {"type": "integer"}}],
                    "responses": single_response,
                },
                "put": {
                    "summary": "Update a threat indicator",
                    "tags": ["Indicators"],
                    "parameters": [{"name": "id", "in": "path", "required": True, "schema": {"type": "integer"}}],
                    "requestBody": {
                        "required": True,
                        "content": {
                            "application/json": {
                                "schema": {
                                    "type": "object",
                                    "properties": {
                                        "indicator_value": {"type": "string"},
                                        "indicator_type": {"type": "string"},
                                        "severity": {"type": "string"},
                                        "status": {"type": "string"},
                                        "tlp_marking": {"type": "string"},
                                        "confidence_score": {"type": "integer"},
                                        "risk_score": {"type": "integer"},
                                        "source": {"type": "string"},
                                        "context": {"type": "string"},
                                    },
                                }
                            }
                        },
                    },
                    "responses": {
                        "200": {
                            "description": "Indicator updated",
                            "content": {"application/json": {"schema": {"type": "object"}}},
                        },
                        "400": {"description": "Validation error"},
                        "404": {"description": "Indicator not found"},
                    },
                },
                "delete": {
                    "summary": "Delete a threat indicator",
                    "tags": ["Indicators"],
                    "parameters": [{"name": "id", "in": "path", "required": True, "schema": {"type": "integer"}}],
                    "responses": {
                        "200": {"description": "Indicator deleted"},
                        "404": {"description": "Indicator not found"},
                    },
                },
            },
            # ---- Alerts ----
            "/api/v2/alerts": {
                "get": {
                    "summary": "List alerts",
                    "tags": ["Alerts"],
                    "parameters": pagination_params + sort_params + [
                        {"name": "severity", "in": "query", "schema": {"type": "string", "enum": list(VALID_SEVERITIES)}},
                        {"name": "status", "in": "query", "schema": {"type": "string", "enum": list(VALID_ALERT_STATUSES)}},
                        {"name": "alert_type", "in": "query", "schema": {"type": "string"}},
                        {"name": "q", "in": "query", "schema": {"type": "string"}},
                        {"name": "is_read", "in": "query", "schema": {"type": "boolean"}},
                    ],
                    "responses": paginated_response,
                },
            },
            "/api/v2/alerts/{id}": {
                "get": {
                    "summary": "Get an alert by ID",
                    "tags": ["Alerts"],
                    "parameters": [{"name": "id", "in": "path", "required": True, "schema": {"type": "integer"}}],
                    "responses": single_response,
                },
                "patch": {
                    "summary": "Update alert status",
                    "tags": ["Alerts"],
                    "parameters": [{"name": "id", "in": "path", "required": True, "schema": {"type": "integer"}}],
                    "requestBody": {
                        "required": True,
                        "content": {
                            "application/json": {
                                "schema": {
                                    "type": "object",
                                    "required": ["status"],
                                    "properties": {
                                        "status": {"type": "string", "enum": list(VALID_ALERT_STATUSES)},
                                    },
                                }
                            }
                        },
                    },
                    "responses": {
                        "200": {
                            "description": "Alert status updated",
                            "content": {"application/json": {"schema": {"type": "object"}}},
                        },
                        "400": {"description": "Validation error"},
                        "404": {"description": "Alert not found"},
                    },
                },
            },
            # ---- Reports ----
            "/api/v2/reports": {
                "get": {
                    "summary": "List threat reports",
                    "tags": ["Reports"],
                    "parameters": pagination_params + sort_params + [
                        {"name": "severity", "in": "query", "schema": {"type": "string"}},
                        {"name": "category", "in": "query", "schema": {"type": "string"}},
                        {"name": "q", "in": "query", "schema": {"type": "string"}},
                    ],
                    "responses": paginated_response,
                },
            },
            "/api/v2/reports/{id}": {
                "get": {
                    "summary": "Get a threat report by ID",
                    "tags": ["Reports"],
                    "parameters": [{"name": "id", "in": "path", "required": True, "schema": {"type": "integer"}}],
                    "responses": single_response,
                },
            },
            # ---- Malware ----
            "/api/v2/malware": {
                "get": {
                    "summary": "List malware entries",
                    "tags": ["Malware"],
                    "parameters": pagination_params + sort_params + [
                        {"name": "malware_type", "in": "query", "schema": {"type": "string", "enum": list(VALID_MALWARE_TYPES)}},
                        {"name": "platform", "in": "query", "schema": {"type": "string", "enum": list(VALID_PLATFORMS)}},
                        {"name": "severity", "in": "query", "schema": {"type": "string"}},
                        {"name": "q", "in": "query", "schema": {"type": "string"}},
                    ],
                    "responses": paginated_response,
                },
            },
            "/api/v2/malware/{id}": {
                "get": {
                    "summary": "Get a malware entry by ID",
                    "tags": ["Malware"],
                    "parameters": [{"name": "id", "in": "path", "required": True, "schema": {"type": "integer"}}],
                    "responses": single_response,
                },
            },
            # ---- Audit Logs ----
            "/api/v2/audit-logs": {
                "get": {
                    "summary": "List audit logs",
                    "tags": ["Audit Logs"],
                    "parameters": pagination_params + sort_params + [
                        {"name": "user_id", "in": "query", "schema": {"type": "integer"}},
                        {"name": "action", "in": "query", "schema": {"type": "string"}},
                        {"name": "target_table", "in": "query", "schema": {"type": "string"}},
                        {"name": "q", "in": "query", "schema": {"type": "string"}},
                    ],
                    "responses": paginated_response,
                },
            },
            # ---- Users ----
            "/api/v2/users": {
                "get": {
                    "summary": "List users (admin only)",
                    "tags": ["Users"],
                    "parameters": pagination_params,
                    "responses": paginated_response,
                },
            },
            # ---- Docs ----
            "/api/v2/docs": {
                "get": {
                    "summary": "Get OpenAPI schema",
                    "tags": ["Documentation"],
                    "responses": {
                        "200": {
                            "description": "OpenAPI 3.0 JSON schema",
                            "content": {"application/json": {"schema": {"type": "object"}}},
                        },
                    },
                },
            },
        },
    }
