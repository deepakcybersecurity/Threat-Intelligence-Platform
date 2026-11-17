"""
IOC Correlation Engine
======================
Analyzes and discovers relational threat intelligence across stored ThreatIndicator,
ThreatReport, and Malware records using existing SQLAlchemy database associations.

Primary Traversal Paths:
1. Direct Threat Reports (ThreatIndicator <-> ThreatReport via report_indicator)
2. Direct Malware Records (ThreatIndicator <-> Malware via malware_indicator)
3. Multi-Hop Related IOCs (via shared Threat Reports and shared Malware)

Guarantees:
- Read-only analysis: NEVER mutates indicator severity, confidence, or risk scores.
- Zero raw SQL: fully ORM-based with eager relationship loading to avoid N+1 queries.
- Deduplication: merges multiple relation paths into a single related IOC entry.
"""

from typing import Dict, Any, List
from sqlalchemy.orm import selectinload

from app import db
from app.models.threat_indicator import ThreatIndicator
from app.models.threat_report import ThreatReport
from app.models.malware import Malware


def _build_correlation_data(indicator: ThreatIndicator) -> Dict[str, Any]:
    """
    Build complete correlation map for a loaded ThreatIndicator instance.
    Calculates direct reports, direct malware, and deduplicated related indicators.
    """
    if not indicator:
        return {
            "success": False,
            "indicator": None,
            "summary": {
                "report_count": 0,
                "malware_count": 0,
                "related_indicator_count": 0
            },
            "reports": [],
            "malware": [],
            "related_indicators": [],
            "correlation_score": 0,
            "error": "Indicator not found"
        }

    # -------------------------------------------------------------------------
    # 1. Direct Threat Reports
    # -------------------------------------------------------------------------
    direct_reports: List[Dict[str, Any]] = []
    for report in indicator.reports or []:
        direct_reports.append({
            "id": report.id,
            "title": report.title or "Untitled Report",
            "category": report.category or "General",
            "severity": report.severity or "Medium",
            "status": report.status or "Active",
            "tlp_level": (report.tlp_level or "WHITE").upper(),
            "target_sector": report.target_sector or "N/A",
            "created_at": report.created_at.strftime("%Y-%m-%d %H:%M:%S") if report.created_at else None
        })

    # -------------------------------------------------------------------------
    # 2. Direct Malware Records
    # -------------------------------------------------------------------------
    direct_malware: List[Dict[str, Any]] = []
    for malware in indicator.malwares or []:
        direct_malware.append({
            "id": malware.id,
            "name": malware.malware_name or "Unknown",
            "family": malware.malware_family or "N/A",
            "type": malware.malware_type or "Other",
            "platform": malware.platform or "Cross-Platform",
            "severity": malware.severity or "Medium",
            "risk_score": malware.risk_score or 50,
            "mitre_attack_id": malware.mitre_attack_id or "N/A",
            "cve_id": malware.cve_id or "N/A"
        })

    # -------------------------------------------------------------------------
    # 3. Related Indicators Traversal
    # -------------------------------------------------------------------------
    # Map from other_indicator.id -> accumulator dict
    related_map: Dict[int, Dict[str, Any]] = {}

    # Path A: Co-occurring in Threat Reports
    for report in indicator.reports or []:
        for other in report.indicators or []:
            if other.id == indicator.id:
                continue  # Never correlate target IOC with itself

            if other.id not in related_map:
                related_map[other.id] = {
                    "indicator": other,
                    "shared_reports": [],
                    "shared_malware": []
                }
            related_map[other.id]["shared_reports"].append({
                "id": report.id,
                "title": report.title or f"Report #{report.id}"
            })

    # Path B: Co-occurring in Malware Records
    for malware in indicator.malwares or []:
        for other in malware.indicators or []:
            if other.id == indicator.id:
                continue  # Never correlate target IOC with itself

            if other.id not in related_map:
                related_map[other.id] = {
                    "indicator": other,
                    "shared_reports": [],
                    "shared_malware": []
                }
            related_map[other.id]["shared_malware"].append({
                "id": malware.id,
                "name": malware.malware_name or f"Malware #{malware.id}"
            })

    # -------------------------------------------------------------------------
    # 4. Consolidate Reasons and Correlation Strength
    # -------------------------------------------------------------------------
    related_indicators: List[Dict[str, Any]] = []
    total_correlation_score = 0

    for other_id, acc in related_map.items():
        other = acc["indicator"]
        reports_shared = acc["shared_reports"]
        malware_shared = acc["shared_malware"]

        has_report = len(reports_shared) > 0
        has_malware = len(malware_shared) > 0

        if has_report and has_malware:
            reason = "Shared Threat Report + Shared Malware"
        elif has_report:
            reason = "Shared Threat Report"
        elif has_malware:
            reason = "Shared Malware"
        else:
            reason = "Connected Entity"

        # Deterministic relationship strength: 1 pt per report, 2 pts per malware
        rel_strength = (len(reports_shared) * 1) + (len(malware_shared) * 2)
        total_correlation_score += rel_strength

        related_indicators.append({
            "id": other.id,
            "value": other.indicator_value,
            "type": other.indicator_type,
            "severity": other.severity,
            "confidence_score": other.confidence_score,
            "source": other.source,
            "relationship_reason": reason,
            "relationship_strength": rel_strength,
            "shared_reports": reports_shared,
            "shared_malware": malware_shared
        })

    # Sort related indicators by relationship strength descending, then by value
    related_indicators.sort(key=lambda x: (-x["relationship_strength"], x["value"]))

    return {
        "success": True,
        "indicator": {
            "id": indicator.id,
            "value": indicator.indicator_value,
            "type": indicator.indicator_type,
            "severity": indicator.severity,
            "confidence_score": indicator.confidence_score,
            "status": indicator.status,
            "source": indicator.source
        },
        "summary": {
            "report_count": len(direct_reports),
            "malware_count": len(direct_malware),
            "related_indicator_count": len(related_indicators)
        },
        "reports": direct_reports,
        "malware": direct_malware,
        "related_indicators": related_indicators,
        "correlation_score": total_correlation_score,
        "error": None
    }


def correlate_indicator(indicator: ThreatIndicator) -> Dict[str, Any]:
    """
    Correlate a ThreatIndicator model instance with related platform intelligence.
    """
    if not indicator:
        return {
            "success": False,
            "indicator": None,
            "summary": {
                "report_count": 0,
                "malware_count": 0,
                "related_indicator_count": 0
            },
            "reports": [],
            "malware": [],
            "related_indicators": [],
            "correlation_score": 0,
            "error": "Invalid indicator provided"
        }

    return _build_correlation_data(indicator)


def correlate_indicator_by_id(indicator_id: int) -> Dict[str, Any]:
    """
    Fetch a ThreatIndicator by ID with optimized eager loading,
    then execute the correlation analysis.
    """
    if not indicator_id or not isinstance(indicator_id, int):
        return {
            "success": False,
            "indicator": None,
            "summary": {
                "report_count": 0,
                "malware_count": 0,
                "related_indicator_count": 0
            },
            "reports": [],
            "malware": [],
            "related_indicators": [],
            "correlation_score": 0,
            "error": "Invalid indicator ID"
        }

    # Eagerly load reports -> indicators and malwares -> indicators in optimal queries
    indicator = ThreatIndicator.query.options(
        selectinload(ThreatIndicator.reports).selectinload(ThreatReport.indicators),
        selectinload(ThreatIndicator.malwares).selectinload(Malware.indicators)
    ).filter_by(id=indicator_id).first()

    if not indicator:
        return {
            "success": False,
            "indicator": None,
            "summary": {
                "report_count": 0,
                "malware_count": 0,
                "related_indicator_count": 0
            },
            "reports": [],
            "malware": [],
            "related_indicators": [],
            "correlation_score": 0,
            "error": "Indicator not found"
        }

    return _build_correlation_data(indicator)
