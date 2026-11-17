"""
IOC Enrichment Orchestrator & Cache Engine
===========================================
Coordinates external threat intelligence enrichment across AbuseIPDB, VirusTotal,
and AlienVault OTX, with automated database response caching via APICache.

Provider Routing:
- IPv4                  -> AbuseIPDB
- MD5, SHA1, SHA256     -> VirusTotal API v3
- Domain, URL           -> AlienVault OTX API v1
"""

from datetime import datetime, timedelta
import json
from flask import current_app

from app import db
from app.models.api_cache import APICache
from app.services.ip_reputation import check_ip_reputation
from app.services.virustotal import check_virustotal_hash
from app.services.otx import check_otx_indicator

CACHE_TTL_HOURS = 24

# Mapping from indicator_type to provider name
PROVIDER_MAP = {
    "ipv4": "AbuseIPDB",
    "ip": "AbuseIPDB",
    "md5": "VirusTotal",
    "sha1": "VirusTotal",
    "sha256": "VirusTotal",
    "domain": "AlienVault OTX",
    "url": "AlienVault OTX",
}


def get_provider_for_type(indicator_type: str) -> str:
    """Return the designated provider name for a given indicator type."""
    if not indicator_type:
        return None
    return PROVIDER_MAP.get(indicator_type.strip().lower())


def _get_cached_enrichment(provider: str, cache_key: str):
    """Retrieve non-expired enrichment result from APICache table."""
    try:
        entry = APICache.query.filter_by(
            api_name=provider,
            endpoint=cache_key
        ).filter(
            APICache.expires_at > datetime.utcnow()
        ).order_by(
            APICache.cached_at.desc()
        ).first()

        if entry and entry.response_data:
            return json.loads(entry.response_data)
    except Exception as e:
        # Cache lookup failure should not break live enrichment
        current_app.logger.warning(f"APICache lookup error: {str(e)}")
    return None


def _set_cached_enrichment(provider: str, cache_key: str, data: dict):
    """Save normalized enrichment result into APICache table with 24-hour expiration."""
    try:
        now = datetime.utcnow()
        expires = now + timedelta(hours=CACHE_TTL_HOURS)

        cache_entry = APICache(
            api_name=provider,
            endpoint=cache_key,
            response_data=json.dumps(data),
            cached_at=now,
            expires_at=expires
        )
        db.session.add(cache_entry)
        db.session.commit()
    except Exception as e:
        db.session.rollback()
        current_app.logger.warning(f"APICache save error: {str(e)}")


def enrich_indicator_by_value(indicator_value: str, indicator_type: str) -> dict:
    """
    Enrich an IOC by its raw value and type string.
    Checks APICache first; queries the designated provider if cache misses.
    """
    if not indicator_value or not isinstance(indicator_value, str):
        return {
            "success": False,
            "provider": None,
            "indicator": indicator_value,
            "indicator_type": indicator_type,
            "data": None,
            "error": "Invalid or missing indicator value.",
            "cached": False
        }

    clean_value = indicator_value.strip()
    clean_type = indicator_type.strip().lower() if indicator_type else ""

    provider = get_provider_for_type(clean_type)
    if not provider:
        return {
            "success": False,
            "provider": None,
            "indicator": clean_value,
            "indicator_type": clean_type,
            "data": None,
            "error": f"Unsupported IOC type '{clean_type}' for external enrichment.",
            "cached": False
        }

    cache_key = f"{clean_type}:{clean_value}"

    # 1. Check database cache
    cached_data = _get_cached_enrichment(provider, cache_key)
    if cached_data is not None:
        return {
            "success": True,
            "provider": provider,
            "indicator": clean_value,
            "indicator_type": clean_type,
            "data": cached_data,
            "error": None,
            "cached": True
        }

    # 2. Call designated provider
    try:
        if provider == "AbuseIPDB":
            raw_data = check_ip_reputation(clean_value)
            normalized_data = {
                "ip_address": raw_data.get("ipAddress", clean_value),
                "abuse_confidence_score": raw_data.get("abuseConfidenceScore", 0),
                "country_code": raw_data.get("countryCode"),
                "country_name": raw_data.get("countryName"),
                "isp": raw_data.get("isp"),
                "domain": raw_data.get("domain"),
                "is_tor": raw_data.get("isTor", False),
                "is_whitelisted": raw_data.get("isWhitelisted", False),
                "total_reports": raw_data.get("totalReports", 0),
                "distinct_users": raw_data.get("numDistinctUsers", 0),
                "last_reported_at": raw_data.get("lastReportedAt"),
                "message": f"Abuse confidence: {raw_data.get('abuseConfidenceScore', 0)}%"
            }

        elif provider == "VirusTotal":
            normalized_data = check_virustotal_hash(clean_value, clean_type)

        elif provider == "AlienVault OTX":
            normalized_data = check_otx_indicator(clean_value, clean_type)

        else:
            raise ValueError(f"Unknown provider: {provider}")

        # 3. Store normalized response in APICache
        _set_cached_enrichment(provider, cache_key, normalized_data)

        return {
            "success": True,
            "provider": provider,
            "indicator": clean_value,
            "indicator_type": clean_type,
            "data": normalized_data,
            "error": None,
            "cached": False
        }

    except Exception as e:
        return {
            "success": False,
            "provider": provider,
            "indicator": clean_value,
            "indicator_type": clean_type,
            "data": None,
            "error": str(e),
            "cached": False
        }


def enrich_indicator(indicator) -> dict:
    """
    Enrich a ThreatIndicator model instance.
    Guarantees no modifications to severity, confidence_score, or risk_score.
    """
    if hasattr(indicator, "indicator_value") and hasattr(indicator, "indicator_type"):
        val = indicator.indicator_value
        typ = indicator.indicator_type
    elif isinstance(indicator, dict):
        val = indicator.get("indicator_value") or indicator.get("value")
        typ = indicator.get("indicator_type") or indicator.get("type")
    else:
        return {
            "success": False,
            "provider": None,
            "indicator": str(indicator),
            "indicator_type": None,
            "data": None,
            "error": "Invalid indicator object provided.",
            "cached": False
        }

    return enrich_indicator_by_value(val, typ)
