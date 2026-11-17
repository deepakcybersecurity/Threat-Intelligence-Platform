"""
AlienVault OTX API v1 Service
==============================
Queries AlienVault Open Threat Exchange (OTX) for pulse intelligence
associated with domains, URLs, and IPv4 addresses.
"""

from urllib.parse import quote
import requests
from flask import current_app

OTX_BASE_URL = "https://otx.alienvault.com/api/v1/indicators/{indicator_type}/{indicator}/general"


def _normalize_otx_type(indicator_type: str) -> str:
    """Map internal indicator type names to AlienVault OTX endpoint path types."""
    t = indicator_type.strip().lower() if indicator_type else ""
    if t in ("ipv4", "ip"):
        return "IPv4"
    if t == "domain":
        return "domain"
    if t == "url":
        return "url"
    return t


def check_otx_indicator(indicator_value: str, indicator_type: str) -> dict:
    """
    Query AlienVault OTX API v1 for threat intelligence on a domain, URL, or IPv4 address.

    Returns:
        dict: Normalized payload containing pulse count, pulse list, and references.
    """
    if not indicator_value or not indicator_type:
        raise ValueError("Indicator value and type must be provided for OTX lookup.")

    otx_type = _normalize_otx_type(indicator_type)
    if otx_type not in ("IPv4", "domain", "url"):
        raise ValueError(f"Unsupported indicator type for AlienVault OTX: '{indicator_type}'.")

    api_key = current_app.config.get("OTX_API_KEY")
    if not api_key:
        raise RuntimeError("OTX_API_KEY is not configured.")

    clean_value = indicator_value.strip()
    encoded_indicator = quote(clean_value, safe="")
    url = OTX_BASE_URL.format(indicator_type=otx_type, indicator=encoded_indicator)

    headers = {
        "X-OTX-API-KEY": api_key,
        "Accept": "application/json"
    }

    try:
        response = requests.get(url, headers=headers, timeout=10)
    except requests.exceptions.Timeout:
        raise RuntimeError("AlienVault OTX API request timed out.")
    except requests.exceptions.RequestException as e:
        raise RuntimeError(f"AlienVault OTX connection error: {str(e)}")

    if response.status_code == 404:
        return {
            "indicator": clean_value,
            "indicator_type": indicator_type.lower(),
            "pulse_count": 0,
            "pulses": [],
            "references": [],
            "last_updated": None,
            "message": "Indicator not found in AlienVault OTX pulses."
        }

    if response.status_code == 401 or response.status_code == 403:
        raise RuntimeError("AlienVault OTX authentication failed: invalid or unauthorized API key.")

    if response.status_code == 429:
        raise RuntimeError("AlienVault OTX rate limit exceeded. Please try again later.")

    if response.status_code == 400:
        raise ValueError(f"AlienVault OTX rejected request: invalid parameter '{clean_value}'.")

    response.raise_for_status()

    try:
        raw_json = response.json()
        pulse_info = raw_json.get("pulse_info", {})
        pulse_count = pulse_info.get("count", 0)
        raw_pulses = pulse_info.get("pulses", [])

        pulses = []
        for p in raw_pulses[:5]:
            pulses.append({
                "id": p.get("id"),
                "name": p.get("name"),
                "created": p.get("created"),
                "tags": p.get("tags", []),
                "author": p.get("author_name")
            })

        references = pulse_info.get("references", [])[:5]
        base_indicator = raw_json.get("base_indicator", {})
        last_updated = base_indicator.get("modified") or raw_json.get("indicator")

    except Exception as e:
        raise ValueError(f"Failed to parse AlienVault OTX response JSON: {str(e)}")

    return {
        "indicator": clean_value,
        "indicator_type": indicator_type.lower(),
        "pulse_count": pulse_count,
        "pulses": pulses,
        "references": references,
        "last_updated": last_updated,
        "message": f"Associated with {pulse_count} OTX threat pulses"
    }
