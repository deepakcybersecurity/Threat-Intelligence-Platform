"""
VirusTotal API v3 Service
=========================
Queries VirusTotal for file hash reputation and analysis statistics (MD5, SHA1, SHA256).
"""

import re
import requests
from flask import current_app

VIRUSTOTAL_FILE_URL = "https://www.virustotal.com/api/v3/files/{file_hash}"

HASH_PATTERNS = {
    "md5": re.compile(r"^[a-fA-F0-9]{32}$"),
    "sha1": re.compile(r"^[a-fA-F0-9]{40}$"),
    "sha256": re.compile(r"^[a-fA-F0-9]{64}$"),
}


def is_valid_hash(file_hash: str, hash_type: str = None) -> bool:
    """Validate that the hash string matches the expected hex length and characters."""
    if not file_hash or not isinstance(file_hash, str):
        return False
    val = file_hash.strip().lower()
    if hash_type:
        pattern = HASH_PATTERNS.get(hash_type.lower())
        return bool(pattern and pattern.match(val))
    return any(p.match(val) for p in HASH_PATTERNS.values())


def check_virustotal_hash(file_hash: str, hash_type: str = None) -> dict:
    """
    Query VirusTotal API v3 for report data on MD5, SHA1, or SHA256 hash.

    Returns:
        dict: Normalized payload containing analysis stats and reputation.
    """
    clean_hash = file_hash.strip().lower() if file_hash else ""
    if not is_valid_hash(clean_hash, hash_type):
        raise ValueError(f"Invalid file hash provided: '{file_hash}'.")

    api_key = current_app.config.get("VIRUSTOTAL_API_KEY")
    if not api_key:
        raise RuntimeError("VIRUSTOTAL_API_KEY is not configured.")

    url = VIRUSTOTAL_FILE_URL.format(file_hash=clean_hash)
    headers = {
        "x-apikey": api_key,
        "Accept": "application/json"
    }

    try:
        response = requests.get(url, headers=headers, timeout=10)
    except requests.exceptions.Timeout:
        raise RuntimeError("VirusTotal API request timed out.")
    except requests.exceptions.RequestException as e:
        raise RuntimeError(f"VirusTotal connection error: {str(e)}")

    if response.status_code == 404:
        return {
            "hash": clean_hash,
            "found": False,
            "malicious_count": 0,
            "suspicious_count": 0,
            "harmless_count": 0,
            "undetected_count": 0,
            "reputation": 0,
            "meaningful_name": "Unknown",
            "last_analysis_date": None,
            "message": "Hash not found in VirusTotal database"
        }

    if response.status_code == 401 or response.status_code == 403:
        raise RuntimeError("VirusTotal authentication failed: invalid or unauthorized API key.")

    if response.status_code == 429:
        raise RuntimeError("VirusTotal rate limit exceeded. Please try again later.")

    if response.status_code == 400:
        raise ValueError(f"VirusTotal rejected request: invalid hash parameter '{clean_hash}'.")

    response.raise_for_status()

    try:
        raw_json = response.json()
        data = raw_json.get("data", {})
        attributes = data.get("attributes", {})
        stats = attributes.get("last_analysis_stats", {})
    except Exception as e:
        raise ValueError(f"Failed to parse VirusTotal response JSON: {str(e)}")

    return {
        "hash": clean_hash,
        "found": True,
        "malicious_count": stats.get("malicious", 0),
        "suspicious_count": stats.get("suspicious", 0),
        "harmless_count": stats.get("harmless", 0),
        "undetected_count": stats.get("undetected", 0),
        "reputation": attributes.get("reputation", 0),
        "meaningful_name": attributes.get("meaningful_name") or attributes.get("type_description", "N/A"),
        "last_analysis_date": attributes.get("last_analysis_date"),
        "message": f"Detected by {stats.get('malicious', 0)} security vendors"
    }
