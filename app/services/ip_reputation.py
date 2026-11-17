import requests
from flask import current_app


ABUSEIPDB_CHECK_URL = "https://api.abuseipdb.com/api/v2/check"


def check_ip_reputation(ip_address):
    """
    Check an IP address reputation using AbuseIPDB.
    """

    api_key = current_app.config.get("ABUSEIPDB_API_KEY")

    if not api_key:
        raise RuntimeError(
            "ABUSEIPDB_API_KEY is not configured."
        )

    params = {
        "ipAddress": ip_address,
        "maxAgeInDays": 90
    }

    headers = {
        "Accept": "application/json",
        "Key": api_key
    }

    response = requests.get(
        ABUSEIPDB_CHECK_URL,
        headers=headers,
        params=params,
        timeout=10
    )

    response.raise_for_status()

    return response.json()["data"]