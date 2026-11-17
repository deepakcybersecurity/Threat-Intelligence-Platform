"""
Comprehensive Unit and Integration Tests for Task 3: External IOC Enrichment Engine
=====================================================================================
Covers all 17 required test cases with mocked external HTTP requests:
1.  IPv4 -> AbuseIPDB
2.  Domain -> AlienVault OTX
3.  URL -> AlienVault OTX
4.  MD5 -> VirusTotal
5.  SHA1 -> VirusTotal
6.  SHA256 -> VirusTotal
7.  Unsupported IOC type
8.  Invalid IOC
9.  Missing API key
10. Timeout handling
11. HTTP 401 Unauthorized
12. HTTP 403 Forbidden
13. HTTP 429 Rate Limit
14. Malformed response
15. Successful normalized response & APICache
16. ThreatIndicator enrichment route
17. Unauthorized access
"""

import json
import unittest
from datetime import datetime, timedelta
from unittest.mock import patch, MagicMock

import requests
from flask import current_app

from app import create_app, db
from app.models import User, ThreatIndicator, APICache
from app.services.ioc_enrichment import (
    enrich_indicator,
    enrich_indicator_by_value,
    get_provider_for_type,
    _get_cached_enrichment,
    _set_cached_enrichment
)
from app.services.ip_reputation import check_ip_reputation
from app.services.virustotal import check_virustotal_hash, is_valid_hash
from app.services.otx import check_otx_indicator


class TestIOCEnrichmentEngine(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.app = create_app()
        cls.app.config["TESTING"] = True
        cls.app.config["WTF_CSRF_ENABLED"] = False
        cls.client = cls.app.test_client()

    def setUp(self):
        self.app_context = self.app.app_context()
        self.app_context.push()

        # Find or create a test analyst user
        self.user = User.query.filter_by(email="enrich_tester@test.com").first()
        if not self.user:
            self.user = User(
                username="enrich_tester",
                email="enrich_tester@test.com",
                password_hash="pbkdf2:sha256:dummyhash",
                role="analyst"
            )
            db.session.add(self.user)
            db.session.commit()

        # Clean test caches
        APICache.query.filter(APICache.endpoint.like("test_%")).delete()
        APICache.query.filter(APICache.endpoint.in_([
            "ipv4:8.8.8.8",
            "domain:malicious-domain.com",
            "url:https://malicious-domain.com/malware.exe",
            "md5:44d88612fea8a8f36de82e1278abb02f",
            "sha1:a9993e364706816aba3e25717850c26c9cd0d89d",
            "sha256:275a5071de6e79cd437d32e6f007e7729d2b2fe2e317180bc3946ac614289cfa",
            "ipv4:1.1.1.1",
            "ipv4:9.9.9.9"
        ])).delete()
        db.session.commit()

    def tearDown(self):
        db.session.rollback()
        # Clean up test indicators
        test_indicators = ThreatIndicator.query.filter(
            ThreatIndicator.indicator_value.in_([
                "8.8.8.8",
                "malicious-domain.com",
                "https://malicious-domain.com/malware.exe",
                "44d88612fea8a8f36de82e1278abb02f",
                "a9993e364706816aba3e25717850c26c9cd0d89d",
                "275a5071de6e79cd437d32e6f007e7729d2b2fe2e317180bc3946ac614289cfa",
                "1.1.1.1",
                "9.9.9.9"
            ])
        ).all()
        for ind in test_indicators:
            ind.reports.clear()
            db.session.delete(ind)
        db.session.commit()
        self.app_context.pop()

    def _login(self, client):
        with client.session_transaction() as sess:
            sess["_user_id"] = str(self.user.id)
            sess["_fresh"] = True

    # -------------------------------------------------------------------------
    # TEST 1: IPv4 -> AbuseIPDB
    # -------------------------------------------------------------------------
    @patch("requests.get")
    def test_1_ipv4_to_abuseipdb(self, mock_get):
        """TEST 1: IPv4 routes to AbuseIPDB with normalized output."""
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "data": {
                "ipAddress": "8.8.8.8",
                "abuseConfidenceScore": 15,
                "countryCode": "US",
                "countryName": "United States",
                "isp": "Google LLC",
                "domain": "google.com",
                "isTor": False,
                "isWhitelisted": True,
                "totalReports": 3,
                "numDistinctUsers": 2,
                "lastReportedAt": "2026-09-15T12:00:00+00:00"
            }
        }
        mock_get.return_value = mock_resp

        result = enrich_indicator_by_value("8.8.8.8", "ipv4")

        self.assertTrue(result["success"])
        self.assertEqual(result["provider"], "AbuseIPDB")
        self.assertEqual(result["indicator_type"], "ipv4")
        self.assertEqual(result["data"]["abuse_confidence_score"], 15)
        self.assertEqual(result["data"]["isp"], "Google LLC")
        self.assertFalse(result["cached"])

    # -------------------------------------------------------------------------
    # TEST 2: Domain -> AlienVault OTX
    # -------------------------------------------------------------------------
    @patch("requests.get")
    def test_2_domain_to_otx(self, mock_get):
        """TEST 2: Domain routes to AlienVault OTX with pulse metrics."""
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "indicator": "malicious-domain.com",
            "pulse_info": {
                "count": 4,
                "pulses": [
                    {"id": "p1", "name": "APT Campaign Pulse", "created": "2026-08-01", "tags": ["apt", "c2"]}
                ],
                "references": ["https://example.com/report1"]
            },
            "base_indicator": {"modified": "2026-08-10"}
        }
        mock_get.return_value = mock_resp

        result = enrich_indicator_by_value("malicious-domain.com", "domain")

        self.assertTrue(result["success"])
        self.assertEqual(result["provider"], "AlienVault OTX")
        self.assertEqual(result["data"]["pulse_count"], 4)
        self.assertEqual(len(result["data"]["pulses"]), 1)

    # -------------------------------------------------------------------------
    # TEST 3: URL -> AlienVault OTX
    # -------------------------------------------------------------------------
    @patch("requests.get")
    def test_3_url_to_otx(self, mock_get):
        """TEST 3: URL routes to AlienVault OTX with URL encoding."""
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "indicator": "https://malicious-domain.com/malware.exe",
            "pulse_info": {"count": 2, "pulses": []},
            "base_indicator": {"modified": "2026-09-01"}
        }
        mock_get.return_value = mock_resp

        result = enrich_indicator_by_value("https://malicious-domain.com/malware.exe", "url")

        self.assertTrue(result["success"])
        self.assertEqual(result["provider"], "AlienVault OTX")
        self.assertEqual(result["data"]["pulse_count"], 2)

    # -------------------------------------------------------------------------
    # TEST 4: MD5 -> VirusTotal
    # -------------------------------------------------------------------------
    @patch("requests.get")
    def test_4_md5_to_virustotal(self, mock_get):
        """TEST 4: MD5 hash routes to VirusTotal v3."""
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "data": {
                "attributes": {
                    "last_analysis_stats": {"malicious": 45, "suspicious": 2, "undetected": 10, "harmless": 0},
                    "reputation": -35,
                    "meaningful_name": "trojan.exe"
                }
            }
        }
        mock_get.return_value = mock_resp

        result = enrich_indicator_by_value("44d88612fea8a8f36de82e1278abb02f", "md5")

        self.assertTrue(result["success"])
        self.assertEqual(result["provider"], "VirusTotal")
        self.assertEqual(result["data"]["malicious_count"], 45)
        self.assertEqual(result["data"]["meaningful_name"], "trojan.exe")

    # -------------------------------------------------------------------------
    # TEST 5: SHA1 -> VirusTotal
    # -------------------------------------------------------------------------
    @patch("requests.get")
    def test_5_sha1_to_virustotal(self, mock_get):
        """TEST 5: SHA1 hash routes to VirusTotal v3."""
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "data": {
                "attributes": {
                    "last_analysis_stats": {"malicious": 12, "suspicious": 1, "undetected": 50, "harmless": 2},
                    "reputation": -10,
                    "meaningful_name": "downloader.dll"
                }
            }
        }
        mock_get.return_value = mock_resp

        result = enrich_indicator_by_value("a9993e364706816aba3e25717850c26c9cd0d89d", "sha1")

        self.assertTrue(result["success"])
        self.assertEqual(result["provider"], "VirusTotal")
        self.assertEqual(result["data"]["malicious_count"], 12)

    # -------------------------------------------------------------------------
    # TEST 6: SHA256 -> VirusTotal
    # -------------------------------------------------------------------------
    @patch("requests.get")
    def test_6_sha256_to_virustotal(self, mock_get):
        """TEST 6: SHA256 hash routes to VirusTotal v3."""
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "data": {
                "attributes": {
                    "last_analysis_stats": {"malicious": 60, "suspicious": 0, "undetected": 5, "harmless": 0},
                    "reputation": -70,
                    "meaningful_name": "ransomware.exe"
                }
            }
        }
        mock_get.return_value = mock_resp

        result = enrich_indicator_by_value(
            "275a5071de6e79cd437d32e6f007e7729d2b2fe2e317180bc3946ac614289cfa",
            "sha256"
        )

        self.assertTrue(result["success"])
        self.assertEqual(result["provider"], "VirusTotal")
        self.assertEqual(result["data"]["malicious_count"], 60)

    # -------------------------------------------------------------------------
    # TEST 7: Unsupported IOC Type
    # -------------------------------------------------------------------------
    def test_7_unsupported_ioc_type(self):
        """TEST 7: Unsupported IOC type does not call any provider and returns error."""
        result = enrich_indicator_by_value("CVE-2026-1234", "cve")

        self.assertFalse(result["success"])
        self.assertIsNone(result["provider"])
        self.assertIn("Unsupported IOC type", result["error"])

    # -------------------------------------------------------------------------
    # TEST 8: Invalid IOC
    # -------------------------------------------------------------------------
    def test_8_invalid_ioc(self):
        """TEST 8: Malformed or invalid IOC is safely rejected."""
        # Non-hex hash
        result = enrich_indicator_by_value("not_a_valid_hash_value_12345", "md5")
        self.assertFalse(result["success"])
        self.assertIn("Invalid file hash", result["error"])

        # None / empty indicator
        result2 = enrich_indicator_by_value("", "ipv4")
        self.assertFalse(result2["success"])

    # -------------------------------------------------------------------------
    # TEST 9: Missing API Key
    # -------------------------------------------------------------------------
    def test_9_missing_api_key(self):
        """TEST 9: Missing API key returns safe configuration error."""
        with patch.dict(self.app.config, {"VIRUSTOTAL_API_KEY": None}):
            result = enrich_indicator_by_value("44d88612fea8a8f36de82e1278abb02f", "md5")
            self.assertFalse(result["success"])
            self.assertIn("VIRUSTOTAL_API_KEY is not configured", result["error"])

    # -------------------------------------------------------------------------
    # TEST 10: Timeout Handling
    # -------------------------------------------------------------------------
    @patch("requests.get", side_effect=requests.exceptions.Timeout("Request timed out"))
    def test_10_timeout_handling(self, mock_get):
        """TEST 10: Network timeout is handled gracefully."""
        result = enrich_indicator_by_value("1.1.1.1", "ipv4")
        self.assertFalse(result["success"])
        self.assertIn("timed out", result["error"].lower())

    # -------------------------------------------------------------------------
    # TEST 11: HTTP 401 Unauthorized
    # -------------------------------------------------------------------------
    @patch("requests.get")
    def test_11_http_401_unauthorized(self, mock_get):
        """TEST 11: HTTP 401 Unauthorized is safely reported."""
        mock_resp = MagicMock()
        mock_resp.status_code = 401
        mock_get.return_value = mock_resp

        result = enrich_indicator_by_value("44d88612fea8a8f36de82e1278abb02f", "md5")
        self.assertFalse(result["success"])
        self.assertIn("authentication failed", result["error"].lower())

    # -------------------------------------------------------------------------
    # TEST 12: HTTP 403 Forbidden
    # -------------------------------------------------------------------------
    @patch("requests.get")
    def test_12_http_403_forbidden(self, mock_get):
        """TEST 12: HTTP 403 Forbidden is safely reported."""
        mock_resp = MagicMock()
        mock_resp.status_code = 403
        mock_get.return_value = mock_resp

        result = enrich_indicator_by_value("evil.com", "domain")
        self.assertFalse(result["success"])
        self.assertIn("authentication failed", result["error"].lower())

    # -------------------------------------------------------------------------
    # TEST 13: HTTP 429 Rate Limit
    # -------------------------------------------------------------------------
    @patch("requests.get")
    def test_13_http_429_rate_limit(self, mock_get):
        """TEST 13: HTTP 429 Rate Limit is safely reported."""
        mock_resp = MagicMock()
        mock_resp.status_code = 429
        mock_get.return_value = mock_resp

        result = enrich_indicator_by_value("44d88612fea8a8f36de82e1278abb02f", "md5")
        self.assertFalse(result["success"])
        self.assertIn("rate limit exceeded", result["error"].lower())

    # -------------------------------------------------------------------------
    # TEST 14: Malformed Response
    # -------------------------------------------------------------------------
    @patch("requests.get")
    def test_14_malformed_response(self, mock_get):
        """TEST 14: Non-JSON or malformed responses are handled safely."""
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.side_effect = ValueError("Invalid JSON string")
        mock_get.return_value = mock_resp

        result = enrich_indicator_by_value("44d88612fea8a8f36de82e1278abb02f", "md5")
        self.assertFalse(result["success"])
        self.assertIn("Failed to parse", result["error"])

    # -------------------------------------------------------------------------
    # TEST 15: Successful Normalized Response & APICache Integration
    # -------------------------------------------------------------------------
    @patch("requests.get")
    def test_15_cache_hit_and_database_persistence(self, mock_get):
        """TEST 15: Successful response is stored in APICache and served from cache on subsequent calls."""
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "data": {
                "ipAddress": "9.9.9.9",
                "abuseConfidenceScore": 0,
                "countryCode": "US",
                "isp": "Quad9",
                "isTor": False,
                "totalReports": 0
            }
        }
        mock_get.return_value = mock_resp

        # First call: cache miss, queries mock
        res1 = enrich_indicator_by_value("9.9.9.9", "ipv4")
        self.assertTrue(res1["success"])
        self.assertFalse(res1["cached"])
        self.assertEqual(mock_get.call_count, 1)

        # Verify entry exists in APICache table
        cached_row = APICache.query.filter_by(
            api_name="AbuseIPDB",
            endpoint="ipv4:9.9.9.9"
        ).first()
        self.assertIsNotNone(cached_row, "Response must be persisted to APICache table")

        # Second call: cache hit, does not call mock_get again
        res2 = enrich_indicator_by_value("9.9.9.9", "ipv4")
        self.assertTrue(res2["success"])
        self.assertTrue(res2["cached"], "Second call must return cached=True")
        self.assertEqual(mock_get.call_count, 1, "mock_get should not be called on cache hit")

    # -------------------------------------------------------------------------
    # TEST 16: ThreatIndicator Enrichment Route (POST /threat-indicator/<id>/enrich)
    # -------------------------------------------------------------------------
    @patch("requests.get")
    def test_16_enrichment_route_success(self, mock_get):
        """TEST 16: Authenticated POST to /threat-indicator/<id>/enrich enriches ThreatIndicator."""
        self._login(self.client)

        indicator = ThreatIndicator(
            indicator_value="8.8.8.8",
            indicator_type="ipv4",
            confidence_score=50,
            severity="Medium",
            status="Active",
            source="Threat Report",
            added_by_user_id=self.user.id
        )
        db.session.add(indicator)
        db.session.commit()

        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "data": {
                "ipAddress": "8.8.8.8",
                "abuseConfidenceScore": 5,
                "countryCode": "US",
                "isp": "Google LLC"
            }
        }
        mock_get.return_value = mock_resp

        response = self.client.post(f"/threat-indicator/{indicator.id}/enrich")
        self.assertEqual(response.status_code, 200)

        data = response.get_json()
        self.assertTrue(data["success"])
        self.assertEqual(data["provider"], "AbuseIPDB")
        self.assertEqual(data["indicator"], "8.8.8.8")

        # Confirm indicator severity and confidence were NOT altered
        db.session.refresh(indicator)
        self.assertEqual(indicator.severity, "Medium")
        self.assertEqual(indicator.confidence_score, 50)

    # -------------------------------------------------------------------------
    # TEST 17: Unauthorized Access
    # -------------------------------------------------------------------------
    def test_17_unauthorized_access(self):
        """TEST 17: Unauthenticated request to enrichment route is redirected or rejected."""
        indicator = ThreatIndicator(
            indicator_value="8.8.8.8",
            indicator_type="ipv4",
            confidence_score=50,
            severity="Medium",
            status="Active",
            source="Threat Report",
            added_by_user_id=self.user.id
        )
        db.session.add(indicator)
        db.session.commit()

        # Unauthenticated client request
        client = self.app.test_client()
        response = client.post(f"/threat-indicator/{indicator.id}/enrich")

        # Flask-Login redirects unauthenticated requests with HTTP 302 to login page
        self.assertIn(response.status_code, [302, 401])


if __name__ == "__main__":
    unittest.main()
