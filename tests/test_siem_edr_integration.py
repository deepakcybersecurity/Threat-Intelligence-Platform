"""
Unit and Integration Tests for Task 8: SIEM & EDR Integration Engine
=====================================================================
Verifies:
1. API Healthcheck (/api/status)
2. Inbound Webhook Authentication (X-API-Key, Authorization Bearer, 401 on missing/invalid)
3. Ingestion of CrowdStrike Falcon EDR alert payloads
4. Ingestion of Microsoft Sentinel SIEM incident payloads
5. Ingestion of Splunk ES notable event payloads
6. Automated IOC extraction, deduplication, and risk scoring upon webhook ingest
7. Incident Alert creation in Alert Center (Alert table)
8. Bi-directional Real-Time IOC Lookup API (single and batch)
9. Firewall/EDR Sensor Blocklist Feeds (JSON and plaintext)
10. Dashboard UI Guide Route (/siem-edr-integration) with Authentication
"""

from datetime import datetime
import json
import unittest

from app import create_app, db
from app.models import User, Alert, ThreatIndicator, ThreatReport, Malware
from app.services.siem_edr_service import (
    authenticate_api_request,
    normalize_severity,
    normalize_alert_payload,
    ingest_siem_edr_alert,
    lookup_ioc,
    get_blocklist_data,
)


class TestSiemEdrIntegration(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.app = create_app()
        cls.app.config["TESTING"] = True
        cls.app.config["WTF_CSRF_ENABLED"] = False
        cls.app.config["SIEM_WEBHOOK_API_KEY"] = "test-siem-edr-key-2026"
        cls.client = cls.app.test_client()
        from app.services.security_service import assert_safe_test_database
        assert_safe_test_database(cls.app)

    def setUp(self):
        self.app_context = self.app.app_context()
        self.app_context.push()

        # Create or find test analyst
        self.analyst = User.query.filter_by(email="siem_analyst@test.com").first()
        if not self.analyst:
            self.analyst = User(
                username="siem_analyst",
                email="siem_analyst@test.com",
                password_hash="pbkdf2:sha256:dummyhash",
                role="analyst",
            )
            db.session.add(self.analyst)
            db.session.commit()

        self.client = self.app.test_client()
        self._cleanup()

    def tearDown(self):
        db.session.rollback()
        self._cleanup()
        self.app_context.pop()

    def _cleanup(self):
        # Scoped cleanup: remove ONLY test alerts and indicators created during this test suite
        test_alerts = Alert.query.filter(
            (Alert.title.like("%CrowdStrike%"))
            | (Alert.title.like("%Sentinel%"))
            | (Alert.title.like("%Splunk%"))
            | (Alert.title.like("Auth Check Alert%"))
            | (Alert.title.like("Bearer Auth Check Alert%"))
            | (Alert.title.like("%Test Alert%"))
            | (Alert.title.like("%SIEM/EDR Incident Alert%"))
        ).all()
        test_alert_ids = [a.id for a in test_alerts]
        if test_alert_ids:
            from app.models import AuditLog
            AuditLog.query.filter(
                AuditLog.target_table == "alerts",
                AuditLog.target_id.in_(test_alert_ids)
            ).delete(synchronize_session=False)
            for a in test_alerts:
                db.session.delete(a)

        test_indicators = ThreatIndicator.query.filter(
            ThreatIndicator.indicator_value.in_([
                "198.51.100.99",
                "203.0.113.55",
                "c2-beacon-malware.org",
                "suspicious-domain-sentinel.com",
                "0123456789abcdef0123456789abcdef",
                "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            ])
        ).all()
        for ind in test_indicators:
            ind.reports.clear()
            ind.malwares.clear()
            ind.alerts.clear()
            db.session.delete(ind)

        db.session.commit()

    def _login(self, user):
        with self.client.session_transaction() as sess:
            sess["_user_id"] = str(user.id)
            sess["_fresh"] = True

    # =========================================================================
    # 1. API STATUS & AUTHENTICATION TESTS
    # =========================================================================

    def test_api_status_endpoint(self):
        """Verifies GET /api/status returns operational status and registered routes."""
        resp = self.client.get("/api/status")
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertEqual(data["status"], "operational")
        self.assertIn("webhook_ingest", data["endpoints"])
        self.assertIn("ioc_lookup", data["endpoints"])
        self.assertIn("blocklist_json", data["endpoints"])

    def test_webhook_unauthorized_when_key_missing(self):
        """Verifies POST /api/v1/webhook/alert returns 401 when no API key is provided."""
        resp = self.client.post(
            "/api/v1/webhook/alert",
            json={"title": "Test Alert", "severity": "High"},
            headers={"Content-Type": "application/json"}
        )
        self.assertEqual(resp.status_code, 401)
        data = resp.get_json()
        self.assertFalse(data["success"])
        self.assertEqual(data["error"], "Unauthorized")

    def test_webhook_unauthorized_when_key_invalid(self):
        """Verifies POST /api/v1/webhook/alert returns 401 when invalid API key is provided."""
        resp = self.client.post(
            "/api/v1/webhook/alert",
            json={"title": "Test Alert", "severity": "High"},
            headers={
                "Content-Type": "application/json",
                "X-API-Key": "wrong-secret-key"
            }
        )
        self.assertEqual(resp.status_code, 401)

    def test_webhook_authorized_via_x_api_key(self):
        """Verifies authentication succeeds with valid X-API-Key header."""
        resp = self.client.post(
            "/api/v1/webhook/alert",
            json={
                "title": "Auth Check Alert",
                "source": "Splunk",
                "severity": "Low",
                "description": "Heartbeat test"
            },
            headers={
                "Content-Type": "application/json",
                "X-API-Key": "test-siem-edr-key-2026"
            }
        )
        self.assertEqual(resp.status_code, 201)
        data = resp.get_json()
        self.assertTrue(data["success"])

    def test_webhook_authorized_via_bearer_token(self):
        """Verifies authentication succeeds with Authorization: Bearer <key> header."""
        resp = self.client.post(
            "/api/v1/webhook/alert",
            json={
                "title": "Bearer Auth Check Alert",
                "source": "Sentinel",
                "severity": "Low",
                "description": "Bearer test"
            },
            headers={
                "Content-Type": "application/json",
                "Authorization": "Bearer test-siem-edr-key-2026"
            }
        )
        self.assertEqual(resp.status_code, 201)

    # =========================================================================
    # 2. VENDOR ALERT INGESTION & RISK SCORING TESTS
    # =========================================================================

    def test_crowdstrike_edr_alert_ingestion(self):
        """
        Verifies ingestion of CrowdStrike Falcon EDR payload with IP, domain, and hash.
        Checks IOC extraction, ThreatIndicator persistence, risk score computation,
        and primary incident Alert creation in Alert Center.
        """
        payload = {
            "DetectionName": "Suspicious PowerShell C2 Connection",
            "vendor": "CrowdStrike Falcon",
            "Severity": "Critical",
            "description": (
                "Powershell.exe established active network communication to 198.51.100.99:4444. "
                "Secondary beacon domain: c2-beacon-malware.org. File MD5 hash was "
                "0123456789abcdef0123456789abcdef."
            ),
        }

        resp = self.client.post(
            "/api/v1/webhook/alert",
            json=payload,
            headers={
                "Content-Type": "application/json",
                "X-API-Key": "test-siem-edr-key-2026"
            }
        )

        self.assertEqual(resp.status_code, 201)
        data = resp.get_json()
        self.assertTrue(data["success"])
        self.assertEqual(data["source"], "CrowdStrike Falcon")
        self.assertGreaterEqual(data["total_iocs_found"], 3)  # IP, domain, MD5
        self.assertGreaterEqual(data["max_risk_score"], 40)

        # Confirm indicator persisted in DB
        ind_ip = ThreatIndicator.query.filter_by(indicator_value="198.51.100.99").first()
        self.assertIsNotNone(ind_ip)
        self.assertEqual(ind_ip.indicator_type, "ipv4")
        self.assertIsNotNone(ind_ip.risk_score)

        ind_dom = ThreatIndicator.query.filter_by(indicator_value="c2-beacon-malware.org").first()
        self.assertIsNotNone(ind_dom)

        # Confirm incident alert created in Alert Center
        alert_rec = Alert.query.filter(Alert.title.like("%CrowdStrike Falcon%")).first()
        self.assertIsNotNone(alert_rec)
        self.assertEqual(alert_rec.alert_type, "SIEM/EDR")
        self.assertEqual(alert_rec.status, "Open")
        self.assertFalse(alert_rec.is_read)

    def test_microsoft_sentinel_incident_ingestion(self):
        """Verifies ingestion of Microsoft Sentinel incident with high severity and domain."""
        payload = {
            "incident_title": "TI Map: Host connected to known malicious domain",
            "product": "Microsoft Sentinel",
            "priority": "High",
            "details": "Alert triggered on DNS query for suspicious-domain-sentinel.com by host SRV-01.",
            "iocs": ["suspicious-domain-sentinel.com"]
        }

        resp = self.client.post(
            "/api/v1/webhook/alert",
            json=payload,
            headers={
                "Content-Type": "application/json",
                "X-API-Key": "test-siem-edr-key-2026"
            }
        )

        self.assertEqual(resp.status_code, 201)
        data = resp.get_json()
        self.assertTrue(data["success"])
        self.assertEqual(data["source"], "Microsoft Sentinel")

        dom_ind = ThreatIndicator.query.filter_by(indicator_value="suspicious-domain-sentinel.com").first()
        self.assertIsNotNone(dom_ind)
        self.assertEqual(dom_ind.indicator_type, "domain")

    def test_duplicate_ioc_reuse_on_repeated_ingestion(self):
        """Verifies that duplicate IOCs across multiple alerts update last_seen_at without duplicating records."""
        payload1 = {
            "title": "Initial Outbound Connection",
            "source": "Splunk ES",
            "severity": "Medium",
            "description": "Observed connection to 203.0.113.55.",
        }
        payload2 = {
            "title": "Repeated Outbound Connection",
            "source": "Splunk ES",
            "severity": "High",
            "description": "Second connection to 203.0.113.55 observed 5 minutes later.",
        }

        # First ingestion
        res1 = self.client.post(
            "/api/v1/webhook/alert",
            json=payload1,
            headers={"Content-Type": "application/json", "X-API-Key": "test-siem-edr-key-2026"}
        )
        self.assertEqual(res1.status_code, 201)
        self.assertEqual(res1.get_json()["indicators_created"], 1)

        # Second ingestion with same IP
        res2 = self.client.post(
            "/api/v1/webhook/alert",
            json=payload2,
            headers={"Content-Type": "application/json", "X-API-Key": "test-siem-edr-key-2026"}
        )
        self.assertEqual(res2.status_code, 201)
        self.assertEqual(res2.get_json()["indicators_reused"], 1)

        # Total indicators with this IP must be exactly 1
        count = ThreatIndicator.query.filter_by(indicator_value="203.0.113.55").count()
        self.assertEqual(count, 1)

    # =========================================================================
    # 3. REAL-TIME IOC LOOKUP API TESTS
    # =========================================================================

    def test_ioc_lookup_known_indicator(self):
        """Verifies GET /api/v1/ioc/lookup returns reputation, correlation, and SOC recommendation."""
        # Create known high risk indicator
        ind = ThreatIndicator(
            indicator_value="198.51.100.99",
            indicator_type="ipv4",
            severity="Critical",
            confidence_score=85,
            risk_score=80,
            status="Active",
            source="Test Threat Stream",
            added_by_user_id=self.analyst.id,
            first_seen_at=datetime.utcnow(),
            last_seen_at=datetime.utcnow(),
        )
        db.session.add(ind)
        db.session.commit()

        resp = self.client.get(
            "/api/v1/ioc/lookup?indicator=198.51.100.99",
            headers={"X-API-Key": "test-siem-edr-key-2026"}
        )
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertTrue(data["success"])
        self.assertTrue(data["known"])
        self.assertEqual(data["indicator"]["value"], "198.51.100.99")
        self.assertEqual(data["indicator"]["risk_level"], "CRITICAL")
        self.assertEqual(data["recommendation"], "BLOCK")

    def test_ioc_lookup_unknown_indicator(self):
        """Verifies GET /api/v1/ioc/lookup returns known=False for clean/untracked indicator."""
        resp = self.client.get(
            "/api/v1/ioc/lookup?indicator=10.0.0.1",
            headers={"X-API-Key": "test-siem-edr-key-2026"}
        )
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertTrue(data["success"])
        self.assertFalse(data["known"])
        self.assertEqual(data["recommendation"], "UNKNOWN")

    def test_batch_ioc_lookup(self):
        """Verifies POST /api/v1/ioc/lookup supports batch indicator query."""
        ind = ThreatIndicator(
            indicator_value="203.0.113.55",
            indicator_type="ipv4",
            severity="High",
            confidence_score=70,
            risk_score=65,
            status="Active",
            source="Batch Test",
            added_by_user_id=self.analyst.id,
            first_seen_at=datetime.utcnow(),
            last_seen_at=datetime.utcnow(),
        )
        db.session.add(ind)
        db.session.commit()

        resp = self.client.post(
            "/api/v1/ioc/lookup",
            json={"indicators": ["203.0.113.55", "unknown-domain-test.net"]},
            headers={
                "Content-Type": "application/json",
                "X-API-Key": "test-siem-edr-key-2026"
            }
        )
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertTrue(data["success"])
        self.assertEqual(data["count"], 2)
        self.assertTrue(data["results"][0]["known"])
        self.assertFalse(data["results"][1]["known"])

    # =========================================================================
    # 4. BLOCKLIST FEED API TESTS
    # =========================================================================

    def test_blocklist_feed_json(self):
        """Verifies GET /api/v1/feed/blocklist returns active high risk indicators in JSON."""
        ind = ThreatIndicator(
            indicator_value="198.51.100.99",
            indicator_type="ipv4",
            severity="Critical",
            risk_score=85,
            status="Active",
            source="Blocklist Test",
            added_by_user_id=self.analyst.id,
            first_seen_at=datetime.utcnow(),
            last_seen_at=datetime.utcnow(),
        )
        db.session.add(ind)
        db.session.commit()

        resp = self.client.get("/api/v1/feed/blocklist?min_risk=70")
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertTrue(data["success"])
        self.assertGreaterEqual(data["total"], 1)
        vals = [item["value"] for item in data["indicators"]]
        self.assertIn("198.51.100.99", vals)

    def test_blocklist_feed_plain_text(self):
        """Verifies GET /api/v1/feed/blocklist/plain returns newline-separated values for firewalls."""
        ind = ThreatIndicator(
            indicator_value="198.51.100.99",
            indicator_type="ipv4",
            severity="Critical",
            risk_score=85,
            status="Active",
            source="Blocklist Test",
            added_by_user_id=self.analyst.id,
            first_seen_at=datetime.utcnow(),
            last_seen_at=datetime.utcnow(),
        )
        db.session.add(ind)
        db.session.commit()

        resp = self.client.get("/api/v1/feed/blocklist/plain?type=ipv4")
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.mimetype, "text/plain")
        text = resp.get_data(as_text=True)
        self.assertIn("198.51.100.99", text)

    # =========================================================================
    # 5. UI VIEW & AUTHORIZATION TESTS
    # =========================================================================

    def test_siem_edr_integration_page_requires_auth(self):
        """Verifies unauthenticated access to /siem-edr-integration redirects to login."""
        unauth_client = self.app.test_client()
        resp = unauth_client.get("/siem-edr-integration")
        self.assertEqual(resp.status_code, 302)
        self.assertIn("/login", resp.headers["Location"])

    def test_siem_edr_integration_page_accessible_for_analyst(self):
        """Verifies authenticated analyst can view the integration hub with documentation and key."""
        self._login(self.analyst)
        resp = self.client.get("/siem-edr-integration")
        self.assertEqual(resp.status_code, 200)
        html = resp.get_data(as_text=True)
        self.assertIn("SIEM & EDR Integration Hub", html)
        self.assertIn("/api/v1/webhook/alert", html)
        self.assertIn("/api/v1/ioc/lookup", html)
        self.assertIn("Live Webhook Tester", html)


if __name__ == "__main__":
    unittest.main()
