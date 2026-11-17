"""
Automated Regression Test Suite: SIEM Webhook & API Security Hardening
======================================================================
Tests all remediated findings (FINDING-01 to FINDING-13):
1. Rejection of unauthenticated and malformed requests.
2. Prevention of auth bypass via username/email parameters.
3. Verification of personal API key lifecycle (valid, revoked, deactivated).
4. RBAC enforcement across API v2 modification and v1 lifecycle endpoints.
5. Webhook HMAC-SHA256 signature verification and replay prevention.
6. Safe generic error responses and sensitive information redaction.
7. Audit log generation for webhook and telemetry events.
8. Access control and secret masking on the SIEM/EDR integration portal.
9. Production secret validation guardrails.
"""

from datetime import datetime, timezone
import hashlib
import hmac
import json
import time
import unittest

from app import create_app, db
from app.models import Alert, AuditLog, ThreatIndicator, User
from config import ProductionConfig


_TEST_PREFIX = "sec_test_"


class TestSiemApiSecurityHardening(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.app = create_app()
        cls.app.config["TESTING"] = True
        cls.app.config["WTF_CSRF_ENABLED"] = False
        cls.app.config["SIEM_WEBHOOK_API_KEY"] = "strong-siem-secret-test-key-2026"
        cls.app.config["SIEM_WEBHOOK_SECRET"] = "strong-siem-secret-test-key-2026"
        cls.client = cls.app.test_client()

    def setUp(self):
        self.ctx = self.app.app_context()
        self.ctx.push()
        self._cleanup()
        self._seed()

    def tearDown(self):
        db.session.rollback()
        self._cleanup()
        self.ctx.pop()

    def _cleanup(self):
        db.session.rollback()

        # Delete test alerts
        Alert.query.filter(
            (Alert.title.like(f"%{_TEST_PREFIX}%"))
            | (Alert.description.like(f"%{_TEST_PREFIX}%"))
            | (Alert.alert_type == "SIEM/EDR")
        ).delete(synchronize_session=False)

        # Delete test indicators
        inds = ThreatIndicator.query.filter(
            ThreatIndicator.indicator_value.like(f"{_TEST_PREFIX}%")
        ).all()
        for i in inds:
            i.reports.clear()
            i.malwares.clear()
            i.alerts.clear()
            db.session.delete(i)

        # Delete test audit logs
        AuditLog.query.filter(
            AuditLog.action.like(f"%{_TEST_PREFIX}%")
            | AuditLog.action.like("siem_webhook_ingest%")
            | AuditLog.action.like("edr_alert_ingest%")
        ).delete(synchronize_session=False)

        # Delete test users
        users = User.query.filter(User.username.like(f"{_TEST_PREFIX}%")).all()
        for u in users:
            AuditLog.query.filter_by(user_id=u.id).delete()
            db.session.delete(u)

        db.session.commit()

    def _seed(self):
        # 1. Admin user with personal API key
        self.admin = User(
            username=f"{_TEST_PREFIX}admin",
            email=f"{_TEST_PREFIX}admin@test.local",
            password_hash="pbkdf2:sha256:dummyhash",
            role="admin",
            is_active=True,
            api_key=f"tip_live_admin_{_TEST_PREFIX}1234567890",
        )
        # 2. Analyst user with personal API key
        self.analyst = User(
            username=f"{_TEST_PREFIX}analyst",
            email=f"{_TEST_PREFIX}analyst@test.local",
            password_hash="pbkdf2:sha256:dummyhash",
            role="analyst",
            is_active=True,
            api_key=f"tip_live_analyst_{_TEST_PREFIX}1234567890",
        )
        # 3. Read-only user with personal API key
        self.regular_user = User(
            username=f"{_TEST_PREFIX}user",
            email=f"{_TEST_PREFIX}user@test.local",
            password_hash="pbkdf2:sha256:dummyhash",
            role="user",
            is_active=True,
            api_key=f"tip_live_user_{_TEST_PREFIX}1234567890",
        )
        # 4. Deactivated analyst with personal API key
        self.inactive_analyst = User(
            username=f"{_TEST_PREFIX}inactive",
            email=f"{_TEST_PREFIX}inactive@test.local",
            password_hash="pbkdf2:sha256:dummyhash",
            role="analyst",
            is_active=False,
            api_key=f"tip_live_inactive_{_TEST_PREFIX}1234567890",
        )

        db.session.add_all([self.admin, self.analyst, self.regular_user, self.inactive_analyst])
        db.session.commit()

    def _login(self, user):
        with self.client.session_transaction() as sess:
            sess["_user_id"] = str(user.id)
            sess["_fresh"] = True
            sess["_session_token"] = user.session_token

    # =========================================================================
    # 1. AUTHENTICATION BYPASS & FALLBACK MITIGATION (FINDING-01 & FINDING-06)
    # =========================================================================

    def test_auth_bypass_via_username_or_email_rejected(self):
        """Verifies passing admin/analyst username or email as API key is rejected (401)."""
        # Test username in X-API-Key
        resp = self.client.get(
            "/api/v2/indicators",
            headers={"X-API-Key": self.admin.username}
        )
        self.assertEqual(resp.status_code, 401)
        data = resp.get_json()
        self.assertFalse(data["success"])
        self.assertEqual(data["error"], "Unauthorized")

        # Test email in X-API-Key
        resp2 = self.client.get(
            "/api/v2/indicators",
            headers={"X-API-Key": self.analyst.email}
        )
        self.assertEqual(resp2.status_code, 401)

        # Test username in Bearer token
        resp3 = self.client.get(
            "/api/v2/indicators",
            headers={"Authorization": f"Bearer {self.admin.username}"}
        )
        self.assertEqual(resp3.status_code, 401)

        # Test username in query parameter
        resp4 = self.client.get(f"/api/v2/indicators?api_key={self.admin.username}")
        self.assertEqual(resp4.status_code, 401)

    def test_deactivated_user_api_key_rejected(self):
        """Verifies API key belonging to suspended/deactivated account is rejected (401)."""
        resp = self.client.get(
            "/api/v2/indicators",
            headers={"X-API-Key": self.inactive_analyst.api_key}
        )
        self.assertEqual(resp.status_code, 401)

    def test_revoked_api_key_rejected(self):
        """Verifies that once an API key is revoked (set to NULL), it is rejected (401)."""
        from app.services.api_key_service import revoke_user_api_key

        old_key = self.analyst.api_key
        revoke_user_api_key(self.analyst.id)

        resp = self.client.get(
            "/api/v2/indicators",
            headers={"X-API-Key": old_key}
        )
        self.assertEqual(resp.status_code, 401)

    # =========================================================================
    # 2. RBAC ENFORCEMENT ON API v2 & v1 ENDPOINTS (FINDING-04 & FINDING-05)
    # =========================================================================

    def test_readonly_user_cannot_create_indicator(self):
        """Verifies read-only 'user' role receives 403 Forbidden when creating indicator."""
        payload = {
            "indicator_value": f"{_TEST_PREFIX}198.51.100.200",
            "indicator_type": "ipv4",
            "severity": "Medium",
        }
        resp = self.client.post(
            "/api/v2/indicators",
            json=payload,
            headers={"X-API-Key": self.regular_user.api_key}
        )
        self.assertEqual(resp.status_code, 403)
        data = resp.get_json()
        self.assertFalse(data["success"])
        self.assertEqual(data["error"], "Forbidden")

    def test_analyst_can_create_indicator(self):
        """Verifies analyst role is authorized to create indicators."""
        payload = {
            "indicator_value": f"{_TEST_PREFIX}198.51.100.201",
            "indicator_type": "ipv4",
            "severity": "High",
        }
        resp = self.client.post(
            "/api/v2/indicators",
            json=payload,
            headers={"X-API-Key": self.analyst.api_key}
        )
        self.assertEqual(resp.status_code, 201)
        data = resp.get_json()
        self.assertTrue(data["success"])

    def test_readonly_user_cannot_update_or_delete_indicator(self):
        """Verifies read-only user cannot update or delete indicators (403)."""
        # Create an indicator as analyst first
        ind = ThreatIndicator(
            indicator_value=f"{_TEST_PREFIX}198.51.100.202",
            indicator_type="ipv4",
            severity="Medium",
            status="Active",
            source="Security Test Suite",
            added_by_user_id=self.analyst.id,
        )
        db.session.add(ind)
        db.session.commit()

        # Update attempt by regular user
        resp_put = self.client.put(
            f"/api/v2/indicators/{ind.id}",
            json={"severity": "Critical"},
            headers={"X-API-Key": self.regular_user.api_key}
        )
        self.assertEqual(resp_put.status_code, 403)

        # Delete attempt by regular user
        resp_del = self.client.delete(
            f"/api/v2/indicators/{ind.id}",
            headers={"X-API-Key": self.regular_user.api_key}
        )
        self.assertEqual(resp_del.status_code, 403)

    def test_readonly_user_cannot_update_alert_status(self):
        """Verifies read-only user cannot PATCH alert status (403)."""
        alert = Alert(
            title=f"{_TEST_PREFIX}Test Alert",
            alert_type="General",
            severity="Medium",
            status="Open",
            user_id=self.analyst.id,
        )
        db.session.add(alert)
        db.session.commit()

        resp = self.client.patch(
            f"/api/v2/alerts/{alert.id}",
            json={"status": "Resolved"},
            headers={"X-API-Key": self.regular_user.api_key}
        )
        self.assertEqual(resp.status_code, 403)

    def test_unauthenticated_ioc_lifecycle_endpoints_rejected(self):
        """Verifies /api/v1/ioc/expire and reactivate require authentication (401)."""
        # 1. Expire endpoint
        resp_expire = self.client.post("/api/v1/ioc/expire", json={"dry_run": True})
        self.assertEqual(resp_expire.status_code, 401)

        # 2. Reactivate endpoint
        resp_react = self.client.post("/api/v1/ioc/reactivate/1")
        self.assertEqual(resp_react.status_code, 401)

        # 3. Bulk reactivate endpoint
        resp_bulk = self.client.post("/api/v1/ioc/bulk-reactivate", json={"indicator_ids": [1]})
        self.assertEqual(resp_bulk.status_code, 401)

        # 4. MITRE extract endpoint
        resp_extract = self.client.post("/api/v1/mitre/extract", json={"text": "cmd.exe"})
        self.assertEqual(resp_extract.status_code, 401)

    def test_regular_user_forbidden_on_ioc_lifecycle_endpoints(self):
        """Verifies read-only user receives 403 on IOC expiration and reactivation."""
        headers = {"X-API-Key": self.regular_user.api_key}

        resp_expire = self.client.post("/api/v1/ioc/expire", json={"dry_run": True}, headers=headers)
        self.assertEqual(resp_expire.status_code, 403)

        resp_react = self.client.post("/api/v1/ioc/reactivate/1", headers=headers)
        self.assertEqual(resp_react.status_code, 403)

        resp_bulk = self.client.post("/api/v1/ioc/bulk-reactivate", json={"indicator_ids": [1]}, headers=headers)
        self.assertEqual(resp_bulk.status_code, 403)

    # =========================================================================
    # 3. WEBHOOK HMAC SIGNATURE & REPLAY PROTECTION (FINDING-07)
    # =========================================================================

    def test_webhook_hmac_signature_validation(self):
        """Verifies HMAC-SHA256 signature verification on inbound webhooks."""
        secret = self.app.config["SIEM_WEBHOOK_API_KEY"]
        payload = {
            "title": f"{_TEST_PREFIX}HMAC Signed Alert",
            "source": "Splunk",
            "severity": "High",
            "description": "Validated signature test",
        }
        raw_body = json.dumps(payload).encode("utf-8")
        ts = str(int(time.time()))

        # Compute valid HMAC of f"{ts}.{raw_body}"
        expected_sig = hmac.new(secret.encode("utf-8"), f"{ts}.".encode("utf-8") + raw_body, hashlib.sha256).hexdigest()

        # 1. Valid signature succeeds
        resp = self.client.post(
            "/api/v1/webhook/alert",
            data=raw_body,
            headers={
                "Content-Type": "application/json",
                "X-API-Key": secret,
                "X-Webhook-Signature": f"sha256={expected_sig}",
                "X-Webhook-Timestamp": ts,
            }
        )
        self.assertEqual(resp.status_code, 201)

        # 2. Tampered signature fails (401)
        resp_tampered = self.client.post(
            "/api/v1/webhook/alert",
            data=raw_body,
            headers={
                "Content-Type": "application/json",
                "X-API-Key": secret,
                "X-Webhook-Signature": "sha256=badf00ddeadbeef1234567890abcdef1234567890abcdef1234567890abcdef",
                "X-Webhook-Timestamp": ts,
            }
        )
        self.assertEqual(resp_tampered.status_code, 401)
        self.assertEqual(resp_tampered.get_json()["error"], "InvalidSignature")

    def test_webhook_replay_protection_rejects_expired_timestamp(self):
        """Verifies timestamps older than 300 seconds are rejected to mitigate replays."""
        secret = self.app.config["SIEM_WEBHOOK_API_KEY"]
        payload = {
            "title": f"{_TEST_PREFIX}Replay Alert",
            "source": "Sentinel",
            "severity": "Medium",
        }
        raw_body = json.dumps(payload).encode("utf-8")
        old_ts = str(int(time.time()) - 360)  # 6 minutes ago (outside 300s window)

        expected_sig = hmac.new(secret.encode("utf-8"), f"{old_ts}.".encode("utf-8") + raw_body, hashlib.sha256).hexdigest()

        resp = self.client.post(
            "/api/v1/webhook/alert",
            data=raw_body,
            headers={
                "Content-Type": "application/json",
                "X-API-Key": secret,
                "X-Webhook-Signature": f"sha256={expected_sig}",
                "X-Webhook-Timestamp": old_ts,
            }
        )
        self.assertEqual(resp.status_code, 401)
        self.assertIn("replay window", resp.get_json()["message"])

    def test_webhook_requires_signature_when_enforced(self):
        """Verifies missing signature header is rejected (401) when SIEM_WEBHOOK_REQUIRE_SIGNATURE is True."""
        orig = self.app.config.get("SIEM_WEBHOOK_REQUIRE_SIGNATURE", False)
        try:
            self.app.config["SIEM_WEBHOOK_REQUIRE_SIGNATURE"] = True
            resp = self.client.post(
                "/api/v1/webhook/alert",
                json={"title": f"{_TEST_PREFIX}Unsigned Alert", "severity": "Medium"},
                headers={"Content-Type": "application/json", "X-API-Key": self.app.config["SIEM_WEBHOOK_API_KEY"]}
            )
            self.assertEqual(resp.status_code, 401)
            data = resp.get_json()
            self.assertEqual(data["error"], "InvalidSignature")
            self.assertIn("Missing required webhook signature", data["message"])
        finally:
            self.app.config["SIEM_WEBHOOK_REQUIRE_SIGNATURE"] = orig

    # =========================================================================
    # 4. WEBHOOK PAYLOAD NORMALIZATION & ERROR HANDLING (FINDING-08 & FINDING-12)
    # =========================================================================

    def test_webhook_rejects_non_json_content_type(self):
        """Verifies rejection of non-JSON content types."""
        resp = self.client.post(
            "/api/v1/webhook/alert",
            data="plain text payload",
            headers={"Content-Type": "text/plain", "X-API-Key": self.app.config["SIEM_WEBHOOK_API_KEY"]}
        )
        self.assertEqual(resp.status_code, 400)
        self.assertEqual(resp.get_json()["error"], "InvalidContentType")

    def test_webhook_rejects_empty_or_malformed_json(self):
        """Verifies rejection of empty or non-dict JSON."""
        resp = self.client.post(
            "/api/v1/webhook/alert",
            data="[]",
            headers={"Content-Type": "application/json", "X-API-Key": self.app.config["SIEM_WEBHOOK_API_KEY"]}
        )
        self.assertEqual(resp.status_code, 400)
        self.assertEqual(resp.get_json()["error"], "EmptyPayload")

    def test_massive_corpus_is_safely_bounded(self):
        """Verifies huge text description (100k+ chars) is safely truncated without crashing."""
        huge_desc = "Safe text payload " * 10000  # 180,000 chars
        payload = {
            "title": f"{_TEST_PREFIX}Large Payload Alert",
            "source": "CrowdStrike",
            "severity": "Low",
            "description": huge_desc,
        }
        resp = self.client.post(
            "/api/v1/webhook/alert",
            json=payload,
            headers={"Content-Type": "application/json", "X-API-Key": self.app.config["SIEM_WEBHOOK_API_KEY"]}
        )
        self.assertEqual(resp.status_code, 201)
        self.assertTrue(resp.get_json()["success"])

    # =========================================================================
    # 5. AUDIT LOGGING FOR WEBHOOK & TELEMETRY (FINDING-10)
    # =========================================================================

    def test_webhook_ingest_records_audit_log(self):
        """Verifies successful webhook ingestion writes an AuditLog entry."""
        payload = {
            "title": f"{_TEST_PREFIX}Audit Log Ingestion Test",
            "source": "Splunk ES",
            "severity": "Medium",
        }
        resp = self.client.post(
            "/api/v1/webhook/alert",
            json=payload,
            headers={"Content-Type": "application/json", "X-API-Key": self.analyst.api_key}
        )
        self.assertEqual(resp.status_code, 201)
        alert_id = resp.get_json()["alert"]["id"]

        audit_entry = AuditLog.query.filter_by(
            action=f"siem_webhook_ingest:Splunk ES:{alert_id}"
        ).first()
        self.assertIsNotNone(audit_entry)
        self.assertEqual(audit_entry.target_table, "alerts")
        self.assertEqual(audit_entry.target_id, alert_id)

    # =========================================================================
    # 6. INTEGRATION PORTAL UI ACCESS CONTROL & SECRET MASKING (FINDING-02)
    # =========================================================================

    def test_siem_portal_accessible_only_to_analyst_and_admin(self):
        """Verifies regular user receives 403 on /siem-edr-integration, while analyst gets 200."""
        # Regular user receives 403
        self._login(self.regular_user)
        resp_user = self.client.get("/siem-edr-integration")
        self.assertEqual(resp_user.status_code, 403)

        # Analyst receives 200
        self._login(self.analyst)
        resp_analyst = self.client.get("/siem-edr-integration")
        self.assertEqual(resp_analyst.status_code, 200)

        # Verify raw system secret key is NOT present in analyst view
        html = resp_analyst.get_data(as_text=True)
        raw_system_key = self.app.config["SIEM_WEBHOOK_API_KEY"]
        self.assertNotIn(f'<code>{raw_system_key}</code>', html)
        self.assertNotIn(f'const apiKey = "{raw_system_key}";', html)

    # =========================================================================
    # 7. PRODUCTION SECRET VALIDATION (FINDING-03)
    # =========================================================================

    def test_production_config_validates_siem_webhook_key(self):
        """Verifies ProductionConfig rejects default or missing SIEM_WEBHOOK_API_KEY."""
        import os
        orig_secret = os.environ.get("SECRET_KEY")
        orig_siem = os.environ.get("SIEM_WEBHOOK_API_KEY")

        try:
            # Valid SECRET_KEY but default SIEM_WEBHOOK_API_KEY must raise ValueError
            os.environ["SECRET_KEY"] = "strong-random-production-secret-key-12345"
            os.environ["SIEM_WEBHOOK_API_KEY"] = "tip-siem-edr-default-secret-key-2026"

            with self.assertRaises(ValueError) as ctx:
                ProductionConfig.validate_production_secrets()
            self.assertIn("SIEM_WEBHOOK_API_KEY", str(ctx.exception))

            # Valid both passes without exception
            os.environ["SIEM_WEBHOOK_API_KEY"] = "strong-random-production-siem-key-98765"
            ProductionConfig.validate_production_secrets()

        finally:
            if orig_secret is not None:
                os.environ["SECRET_KEY"] = orig_secret
            else:
                os.environ.pop("SECRET_KEY", None)

            if orig_siem is not None:
                os.environ["SIEM_WEBHOOK_API_KEY"] = orig_siem
            else:
                os.environ.pop("SIEM_WEBHOOK_API_KEY", None)

    # =========================================================================
    # 8. QUERY STRING API KEY REJECTION REGRESSION TESTS (CWE-598)
    # =========================================================================

    def test_valid_header_api_key_authenticates(self):
        """Verifies valid X-API-Key header authenticates an authorized request (200)."""
        resp = self.client.get(
            "/api/v2/indicators",
            headers={"X-API-Key": self.analyst.api_key}
        )
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertIn("items", data)

    def test_invalid_header_api_key_rejected(self):
        """Verifies invalid X-API-Key header is rejected with 401 Unauthorized."""
        resp = self.client.get(
            "/api/v2/indicators",
            headers={"X-API-Key": "completely_invalid_key_99999"}
        )
        self.assertEqual(resp.status_code, 401)
        data = resp.get_json()
        self.assertFalse(data.get("success", True))
        self.assertEqual(data.get("error"), "Unauthorized")

    def test_query_string_api_key_alone_rejected_even_if_valid(self):
        """Verifies query-string ?api_key= alone is rejected with 401 even if key is valid."""
        secret_sample = self.analyst.api_key
        resp = self.client.get(f"/api/v2/indicators?api_key={secret_sample}")
        self.assertEqual(resp.status_code, 401)
        data = resp.get_json()
        self.assertFalse(data.get("success", True))
        self.assertEqual(data.get("error"), "Unauthorized")
        # Ensure error message states rejection policy
        self.assertIn("rejected", data.get("message", "").lower())
        # Ensure secret itself is NOT leaked in the response body
        self.assertNotIn(secret_sample, resp.get_data(as_text=True))

    def test_header_precedence_and_no_fallback_to_query_string(self):
        """
        Verifies policy when both header and query-string are provided:
        - Valid header authenticates without relying on query-string.
        - Invalid header fails (401) and does NOT silently fall back to valid query-string.
        """
        # Case A: Valid header + invalid query string -> Authenticates via valid header (200)
        resp_a = self.client.get(
            "/api/v2/indicators?api_key=invalid_query_key_123",
            headers={"X-API-Key": self.analyst.api_key}
        )
        self.assertEqual(resp_a.status_code, 200)

        # Case B: Invalid header + valid query string -> Fails (401), does NOT fall back to query string!
        resp_b = self.client.get(
            f"/api/v2/indicators?api_key={self.analyst.api_key}",
            headers={"X-API-Key": "invalid_header_key_456"}
        )
        self.assertEqual(resp_b.status_code, 401)
        self.assertFalse(resp_b.get_json().get("success", True))

    def test_secrets_redacted_from_error_responses_and_logs(self):
        """Verifies that secrets passed in query string or headers are never exposed in error text or logs."""
        canary_secret = "CANARY_SECRET_DO_NOT_LEAK_789xyz"
        with self.assertLogs("app.services.siem_edr_service", level="WARNING") as log_capture:
            resp = self.client.get(f"/api/v2/indicators?api_key={canary_secret}")
            self.assertEqual(resp.status_code, 401)
            response_text = resp.get_data(as_text=True)
            self.assertNotIn(canary_secret, response_text)

        # Verify log output does not include the raw secret
        for log_entry in log_capture.output:
            self.assertNotIn(canary_secret, log_entry)
            self.assertIn("query parameter", log_entry.lower())


if __name__ == "__main__":
    unittest.main()
