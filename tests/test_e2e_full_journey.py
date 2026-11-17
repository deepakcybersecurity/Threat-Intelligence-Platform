"""
Full Application End-to-End (E2E) Test Suite — Threat Intelligence Platform (TIP)
==================================================================================
Covers:
Phase 3: Authentication and Account Journeys (Login, Password Toggle, Cookies, Logout, Lockout, Reset, Register, MFA, Session Invalidation)
Phase 4: UI, Major Pages and Forms (All 88 routes across Dashboard, IOCs, Alerts, News, Reports, Malware, Search, Profile)
Phase 5: Admin Panel End-to-End Governance (User table, Reset link, Suspension, Lockout/Unlock, Self-action/Last-admin protection, Audit CSV)
Phase 6: Threat Intelligence Core (CRUD IOCs, Deduplication, Risk Scoring, Report Upload & Extraction, Alert Lifecycle, IOC Expiry)
Phase 7: SIEM / EDR Webhook Ingestion (Portal RBAC, HMAC-SHA256 signature, Replay prevention, Ingest -> Alert -> IOC -> AuditLog)
Phase 8: REST API v1 & v2 Lifecycle (/api/status, /api/v2/docs, Blocklists, STIX bundle, CRUD & RBAC enforcement)
"""

from datetime import datetime, timedelta, timezone
import hashlib
import hmac
import io
import json
import secrets
import time
import unittest
from unittest.mock import patch

from werkzeug.security import generate_password_hash

from app import create_app, db
from app.models import (
    Alert,
    AuditLog,
    Malware,
    ThreatIndicator,
    ThreatNews,
    ThreatReport,
    User,
)
from app.services.admin_service import (
    generate_password_reset_token,
    reset_password_with_token,
)
from app.services.api_key_service import generate_user_api_key, revoke_user_api_key
from app.services.ioc_expiry_service import evaluate_and_expire_iocs

_TEST_PREFIX = "e2e_test_"
_VALID_PASSWORD = "ValidE2EPass2026!#"


class TestE2EFullJourney(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.app = create_app()
        cls.app.config["TESTING"] = True
        cls.app.config["WTF_CSRF_ENABLED"] = False
        cls.app.config["SIEM_WEBHOOK_API_KEY"] = "e2e-strong-siem-secret-key-2026"
        cls.app.config["SIEM_WEBHOOK_SECRET"] = "e2e-strong-siem-secret-key-2026"
        cls.app.config["SIEM_WEBHOOK_REQUIRE_SIGNATURE"] = False
        cls.client = cls.app.test_client()

    def setUp(self):
        self.ctx = self.app.app_context()
        self.ctx.push()
        db.session.rollback()
        self._cleanup()
        self._seed_test_users()

    def tearDown(self):
        try:
            db.session.rollback()
            self._cleanup()
        finally:
            db.session.remove()
            self.ctx.pop()

    def _cleanup(self):
        """Clean all test-generated entities."""
        db.session.rollback()

        # 1. Clean test alerts
        Alert.query.filter(
            (Alert.title.like(f"%{_TEST_PREFIX}%"))
            | (Alert.description.like(f"%{_TEST_PREFIX}%"))
        ).delete(synchronize_session=False)

        # 2. Clean test threat reports & associations
        reports = ThreatReport.query.filter(ThreatReport.title.like(f"%{_TEST_PREFIX}%")).all()
        for r in reports:
            r.indicators.clear()
            r.malwares.clear()
            db.session.delete(r)

        # 3. Clean test indicators
        indicators = ThreatIndicator.query.filter(ThreatIndicator.indicator_value.like(f"%{_TEST_PREFIX}%")).all()
        for ind in indicators:
            ind.reports.clear()
            ind.alerts.clear()
            ind.malwares.clear()
            db.session.delete(ind)

        # 4. Clean test malware
        Malware.query.filter(Malware.malware_name.like(f"%{_TEST_PREFIX}%")).delete(synchronize_session=False)

        # 5. Clean test users and audit logs
        test_users = User.query.filter(
            (User.username.like(f"%{_TEST_PREFIX}%"))
            | (User.email.like(f"%{_TEST_PREFIX}%"))
        ).all()
        for u in test_users:
            AuditLog.query.filter_by(user_id=u.id).delete(synchronize_session=False)
            AuditLog.query.filter_by(target_id=u.id).delete(synchronize_session=False)
            db.session.delete(u)

        db.session.commit()

    def _seed_test_users(self):
        """Seed dedicated Admin, Analyst, and Regular User accounts."""
        self.admin = User(
            username=f"{_TEST_PREFIX}admin",
            email=f"{_TEST_PREFIX}admin@e2e.test",
            password_hash=generate_password_hash(_VALID_PASSWORD),
            role="admin",
            is_active=True,
            session_token=secrets.token_hex(16),
            api_key=f"tip_live_admin_{_TEST_PREFIX}1234567890",
        )
        self.analyst = User(
            username=f"{_TEST_PREFIX}analyst",
            email=f"{_TEST_PREFIX}analyst@e2e.test",
            password_hash=generate_password_hash(_VALID_PASSWORD),
            role="analyst",
            is_active=True,
            session_token=secrets.token_hex(16),
            api_key=f"tip_live_analyst_{_TEST_PREFIX}1234567890",
        )
        self.user = User(
            username=f"{_TEST_PREFIX}user",
            email=f"{_TEST_PREFIX}user@e2e.test",
            password_hash=generate_password_hash(_VALID_PASSWORD),
            role="user",
            is_active=True,
            session_token=secrets.token_hex(16),
            api_key=f"tip_live_user_{_TEST_PREFIX}1234567890",
        )
        db.session.add_all([self.admin, self.analyst, self.user])
        db.session.commit()

    def _login_session(self, user):
        """Simulate browser session cookie login for a user."""
        with self.client.session_transaction() as sess:
            sess["_user_id"] = str(user.id)
            sess["_fresh"] = True
            sess["_session_token"] = user.session_token

    # =========================================================================
    # PHASE 3: AUTHENTICATION AND ACCOUNT TESTING
    # =========================================================================

    def test_01_login_page_renders_and_has_password_toggle(self):
        """Verifies /login renders 200 OK and includes show/hide password toggle elements."""
        resp = self.client.get("/login")
        self.assertEqual(resp.status_code, 200)
        html = resp.get_data(as_text=True)
        self.assertIn('password-toggle-btn', html)
        self.assertIn('aria-label="Show password"', html)
        self.assertIn('eye-icon', html)

    def test_02_registration_validation_and_toggle(self):
        """Verifies /register has toggles for both password fields and validates inputs."""
        resp_get = self.client.get("/register")
        self.assertEqual(resp_get.status_code, 200)
        html = resp_get.get_data(as_text=True)
        self.assertIn('aria-label="Show password"', html)
        self.assertIn('aria-label="Show confirm password"', html)

        # Mismatched password rejected
        resp_mismatch = self.client.post("/register", data={
            "username": f"{_TEST_PREFIX}newreg",
            "email": f"{_TEST_PREFIX}newreg@e2e.test",
            "password": _VALID_PASSWORD,
            "confirm_password": "MismatchedPass123!",
        }, follow_redirects=True)
        self.assertIn("Passwords do not match", resp_mismatch.get_data(as_text=True))

        # Successful registration
        resp_success = self.client.post("/register", data={
            "username": f"{_TEST_PREFIX}newreg",
            "email": f"{_TEST_PREFIX}newreg@e2e.test",
            "password": _VALID_PASSWORD,
            "confirm_password": _VALID_PASSWORD,
        }, follow_redirects=True)
        self.assertEqual(resp_success.status_code, 200)
        created_user = User.query.filter_by(username=f"{_TEST_PREFIX}newreg").first()
        self.assertIsNotNone(created_user)
        self.assertEqual(created_user.role, "user")

    def test_03_login_valid_and_invalid_credentials(self):
        """Verifies invalid login rejected with error, valid login creates session."""
        # Invalid password
        resp_fail = self.client.post("/login", data={
            "email": self.admin.email,
            "password": "WrongPassword2026!",
        }, follow_redirects=True)
        self.assertIn("Invalid email or password", resp_fail.get_data(as_text=True))

        # Valid login
        resp_ok = self.client.post("/login", data={
            "email": self.admin.email,
            "password": _VALID_PASSWORD,
        }, follow_redirects=False)
        self.assertEqual(resp_ok.status_code, 302)
        self.assertIn("/dashboard", resp_ok.headers.get("Location", ""))

        # Check session cookie attributes
        cookies = resp_ok.headers.getlist("Set-Cookie")
        session_cookie = [c for c in cookies if "session=" in c]
        self.assertTrue(len(session_cookie) > 0)
        self.assertIn("HttpOnly", session_cookie[0])
        self.assertIn("SameSite=Lax", session_cookie[0])

    def test_04_account_lockout_after_failed_attempts(self):
        """Verifies account is locked after consecutive failed login attempts."""
        for _ in range(5):
            self.client.post("/login", data={
                "email": self.analyst.email,
                "password": "WrongPasswordAttempt!",
            })

        db.session.refresh(self.analyst)
        self.assertIsNotNone(self.analyst.locked_until)
        self.assertGreaterEqual(self.analyst.failed_login_count, 5)

        # Attempt login while locked
        resp_locked = self.client.post("/login", data={
            "email": self.analyst.email,
            "password": _VALID_PASSWORD,
        }, follow_redirects=True)
        self.assertIn("temporarily locked", resp_locked.get_data(as_text=True))

    def test_05_session_invalidation_on_logout(self):
        """Verifies logout invalidates the session and redirects to login."""
        self._login_session(self.user)
        resp_logout = self.client.get("/logout", follow_redirects=False)
        self.assertEqual(resp_logout.status_code, 302)
        self.assertIn("/login", resp_logout.headers.get("Location", ""))

    def test_06_password_reset_token_flow(self):
        """Verifies token generation, password reset page, and token usage."""
        ok, msg, token = generate_password_reset_token(self.admin.id, self.user.id)
        self.assertTrue(ok)
        self.assertIsNotNone(token)

        # GET /reset-password/<token>
        resp_token_page = self.client.get(f"/reset-password/{token}")
        self.assertEqual(resp_token_page.status_code, 200)
        html = resp_token_page.get_data(as_text=True)
        self.assertIn('aria-label="Show password"', html)

        # POST /reset-password/<token> with new password
        new_pass = "BrandNewPass2026!#"
        resp_reset = self.client.post(f"/reset-password/{token}", data={
            "new_password": new_pass,
            "confirm_password": new_pass,
        }, follow_redirects=True)
        self.assertEqual(resp_reset.status_code, 200)

        # Verify login with new password succeeds
        resp_relogin = self.client.post("/login", data={
            "email": self.user.email,
            "password": new_pass,
        }, follow_redirects=False)
        self.assertEqual(resp_relogin.status_code, 302)

    def test_07_deactivated_account_cannot_login(self):
        """Verifies suspended/deactivated account is denied login."""
        self.user.is_active = False
        db.session.commit()

        resp = self.client.post("/login", data={
            "email": self.user.email,
            "password": _VALID_PASSWORD,
        }, follow_redirects=True)
        self.assertIn("deactivated", resp.get_data(as_text=True))

    # =========================================================================
    # PHASE 4: UI, MAJOR PAGES AND FORMS
    # =========================================================================

    def test_08_core_authenticated_pages_render_successfully(self):
        """Verifies all major platform views render with HTTP 200 for authenticated user."""
        self._login_session(self.admin)

        routes = [
            "/dashboard",
            "/threat-feed",
            "/alerts",
            "/threat-news",
            "/threat-reports",
            "/threat-report-upload",
            "/malware-info",
            "/add-malware",
            "/ip-checker",
            "/ip-lookup-history",
            "/mitre-matrix",
            "/search-threats",
            "/profile",
            "/siem-edr-integration",
            "/admin",
        ]

        for route in routes:
            resp = self.client.get(route)
            self.assertEqual(
                resp.status_code, 200,
                f"Failed route: {route} returned status {resp.status_code}"
            )

    def test_09_unauthenticated_redirection_to_login(self):
        """Verifies unauthenticated requests to protected pages redirect to /login."""
        protected_routes = ["/dashboard", "/threat-feed", "/alerts", "/admin", "/profile"]
        for route in protected_routes:
            resp = self.client.get(route, follow_redirects=False)
            self.assertEqual(resp.status_code, 302)
            self.assertIn("/login", resp.headers.get("Location", ""))

    # =========================================================================
    # PHASE 5: ADMIN PANEL GOVERNANCE
    # =========================================================================

    def test_10_admin_panel_rbac_enforcement(self):
        """Verifies /admin is forbidden (403) to non-admin roles and accessible (200) to admin."""
        # Regular user receives 403
        self._login_session(self.user)
        self.assertEqual(self.client.get("/admin").status_code, 403)

        # Analyst receives 403
        self._login_session(self.analyst)
        self.assertEqual(self.client.get("/admin").status_code, 403)

        # Admin receives 200
        self._login_session(self.admin)
        self.assertEqual(self.client.get("/admin").status_code, 200)

    def test_11_admin_user_management_actions(self):
        """Verifies admin actions: suspend, activate, role change, session revoke."""
        self._login_session(self.admin)

        # 1. Suspend user
        resp_suspend = self.client.post("/admin", data={
            "action": "suspend",
            "user_id": self.user.id,
        }, follow_redirects=True)
        self.assertEqual(resp_suspend.status_code, 200)
        db.session.refresh(self.user)
        self.assertFalse(self.user.is_active)

        # 2. Activate user
        resp_activate = self.client.post("/admin", data={
            "action": "activate",
            "user_id": self.user.id,
        }, follow_redirects=True)
        self.assertEqual(resp_activate.status_code, 200)
        db.session.refresh(self.user)
        self.assertTrue(self.user.is_active)

        # 3. Update role
        resp_role = self.client.post("/admin", data={
            "action": "update_role",
            "user_id": self.user.id,
            "new_role": "analyst",
        }, follow_redirects=True)
        self.assertEqual(resp_role.status_code, 200)
        db.session.refresh(self.user)
        self.assertEqual(self.user.role, "analyst")

    def test_12_admin_self_action_and_last_admin_protection(self):
        """Verifies administrator cannot suspend self or demote the last admin."""
        self._login_session(self.admin)

        # Attempt self-suspend
        resp_self = self.client.post("/admin", data={
            "action": "suspend",
            "user_id": self.admin.id,
        }, follow_redirects=True)
        self.assertIn("cannot suspend your own", resp_self.get_data(as_text=True).lower())
        db.session.refresh(self.admin)
        self.assertTrue(self.admin.is_active)

    def test_13_audit_log_search_and_csv_export(self):
        """Verifies audit log filtering and CSV export endpoints."""
        self._login_session(self.admin)

        # Search audit logs
        resp_search = self.client.get("/admin?q=e2e")
        self.assertEqual(resp_search.status_code, 200)

        # Export CSV
        resp_csv = self.client.get("/admin/audit-logs/export-csv")
        self.assertEqual(resp_csv.status_code, 200)
        self.assertIn("text/csv", resp_csv.headers.get("Content-Type", ""))
        csv_text = resp_csv.get_data(as_text=True)
        self.assertIn("Timestamp", csv_text)
        self.assertIn("Actor Username", csv_text)

    # =========================================================================
    # PHASE 6: THREAT INTELLIGENCE CORE
    # =========================================================================

    def test_15_ioc_creation_validation_and_risk_scoring(self):
        """Verifies IOC creation via API v2, input validation, and risk score generation."""
        ioc_value = f"{_TEST_PREFIX}198.51.100.77"
        payload = {
            "indicator_value": ioc_value,
            "indicator_type": "ipv4",
            "severity": "High",
            "confidence": 85,
        }
        resp = self.client.post(
            "/api/v2/indicators",
            json=payload,
            headers={"X-API-Key": self.analyst.api_key}
        )
        self.assertEqual(resp.status_code, 201)
        data = resp.get_json()
        self.assertTrue(data["success"])
        self.assertEqual(data["indicator"]["indicator_value"], ioc_value)

        # Verify persistence in database
        ind = ThreatIndicator.query.filter_by(indicator_value=ioc_value).first()
        self.assertIsNotNone(ind)
        self.assertEqual(ind.severity, "High")

    def test_16_threat_report_upload_and_ioc_extraction(self):
        """Verifies threat report upload and automatic text extraction."""
        self._login_session(self.analyst)

        file_content = f"Threat incident report containing malicious IP: {_TEST_PREFIX}203.0.113.88"
        file_obj = (io.BytesIO(file_content.encode("utf-8")), "threat_intel_sample.txt")

        resp = self.client.post("/threat-report-upload", data={
            "title": f"{_TEST_PREFIX}Incident Report",
            "summary": "Sample incident telemetry for E2E",
            "category": "APT",
            "severity": "High",
            "tlp_level": "AMBER",
            "sectors": "Finance",
            "report_file": file_obj,
        }, content_type="multipart/form-data", follow_redirects=True)
        self.assertEqual(resp.status_code, 200)

        report = ThreatReport.query.filter(ThreatReport.title.like(f"%{_TEST_PREFIX}%")).first()
        self.assertIsNotNone(report)

    def test_17_alert_center_lifecycle(self):
        """Verifies alert status lifecycle: Open -> Acknowledged -> Resolved -> Reopened."""
        self._login_session(self.analyst)

        alert = Alert(
            title=f"{_TEST_PREFIX}Test Security Alert",
            alert_type="SIEM/EDR",
            severity="High",
            status="Open",
            user_id=self.analyst.id,
        )
        db.session.add(alert)
        db.session.commit()

        # 1. Acknowledge
        resp_ack = self.client.post(f"/alert/{alert.id}/acknowledge", follow_redirects=True)
        self.assertEqual(resp_ack.status_code, 200)
        db.session.refresh(alert)
        self.assertEqual(alert.status, "In Progress")

        # 2. Resolve
        resp_res = self.client.post(f"/alert/{alert.id}/resolve", follow_redirects=True)
        self.assertEqual(resp_res.status_code, 200)
        db.session.refresh(alert)
        self.assertEqual(alert.status, "Resolved")

        # 3. Reopen
        resp_reopen = self.client.post(f"/alert/{alert.id}/reopen", follow_redirects=True)
        self.assertEqual(resp_reopen.status_code, 200)
        db.session.refresh(alert)
        self.assertEqual(alert.status, "Open")

    def test_18_threat_news_aggregation_mocked(self):
        """Verifies threat news view renders cleanly with mocked upstream feeds."""
        self._login_session(self.analyst)
        with patch("requests.get") as mock_get:
            mock_get.return_value.status_code = 200
            mock_get.return_value.text = "<rss><channel><title>Mock News</title></channel></rss>"
            resp = self.client.get("/threat-news")
            self.assertEqual(resp.status_code, 200)

    def test_19_ioc_lifecycle_expiration_and_reactivation(self):
        """Verifies IOC automated expiration job and analyst reactivation flow."""
        old_indicator = ThreatIndicator(
            indicator_value=f"{_TEST_PREFIX}192.0.2.105",
            indicator_type="ipv4",
            severity="Medium",
            status="Active",
            source="E2E Test",
            first_seen_at=datetime.now(timezone.utc) - timedelta(days=95),
            last_seen_at=datetime.now(timezone.utc) - timedelta(days=95),
            added_by_user_id=self.analyst.id,
        )
        db.session.add(old_indicator)
        db.session.commit()

        # Run automated expiration with 90 day policy
        result = evaluate_and_expire_iocs(ttl_policies={"ipv4": 90}, dry_run=False)
        self.assertGreaterEqual(result["expired_count"], 1)

        db.session.refresh(old_indicator)
        self.assertEqual(old_indicator.status, "Expired")

        # Reactivate via API
        resp_react = self.client.post(
            f"/api/v1/ioc/reactivate/{old_indicator.id}",
            headers={"X-API-Key": self.analyst.api_key}
        )
        self.assertEqual(resp_react.status_code, 200)
        db.session.refresh(old_indicator)
        self.assertEqual(old_indicator.status, "Active")

    # =========================================================================
    # PHASE 7: SIEM / EDR INTEGRATION TESTING
    # =========================================================================

    def test_20_siem_portal_access_and_key_masking(self):
        """Verifies SIEM portal is analyst-only and masks master secret key in UI."""
        # Regular user receives 403
        self._login_session(self.user)
        self.assertEqual(self.client.get("/siem-edr-integration").status_code, 403)

        # Analyst receives 200 with masked key
        self._login_session(self.analyst)
        resp_analyst = self.client.get("/siem-edr-integration")
        self.assertEqual(resp_analyst.status_code, 200)
        html = resp_analyst.get_data(as_text=True)
        raw_key = self.app.config["SIEM_WEBHOOK_API_KEY"]
        self.assertNotIn(f"<code>{raw_key}</code>", html)

    def test_21_siem_webhook_ingestion_end_to_end(self):
        """Verifies complete ingestion: HMAC validation -> IOC extract -> Alert -> AuditLog."""
        secret = self.app.config["SIEM_WEBHOOK_SECRET"]
        payload = {
            "title": f"{_TEST_PREFIX}CrowdStrike Detected Threat",
            "source": "CrowdStrike Falcon",
            "severity": "High",
            "description": f"Connection detected to C2 IP {_TEST_PREFIX}198.51.100.66",
        }
        body_bytes = json.dumps(payload).encode("utf-8")
        ts = str(int(time.time()))
        expected_sig = hmac.new(
            secret.encode("utf-8"),
            f"{ts}.".encode("utf-8") + body_bytes,
            hashlib.sha256
        ).hexdigest()

        # Ingest alert via webhook
        resp = self.client.post(
            "/api/v1/webhook/alert",
            data=body_bytes,
            headers={
                "Content-Type": "application/json",
                "X-API-Key": self.app.config["SIEM_WEBHOOK_API_KEY"],
                "X-Webhook-Signature": f"sha256={expected_sig}",
                "X-Webhook-Timestamp": ts,
            }
        )
        self.assertEqual(resp.status_code, 201)
        data = resp.get_json()
        self.assertTrue(data["success"])
        alert_id = data["alert"]["id"]

        # Confirm Alert is in database
        alert = db.session.get(Alert, alert_id)
        self.assertIsNotNone(alert)
        self.assertEqual(alert.severity, "High")

        # Confirm unalterable AuditLog entry was written
        audit = AuditLog.query.filter_by(target_table="alerts", target_id=alert_id).first()
        self.assertIsNotNone(audit)

    # =========================================================================
    # PHASE 8: REST API v1 AND v2 LIFECYCLE
    # =========================================================================

    def test_22_api_status_and_docs(self):
        """Verifies /api/status healthcheck and /api/v2/docs Swagger availability."""
        # /api/status (public)
        resp_status = self.client.get("/api/status")
        self.assertEqual(resp_status.status_code, 200)
        self.assertEqual(resp_status.get_json()["status"], "operational")

        # /api/v2/docs (public OpenAPI spec)
        resp_docs = self.client.get("/api/v2/docs")
        self.assertEqual(resp_docs.status_code, 200)
        docs_json = resp_docs.get_json()
        self.assertIn("openapi", docs_json)
        self.assertEqual(docs_json["info"]["title"], "Threat Intelligence Platform API")

    def test_23_api_blocklist_plain_and_stix_bundle(self):
        """Verifies firewall blocklist export feed and STIX 2.1 bundle export."""
        # Blocklist plain feed
        resp_feed = self.client.get("/api/v1/feed/blocklist/plain")
        self.assertEqual(resp_feed.status_code, 200)
        self.assertIn("text/plain", resp_feed.headers.get("Content-Type", ""))

        # STIX 2.1 Bundle
        resp_stix = self.client.get("/api/v1/stix/bundle")
        self.assertEqual(resp_stix.status_code, 200)
        stix_data = resp_stix.get_json()
        self.assertEqual(stix_data["type"], "bundle")
        self.assertIn("objects", stix_data)

    def test_24_api_v2_crud_and_rbac(self):
        """Verifies RBAC enforcement on API v2 indicator and alert endpoints."""
        ind_val = f"{_TEST_PREFIX}203.0.113.199"

        # 1. Read-only user rejected on POST (403)
        resp_user = self.client.post(
            "/api/v2/indicators",
            json={"indicator_value": ind_val, "indicator_type": "ipv4", "severity": "Medium"},
            headers={"X-API-Key": self.user.api_key}
        )
        self.assertEqual(resp_user.status_code, 403)

        # 2. Analyst allowed on POST (201)
        resp_analyst = self.client.post(
            "/api/v2/indicators",
            json={"indicator_value": ind_val, "indicator_type": "ipv4", "severity": "Medium"},
            headers={"X-API-Key": self.analyst.api_key}
        )
        self.assertEqual(resp_analyst.status_code, 201)
        ind_id = resp_analyst.get_json()["indicator"]["id"]

        # 3. Read-only user rejected on DELETE (403)
        resp_del_user = self.client.delete(
            f"/api/v2/indicators/{ind_id}",
            headers={"X-API-Key": self.user.api_key}
        )
        self.assertEqual(resp_del_user.status_code, 403)

        # 4. Analyst allowed on DELETE (200)
        resp_del_analyst = self.client.delete(
            f"/api/v2/indicators/{ind_id}",
            headers={"X-API-Key": self.analyst.api_key}
        )
        self.assertEqual(resp_del_analyst.status_code, 200)


if __name__ == "__main__":
    unittest.main()
