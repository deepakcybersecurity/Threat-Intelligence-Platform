"""
Tests for Task 11: Security Hardening
=====================================
Covers:
1. CSRF Protection (enforcement, rejection of missing/invalid token, acceptance of valid token, API exemption)
2. Rate Limiting (rejection with HTTP 429 when threshold exceeded, JSON error format)
3. Password Policy & Complexity (length, uppercase, lowercase, number, special character; registration and admin provisioning)
4. Security Headers (CSP, X-Content-Type-Options, X-Frame-Options, Referrer-Policy, HSTS)
5. Session & Cookie Security (HttpOnly, SameSite=Lax, Secure in production, secret key validation)
6. Input Validation & XSS Sanitization (script stripping, event handler stripping, preservation of defanged IOCs & URLs)
"""

import os
import re
import unittest
from flask import session
from werkzeug.security import generate_password_hash

from app import create_app, db, limiter
from app.models import User, ThreatReport, ThreatIndicator, AuditLog, Alert, Malware
from app.services.security_service import (
    validate_password_complexity,
    sanitize_text,
    build_csp_header,
)
from app.services.admin_service import provision_user
from config import Config, DevelopmentConfig, ProductionConfig

_TEST_PREFIX = "sec_test_"
_VALID_TEST_PASSWORD = "ValidPass2026!#"


class TestSecurityHardening(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.app = create_app()
        cls.app.config["TESTING"] = True
        cls.app.config["WTF_CSRF_ENABLED"] = True  # Explicitly enable CSRF for this suite
        cls.app.config["RATELIMIT_ENABLED"] = True
        cls.app.config["RATELIMIT_STORAGE_URI"] = "memory://"
        cls.app.config["SIEM_WEBHOOK_API_KEY"] = "sec-test-api-key-2026"
        cls.client = cls.app.test_client()

    def setUp(self):
        limiter.reset()
        self.ctx = self.app.app_context()
        self.ctx.push()
        self._cleanup()
        self._seed()

    def tearDown(self):
        limiter.reset()
        db.session.rollback()
        self._cleanup()
        self.ctx.pop()

    def _cleanup(self):
        db.session.rollback()
        # Clean test reports and associations
        test_reps = ThreatReport.query.filter(ThreatReport.title.like(f"{_TEST_PREFIX}%")).all()
        for r in test_reps:
            r.malwares.clear()
            r.indicators.clear()
            db.session.delete(r)

        # Clean test indicators
        test_inds = ThreatIndicator.query.filter(ThreatIndicator.indicator_value.like(f"{_TEST_PREFIX}%")).all()
        for ind in test_inds:
            ind.reports.clear()
            ind.malwares.clear()
            ind.alerts.clear()
            db.session.delete(ind)

        # Clean test users and associated audit logs
        test_users = User.query.filter(User.username.like(f"{_TEST_PREFIX}%")).all()
        for u in test_users:
            AuditLog.query.filter_by(user_id=u.id).delete()
            db.session.delete(u)

        AuditLog.query.filter(AuditLog.action.like(f"%{_TEST_PREFIX}%")).delete(synchronize_session=False)
        db.session.commit()

    def _seed(self):
        self.admin = User(
            username=f"{_TEST_PREFIX}admin",
            email=f"{_TEST_PREFIX}admin@tip.local",
            password_hash=generate_password_hash(_VALID_TEST_PASSWORD),
            role="admin",
            is_active=True,
        )
        db.session.add(self.admin)
        db.session.commit()
        self.admin_id = self.admin.id

    def _extract_csrf_token(self, html_text):
        """Extract CSRF token from HTML form hidden input."""
        match = re.search(r'name=["\']csrf_token["\']\s+value=["\']([^"\']+)["\']', html_text)
        if match:
            return match.group(1)
        # Check meta tag format: <meta name="csrf-token" content="...">
        match_meta = re.search(r'name=["\']csrf-token["\']\s+content=["\']([^"\']+)["\']', html_text)
        if match_meta:
            return match_meta.group(1)
        return None

    def _login_as_admin(self, client=None):
        """Helper to log in as admin through browser form with valid CSRF token."""
        c = client or self.client
        get_resp = c.get("/login")
        token = self._extract_csrf_token(get_resp.get_data(as_text=True))
        post_resp = c.post(
            "/login",
            data={
                "csrf_token": token,
                "email": f"{_TEST_PREFIX}admin@tip.local",
                "password": _VALID_TEST_PASSWORD,
            },
            follow_redirects=True,
        )
        return post_resp

    # =========================================================================
    # 1. CSRF PROTECTION TESTS
    # =========================================================================

    def test_csrf_protection_rejects_post_without_token(self):
        """Verifies browser POST request lacking a CSRF token returns HTTP 400."""
        resp = self.client.post(
            "/login",
            data={
                "email": f"{_TEST_PREFIX}admin@tip.local",
                "password": _VALID_TEST_PASSWORD,
            },
        )
        self.assertEqual(resp.status_code, 400)
        self.assertTrue(
            b"CSRF" in resp.data or b"Bad Request" in resp.data or b"400" in resp.data
        )

    def test_csrf_protection_rejects_post_with_invalid_token(self):
        """Verifies browser POST with a forged/invalid CSRF token returns HTTP 400."""
        resp = self.client.post(
            "/login",
            data={
                "csrf_token": "forged_malicious_token_12345",
                "email": f"{_TEST_PREFIX}admin@tip.local",
                "password": _VALID_TEST_PASSWORD,
            },
        )
        self.assertEqual(resp.status_code, 400)

    def test_csrf_protection_accepts_valid_token(self):
        """Verifies browser POST with a valid CSRF token is processed without CSRF error."""
        get_resp = self.client.get("/login")
        self.assertEqual(get_resp.status_code, 200)
        token = self._extract_csrf_token(get_resp.get_data(as_text=True))
        self.assertIsNotNone(token, "CSRF token must be present in login form")

        post_resp = self.client.post(
            "/login",
            data={
                "csrf_token": token,
                "email": f"{_TEST_PREFIX}admin@tip.local",
                "password": _VALID_TEST_PASSWORD,
            },
            follow_redirects=False,
        )
        # Successful login redirects (302) to dashboard
        self.assertEqual(post_resp.status_code, 302)

    def test_api_endpoints_exempt_from_csrf(self):
        """
        Verifies machine-to-machine REST API endpoints (/api/...) are exempt from CSRF
        because they utilize stateless header-based token authentication (X-API-Key).
        """
        resp = self.client.get(
            "/api/v2/indicators",
            headers={"X-API-Key": "sec-test-api-key-2026"},
        )
        self.assertEqual(resp.status_code, 200)

        # POST to stateless endpoint without CSRF token
        post_resp = self.client.post(
            "/api/v2/indicators",
            json={
                "indicator_value": f"{_TEST_PREFIX}10.0.0.99",
                "indicator_type": "ipv4",
                "severity": "Medium",
                "source": "SecurityTest",
            },
            headers={"X-API-Key": "sec-test-api-key-2026"},
        )
        self.assertNotEqual(post_resp.status_code, 400)
        self.assertEqual(post_resp.status_code, 201)

    # =========================================================================
    # 2. RATE LIMITING TESTS
    # =========================================================================

    def test_rate_limiting_exceeded_returns_429(self):
        """Verifies exceeding endpoint rate limits returns consistent HTTP 429."""
        # /login has a strict limit of 15 per minute
        # We temporarily disable CSRF validation so requests hit the route limiter
        orig_csrf = self.app.config.get("WTF_CSRF_ENABLED", True)
        try:
            self.app.config["WTF_CSRF_ENABLED"] = False
            hit_429 = False
            for i in range(20):
                r = self.client.post(
                    "/login",
                    data={
                        "email": "rate@test.local",
                        "password": "WrongPassword1!",
                    },
                )
                if r.status_code == 429:
                    hit_429 = True
                    break
            self.assertTrue(hit_429, "Expected rate limit (429) after repeated POST to /login")
        finally:
            limiter.reset()
            self.app.config["WTF_CSRF_ENABLED"] = orig_csrf

    def test_rate_limiting_json_error_response(self):
        """Verifies errorhandler returns structured JSON 429 payload for API requests."""
        # Directly invoke the registered 429 handler or test with API route
        with self.app.test_request_context("/api/v2/test"):
            from werkzeug.exceptions import TooManyRequests
            e = TooManyRequests("Too many requests")
            from app import limiter
            # Call the app's 429 handler directly
            handler = self.app.error_handler_spec[None][429][TooManyRequests]
            resp, status = handler(e)
            self.assertEqual(status, 429)
            data = resp.get_json()
            self.assertFalse(data["success"])
            self.assertEqual(data["error"], "RateLimitExceeded")
            self.assertIn("Too many requests", data["message"])

    # =========================================================================
    # 3. PASSWORD POLICY & COMPLEXITY TESTS
    # =========================================================================

    def test_password_policy_valid_combinations(self):
        """Verifies strong passwords meeting all complexity requirements pass validation."""
        strong_passwords = [
            "AdminPass1!",
            "CyberSec#2026",
            "P@ssw0rd99$",
            "Thre@tIntel_42",
            "XyZ!99aB#cD",
        ]
        for pw in strong_passwords:
            valid, err = validate_password_complexity(pw)
            self.assertTrue(valid, f"Expected '{pw}' to be valid, got error: {err}")
            self.assertIsNone(err)

    def test_password_policy_rejections(self):
        """Verifies passwords failing individual complexity rules are rejected."""
        # 1. Too short (< 8)
        v, err = validate_password_complexity("Ab1!", min_length=8)
        self.assertFalse(v)
        self.assertIn("8 characters", err)

        # 2. Missing uppercase
        v, err = validate_password_complexity("weakpassword1!")
        self.assertFalse(v)
        self.assertIn("uppercase", err)

        # 3. Missing lowercase
        v, err = validate_password_complexity("WEAKPASSWORD1!")
        self.assertFalse(v)
        self.assertIn("lowercase", err)

        # 4. Missing numeric digit
        v, err = validate_password_complexity("WeakPassword!")
        self.assertFalse(v)
        self.assertIn("digit", err)

        # 5. Missing special character
        v, err = validate_password_complexity("WeakPassword1")
        self.assertFalse(v)
        self.assertIn("special character", err)

        # 6. Empty or None
        v, err = validate_password_complexity("")
        self.assertFalse(v)
        v, err = validate_password_complexity(None)
        self.assertFalse(v)

    def test_registration_enforces_password_policy(self):
        """Verifies registration rejects weak passwords and flashes an error."""
        # Use an isolated test client session
        c = self.app.test_client()
        get_resp = c.get("/register")
        token = self._extract_csrf_token(get_resp.get_data(as_text=True))

        resp = c.post(
            "/register",
            data={
                "csrf_token": token,
                "username": f"{_TEST_PREFIX}weak_user",
                "email": f"{_TEST_PREFIX}weak@tip.local",
                "password": "weak",  # Fails complexity
                "confirm_password": "weak",
            },
            follow_redirects=True,
        )
        self.assertEqual(resp.status_code, 200)
        self.assertTrue(
            b"Password must be at least 8 characters" in resp.data
            or b"special character" in resp.data
        )

        # Verify user was NOT created in DB
        u = User.query.filter_by(username=f"{_TEST_PREFIX}weak_user").first()
        self.assertIsNone(u)

    def test_admin_provisioning_enforces_password_policy(self):
        """Verifies admin provisioning rejects weak passwords."""
        ok, msg = provision_user(
            actor_id=self.admin_id,
            username=f"{_TEST_PREFIX}prov_user",
            email=f"{_TEST_PREFIX}prov@tip.local",
            password="weakpassword",  # Missing uppercase, digit, special char
            role="analyst",
        )
        self.assertFalse(ok)
        self.assertTrue("uppercase" in msg or "character" in msg or "digit" in msg)

    # =========================================================================
    # 4. SECURITY HEADERS TESTS
    # =========================================================================

    def test_security_headers_present(self):
        """Verifies standard security headers on HTTP responses."""
        resp = self.client.get("/login")
        self.assertEqual(resp.status_code, 200)

        # X-Content-Type-Options
        self.assertEqual(resp.headers.get("X-Content-Type-Options"), "nosniff")

        # X-Frame-Options
        self.assertEqual(resp.headers.get("X-Frame-Options"), "DENY")

        # Referrer-Policy
        self.assertEqual(resp.headers.get("Referrer-Policy"), "strict-origin-when-cross-origin")

        # Content-Security-Policy
        csp = resp.headers.get("Content-Security-Policy")
        self.assertIsNotNone(csp)
        self.assertIn("default-src 'self'", csp)
        self.assertIn("frame-ancestors 'none'", csp)
        self.assertIn("base-uri 'self'", csp)
        self.assertIn("form-action 'self'", csp)

    def test_hsts_header_toggle(self):
        """Verifies HSTS is applied when ENABLE_HSTS is True and omitted when False."""
        # 1. Disabled (default in development)
        resp_dev = self.client.get("/login")
        self.assertNotIn("Strict-Transport-Security", resp_dev.headers)

        # 2. Enabled dynamically via app.config
        orig = self.app.config.get("ENABLE_HSTS", False)
        try:
            self.app.config["ENABLE_HSTS"] = True
            resp_hsts = self.client.get("/login")
            self.assertIn("Strict-Transport-Security", resp_hsts.headers)
            self.assertIn("max-age=31536000", resp_hsts.headers["Strict-Transport-Security"])
        finally:
            self.app.config["ENABLE_HSTS"] = orig

    # =========================================================================
    # 5. SESSION & COOKIE SECURITY TESTS
    # =========================================================================

    def test_session_cookie_security_configurations(self):
        """Verifies session cookie configuration flags."""
        self.assertTrue(self.app.config["SESSION_COOKIE_HTTPONLY"])
        self.assertEqual(self.app.config["SESSION_COOKIE_SAMESITE"], "Lax")
        self.assertTrue(self.app.config["REMEMBER_COOKIE_HTTPONLY"])
        self.assertEqual(self.app.config["REMEMBER_COOKIE_SAMESITE"], "Lax")

    def test_production_config_cookie_security(self):
        """Verifies ProductionConfig enables Secure cookies and HSTS."""
        self.assertTrue(ProductionConfig.SESSION_COOKIE_SECURE)
        self.assertTrue(ProductionConfig.REMEMBER_COOKIE_SECURE)
        self.assertTrue(ProductionConfig.ENABLE_HSTS)
        self.assertFalse(ProductionConfig.DEBUG)

    def test_production_secret_key_validation(self):
        """Verifies production configuration fails safely if SECRET_KEY is not set or default."""
        orig_key = os.environ.get("SECRET_KEY")
        try:
            # Test default insecure key rejection
            os.environ["SECRET_KEY"] = "dev-insecure-secret-key-change-in-production-2026"
            with self.assertRaises(ValueError) as ctx:
                ProductionConfig.validate_production_secrets()
            self.assertIn("SECRET_KEY", str(ctx.exception))

            # Test missing key rejection
            os.environ.pop("SECRET_KEY", None)
            with self.assertRaises(ValueError) as ctx:
                ProductionConfig.validate_production_secrets()
            self.assertIn("SECRET_KEY", str(ctx.exception))
        finally:
            if orig_key:
                os.environ["SECRET_KEY"] = orig_key

    # =========================================================================
    # 6. INPUT VALIDATION & XSS SANITIZATION TESTS
    # =========================================================================

    def test_sanitize_text_strips_xss_scripts(self):
        """Verifies script tags and nested script payloads are completely removed."""
        payload = "<script>alert('XSS-Attack')</script>Malicious text"
        result = sanitize_text(payload)
        self.assertEqual(result, "Malicious text")
        self.assertNotIn("<script>", result)
        self.assertNotIn("alert", result)

    def test_sanitize_text_strips_event_handlers(self):
        """Verifies inline HTML event handlers (onerror, onload, onclick) are stripped."""
        payload = '<img src="x" onerror="alert(1)">Incident Report'
        result = sanitize_text(payload)
        self.assertNotIn("onerror", result)
        self.assertNotIn("alert(1)", result)
        self.assertIn("Incident Report", result)

    def test_sanitize_text_strips_javascript_schemes(self):
        """Verifies javascript: URI pseudo-protocols are stripped."""
        payload = '<a href="javascript:alert(document.cookie)">Click here</a>'
        result = sanitize_text(payload)
        self.assertNotIn("javascript:", result)
        self.assertNotIn("document.cookie", result)

    def test_sanitize_text_preserves_legitimate_threat_intel(self):
        """
        CRITICAL TEST: Verifies that defensive threat intelligence formatting,
        defanged indicators, URLs, hashes, CVEs, and MITRE TTPs are NOT altered.
        """
        samples = [
            "198.51.100[.]10",
            "malware-c2[.]net",
            "https://evil-payload.com/download.php?id=42&session=xyz#anchor",
            "d41d8cd98f00b204e9800998ecf8427e",
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            "CVE-2026-12345",
            "T1059.001 - PowerShell Command Execution",
            "Port 443/TCP traffic observed across subnet 10.0.0.0/24",
        ]
        for s in samples:
            cleaned = sanitize_text(s)
            self.assertEqual(cleaned, s, f"Sanitization altered legitimate IOC format: {s}")

    def test_report_upload_sanitizes_xss_payload(self):
        """Verifies Threat Report creation sanitizes XSS in title and description."""
        # 1. Login with a fresh client
        c = self.app.test_client()
        self._login_as_admin(c)

        # 2. Get upload form for CSRF token
        get_resp = c.get("/threat-report-upload")
        token = self._extract_csrf_token(get_resp.get_data(as_text=True))

        # 3. Post report with XSS payload and valid CSRF token
        resp = c.post(
            "/threat-report-upload",
            data={
                "csrf_token": token,
                "title": f"{_TEST_PREFIX}<script>alert('XSS')</script>APT41 Campaign",
                "summary": "Observation <iframe src='evil.com'></iframe> of 198.51.100[.]99",
                "category": "APT Campaign",
                "severity": "High",
                "tlp_level": "AMBER",
                "sectors": "Energy",
            },
            follow_redirects=True,
        )
        self.assertEqual(resp.status_code, 200)

        # 4. Retrieve from DB and verify XSS was stripped while legitimate content remained
        rep = ThreatReport.query.filter(ThreatReport.title.like(f"{_TEST_PREFIX}%APT41%")).first()
        self.assertIsNotNone(rep)
        self.assertNotIn("<script>", rep.title)
        self.assertNotIn("<iframe", rep.description)
        self.assertIn("198.51.100[.]99", rep.description)


if __name__ == "__main__":
    unittest.main()
