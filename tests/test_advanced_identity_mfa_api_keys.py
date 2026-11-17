"""
Tests for Advanced Identity & Authentication (Phase 3)
======================================================
Covers:
1. RFC 6238 TOTP Multi-Factor Authentication:
   - Secret generation (Base32) & standard otpauth URI
   - Vector SVG QR code generation
   - 8 single-use emergency backup recovery codes
   - Initial TOTP confirmation & enablement
   - Login challenge workflow (/login -> /login/2fa -> /dashboard)
   - TOTP code verification & rejection of invalid codes
   - Emergency backup recovery code verification, single-use consumption, and reuse prevention
   - Self-service MFA disablement requiring current password verification
   - Administrator-initiated MFA reset/override for locked-out analysts
   - Non-admin cannot invoke admin reset_mfa (403 Forbidden)
2. User API Key Self-Service:
   - Generation of personal API keys (format: tip_live_<token>)
   - Masked token representation (tip_live_••••••••<last4>)
   - Key rotation (old key invalidated upon new generation)
   - Key revocation (immediate invalidation)
   - Programmatic REST API v1/v2 authentication via X-API-Key
   - Revoked/invalid keys return 401 Unauthorized
   - Audit logging for all MFA and API key lifecycle events (no plaintext secrets recorded)
"""

import json
import re
import unittest
from datetime import datetime, timezone
import pyotp
from flask import g
from werkzeug.security import generate_password_hash

from app import create_app, db, limiter
from app.models import User, AuditLog
from app.services.mfa_service import (
    generate_mfa_secret,
    get_totp_uri,
    generate_qr_code_svg,
    generate_backup_codes,
    init_mfa_setup,
    confirm_and_enable_mfa,
    disable_mfa_for_user,
    verify_user_mfa,
    count_remaining_backup_codes,
)
from app.services.api_key_service import (
    generate_user_api_key,
    revoke_user_api_key,
    get_user_api_key_info,
)

_TEST_PREFIX = "mfa_api_test_"
_ADMIN_PWD = "AdminSecure2026!#"
_ANALYST_PWD = "AnalystSecure2026!#"
_USER_PWD = "UserSecure2026!#"


class TestAdvancedIdentityMfaApiKeys(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.app = create_app()
        cls.app.config["TESTING"] = True
        cls.app.config["WTF_CSRF_ENABLED"] = True
        cls.app.config["RATELIMIT_ENABLED"] = False
        cls.client = cls.app.test_client()

    def setUp(self):
        limiter.reset()
        self.ctx = self.app.app_context()
        self.ctx.push()
        g.pop("csrf_token", None)
        self._cleanup()
        self._seed()

    def tearDown(self):
        limiter.reset()
        db.session.rollback()
        self._cleanup()
        g.pop("csrf_token", None)
        self.ctx.pop()

    def _cleanup(self):
        db.session.rollback()
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
            password_hash=generate_password_hash(_ADMIN_PWD),
            role="admin",
            is_active=True,
            failed_login_count=0,
        )
        self.analyst = User(
            username=f"{_TEST_PREFIX}analyst",
            email=f"{_TEST_PREFIX}analyst@tip.local",
            password_hash=generate_password_hash(_ANALYST_PWD),
            role="analyst",
            is_active=True,
            failed_login_count=0,
        )
        self.regular_user = User(
            username=f"{_TEST_PREFIX}regular",
            email=f"{_TEST_PREFIX}regular@tip.local",
            password_hash=generate_password_hash(_USER_PWD),
            role="user",
            is_active=True,
            failed_login_count=0,
        )
        db.session.add_all([self.admin, self.analyst, self.regular_user])
        db.session.commit()
        self.admin_id = self.admin.id
        self.analyst_id = self.analyst.id
        self.user_id = self.regular_user.id

    def _extract_csrf_token(self, html_text):
        match = re.search(r'name=["\']csrf_token["\']\s+value=["\']([^"\']+)["\']', html_text)
        if match:
            return match.group(1)
        match_meta = re.search(r'name=["\']csrf-token["\']\s+content=["\']([^"\']+)["\']', html_text)
        if match_meta:
            return match_meta.group(1)
        return None

    def _get_csrf_token(self, client, url="/login"):
        g.pop("csrf_token", None)
        resp = client.get(url)
        return self._extract_csrf_token(resp.get_data(as_text=True))

    def _login(self, client, email, password):
        token = self._get_csrf_token(client, "/login")
        return client.post(
            "/login",
            data={"csrf_token": token, "email": email, "password": password},
            follow_redirects=True,
        )

    # =========================================================================
    # 1. MFA SERVICE UNIT TESTS
    # =========================================================================

    def test_mfa_secret_and_uri_generation(self):
        """MFA secret is a valid 32-char Base32 string and URI contains standard otpauth format."""
        secret = generate_mfa_secret()
        self.assertEqual(len(secret), 32)
        totp = pyotp.TOTP(secret)
        code = totp.now()
        self.assertEqual(len(code), 6)
        self.assertTrue(code.isdigit())

        uri = get_totp_uri(secret, "analyst1", "analyst1@tip.local")
        self.assertIn("otpauth://totp/", uri)
        self.assertIn("ThreatIntel", uri)
        self.assertIn(secret, uri)

    def test_qr_code_svg_generation(self):
        """QR code generation returns a valid SVG XML string."""
        secret = generate_mfa_secret()
        uri = get_totp_uri(secret, "analyst1", "analyst1@tip.local")
        svg = generate_qr_code_svg(uri)
        self.assertIn("<svg", svg)
        self.assertIn("</svg>", svg)

    def test_backup_codes_generation(self):
        """generate_backup_codes produces 8 unique codes formatted as XXXX-XXXX."""
        codes = generate_backup_codes(8)
        self.assertEqual(len(codes), 8)
        self.assertEqual(len(set(codes)), 8)
        for c in codes:
            self.assertRegex(c, r"^[0-9A-Z]{4}-[0-9A-Z]{4}$")

    def test_confirm_and_enable_mfa_validates_totp(self):
        """confirm_and_enable_mfa rejects wrong code and enables MFA on correct TOTP code."""
        ok, msg, setup_data = init_mfa_setup(self.analyst_id)
        self.assertTrue(ok)
        secret = setup_data["secret"]
        backup_codes = setup_data["backup_codes"]

        # 1. Invalid TOTP code is rejected
        bad_ok, bad_msg = confirm_and_enable_mfa(self.analyst_id, secret, "000000", backup_codes)
        self.assertFalse(bad_ok)
        self.assertIn("Invalid authenticator code", bad_msg)

        u = db.session.get(User, self.analyst_id)
        self.assertFalse(u.mfa_enabled)
        self.assertIsNone(u.mfa_secret)

        # 2. Valid TOTP code enables MFA
        valid_code = pyotp.TOTP(secret).now()
        good_ok, good_msg = confirm_and_enable_mfa(self.analyst_id, secret, valid_code, backup_codes)
        self.assertTrue(good_ok)

        db.session.refresh(u)
        self.assertTrue(u.mfa_enabled)
        self.assertEqual(u.mfa_secret, secret)
        self.assertIsNotNone(u.mfa_backup_codes)

        # Verify audit log recorded
        log = AuditLog.query.filter_by(user_id=self.analyst_id, action="mfa_enabled:totp").first()
        self.assertIsNotNone(log)
        # Verify secret is never stored in audit log
        self.assertNotIn(secret, str(log.action))

    def test_verify_user_mfa_totp_and_backup_code(self):
        """verify_user_mfa validates TOTP and consumes single-use emergency backup recovery codes."""
        secret = generate_mfa_secret()
        backup_codes = generate_backup_codes(8)
        first_backup = backup_codes[0]

        ok, msg = confirm_and_enable_mfa(self.analyst_id, secret, pyotp.TOTP(secret).now(), backup_codes)
        self.assertTrue(ok)

        u = db.session.get(User, self.analyst_id)
        self.assertEqual(count_remaining_backup_codes(u), 8)

        # 1. Valid TOTP code verifies successfully
        totp_code = pyotp.TOTP(secret).now()
        v_ok, _ = verify_user_mfa(u, totp_code)
        self.assertTrue(v_ok)

        # 2. Invalid TOTP code fails
        bad_ok, _ = verify_user_mfa(u, "999999")
        self.assertFalse(bad_ok)

        # 3. Valid backup code verifies and decrements remaining count
        b_ok, _ = verify_user_mfa(u, first_backup)
        self.assertTrue(b_ok)
        db.session.refresh(u)
        self.assertEqual(count_remaining_backup_codes(u), 7)

        # 4. Consumed backup code cannot be used a second time
        reused_ok, _ = verify_user_mfa(u, first_backup)
        self.assertFalse(reused_ok)
        self.assertEqual(count_remaining_backup_codes(u), 7)

    def test_disable_mfa_self_service_and_admin_override(self):
        """Self-service disable requires password; admin override disables without user password."""
        secret = generate_mfa_secret()
        backup_codes = generate_backup_codes(8)
        confirm_and_enable_mfa(self.analyst_id, secret, pyotp.TOTP(secret).now(), backup_codes)

        u = db.session.get(User, self.analyst_id)
        self.assertTrue(u.mfa_enabled)

        # 1. Self-service wrong password rejected
        bad_ok, _ = disable_mfa_for_user(self.analyst_id, current_password="WrongPassword123!")
        self.assertFalse(bad_ok)
        db.session.refresh(u)
        self.assertTrue(u.mfa_enabled)

        # 2. Self-service correct password disables MFA
        good_ok, _ = disable_mfa_for_user(self.analyst_id, current_password=_ANALYST_PWD)
        self.assertTrue(good_ok)
        db.session.refresh(u)
        self.assertFalse(u.mfa_enabled)
        self.assertIsNone(u.mfa_secret)
        self.assertIsNone(u.mfa_backup_codes)

        # 3. Admin override disables MFA
        confirm_and_enable_mfa(self.analyst_id, secret, pyotp.TOTP(secret).now(), backup_codes)
        db.session.refresh(u)
        self.assertTrue(u.mfa_enabled)

        admin_ok, _ = disable_mfa_for_user(self.analyst_id, is_admin_override=True, actor_id=self.admin_id)
        self.assertTrue(admin_ok)
        db.session.refresh(u)
        self.assertFalse(u.mfa_enabled)

        # Check admin audit log (most recent disable event)
        log = AuditLog.query.filter(AuditLog.action.like("mfa_disabled%"), AuditLog.target_id == self.analyst_id).order_by(AuditLog.id.desc()).first()
        self.assertIsNotNone(log)
        self.assertEqual(log.user_id, self.admin_id)

    # =========================================================================
    # 2. LOGIN 2FA CHALLENGE WORKFLOW
    # =========================================================================

    def test_login_flow_redirects_to_2fa_when_mfa_enabled(self):
        """User with MFA enabled is redirected to /login/2fa upon correct password entry."""
        secret = generate_mfa_secret()
        backup_codes = generate_backup_codes(8)
        confirm_and_enable_mfa(self.analyst_id, secret, pyotp.TOTP(secret).now(), backup_codes)

        client = self.app.test_client()
        token = self._get_csrf_token(client, "/login")

        # Step 1: Submit email & password
        resp = client.post(
            "/login",
            data={
                "csrf_token": token,
                "email": self.analyst.email,
                "password": _ANALYST_PWD,
            },
            follow_redirects=False,
        )
        self.assertEqual(resp.status_code, 302)
        self.assertIn("/login/2fa", resp.headers["Location"])

        # Step 2: Accessing /dashboard directly before completing 2FA redirects back to /login
        dash_resp = client.get("/dashboard", follow_redirects=False)
        self.assertEqual(dash_resp.status_code, 302)
        self.assertIn("/login", dash_resp.headers["Location"])

        # Step 3: GET /login/2fa renders 2FA input page
        two_fa_page = client.get("/login/2fa")
        self.assertEqual(two_fa_page.status_code, 200)
        page_html = two_fa_page.get_data(as_text=True)
        self.assertIn("Two-Factor Authentication", page_html)
        self.assertIn("totp_code", page_html)

        # Step 4: POST /login/2fa with invalid code fails
        two_fa_token = self._extract_csrf_token(page_html)
        bad_post = client.post(
            "/login/2fa",
            data={"csrf_token": two_fa_token, "totp_code": "000000"},
            follow_redirects=True,
        )
        bad_html = bad_post.get_data(as_text=True)
        self.assertIn("Invalid authentication code", bad_html)

        # Step 5: POST /login/2fa with valid TOTP code completes login
        good_code = pyotp.TOTP(secret).now()
        fresh_token = self._get_csrf_token(client, "/login/2fa")
        good_post = client.post(
            "/login/2fa",
            data={"csrf_token": fresh_token, "totp_code": good_code},
            follow_redirects=False,
        )
        self.assertEqual(good_post.status_code, 302)
        self.assertIn("/dashboard", good_post.headers["Location"])

        # User is now fully authenticated
        dash_auth = client.get("/dashboard")
        self.assertEqual(dash_auth.status_code, 200)

    def test_login_2fa_via_backup_code(self):
        """User can log in using single-use emergency backup recovery code."""
        secret = generate_mfa_secret()
        backup_codes = generate_backup_codes(8)
        test_recovery_code = backup_codes[0]
        confirm_and_enable_mfa(self.analyst_id, secret, pyotp.TOTP(secret).now(), backup_codes)

        client = self.app.test_client()
        token = self._get_csrf_token(client, "/login")

        client.post(
            "/login",
            data={
                "csrf_token": token,
                "email": self.analyst.email,
                "password": _ANALYST_PWD,
            },
            follow_redirects=True,
        )

        two_fa_token = self._get_csrf_token(client, "/login/2fa")
        resp = client.post(
            "/login/2fa",
            data={"csrf_token": two_fa_token, "totp_code": test_recovery_code},
            follow_redirects=False,
        )
        self.assertEqual(resp.status_code, 302)
        self.assertIn("/dashboard", resp.headers["Location"])

        # Backup code should now be consumed
        u = db.session.get(User, self.analyst_id)
        self.assertEqual(count_remaining_backup_codes(u), 7)

    # =========================================================================
    # 3. PROFILE ROUTE & TEMPLATE MFA INTEGRATION
    # =========================================================================

    def test_profile_mfa_setup_and_enable_workflow(self):
        """Analyst can initiate MFA setup on profile, view QR SVG, and complete enablement."""
        client = self.app.test_client()
        self._login(client, self.analyst.email, _ANALYST_PWD)

        # 1. Profile page displays 2FA Disabled initial state
        prof = client.get("/profile")
        self.assertEqual(prof.status_code, 200)
        self.assertIn("2FA Disabled", prof.get_data(as_text=True))

        # 2. POST action="setup_mfa" starts wizard
        token = self._get_csrf_token(client, "/profile")
        setup_resp = client.post(
            "/profile",
            data={"csrf_token": token, "action": "setup_mfa"},
            follow_redirects=True,
        )
        setup_html = setup_resp.get_data(as_text=True)
        self.assertIn("Scan Authenticator QR Code", setup_html)
        self.assertIn("<svg", setup_html)
        self.assertIn("Save Emergency Recovery Codes", setup_html)

        # 3. Read secret from session
        with client.session_transaction() as sess:
            secret = sess.get("mfa_setup_secret")
        self.assertIsNotNone(secret)

        # 4. POST action="enable_mfa" with valid code
        token2 = self._get_csrf_token(client, "/profile")
        valid_code = pyotp.TOTP(secret).now()
        enable_resp = client.post(
            "/profile",
            data={"csrf_token": token2, "action": "enable_mfa", "totp_code": valid_code},
            follow_redirects=True,
        )
        enable_html = enable_resp.get_data(as_text=True)
        self.assertIn("2FA Is Active & Enforced", enable_html)

        # 5. POST action="disable_mfa" with password disables it
        token3 = self._get_csrf_token(client, "/profile")
        disable_resp = client.post(
            "/profile",
            data={"csrf_token": token3, "action": "disable_mfa", "current_password": _ANALYST_PWD},
            follow_redirects=True,
        )
        disable_html = disable_resp.get_data(as_text=True)
        self.assertIn("Multi-Factor Authentication disabled for", disable_html)

    # =========================================================================
    # 4. USER API KEY SERVICE & PROFILE INTEGRATION
    # =========================================================================

    def test_api_key_generation_rotation_revocation(self):
        """API keys are securely generated, rotated, masked, and revoked."""
        # 1. Generate key
        ok, msg, raw_token = generate_user_api_key(self.analyst_id, label="SIEM Daemon")
        self.assertTrue(ok)
        self.assertTrue(raw_token.startswith("tip_live_"))

        u = db.session.get(User, self.analyst_id)
        self.assertEqual(u.api_key, raw_token)
        self.assertEqual(u.api_key_label, "SIEM Daemon")
        self.assertIsNotNone(u.api_key_created_at)

        # 2. Info masking
        info = get_user_api_key_info(self.analyst_id)
        self.assertTrue(info["has_key"])
        self.assertEqual(info["label"], "SIEM Daemon")
        self.assertTrue(info["masked_key"].startswith("tip_live_"))
        self.assertEqual(info["masked_key"][-4:], raw_token[-4:])

        # 3. Rotate key
        ok_rot, _, raw_token_2 = generate_user_api_key(self.analyst_id, label="SIEM Daemon v2")
        self.assertTrue(ok_rot)
        self.assertNotEqual(raw_token, raw_token_2)

        db.session.refresh(u)
        self.assertEqual(u.api_key, raw_token_2)
        self.assertEqual(u.api_key_label, "SIEM Daemon v2")

        # 4. Revoke key
        ok_rev, _ = revoke_user_api_key(self.analyst_id)
        self.assertTrue(ok_rev)

        db.session.refresh(u)
        self.assertIsNone(u.api_key)
        self.assertIsNone(u.api_key_created_at)
        self.assertIsNone(u.api_key_label)

        info_rev = get_user_api_key_info(self.analyst_id)
        self.assertFalse(info_rev["has_key"])

    def test_profile_api_key_self_service_workflow(self):
        """Analyst can generate, view masked info, and revoke personal API key via /profile."""
        client = self.app.test_client()
        self._login(client, self.analyst.email, _ANALYST_PWD)

        # 1. Generate key
        token = self._get_csrf_token(client, "/profile")
        gen_resp = client.post(
            "/profile",
            data={"csrf_token": token, "action": "generate_api_key", "api_key_label": "Automation-Worker"},
            follow_redirects=True,
        )
        gen_html = gen_resp.get_data(as_text=True)
        self.assertIn("New Personal API Key Generated", gen_html)
        self.assertIn("tip_live_", gen_html)

        # 2. Subsequent GET hides raw token and displays masked key
        next_get = client.get("/profile")
        next_html = next_get.get_data(as_text=True)
        self.assertIn("Active API Key Provisioned", next_html)
        self.assertIn("tip_live_", next_html)
        self.assertIn("••••••••", next_html)
        self.assertIn("Automation-Worker", next_html)

        # 3. Revoke key
        token2 = self._get_csrf_token(client, "/profile")
        rev_resp = client.post(
            "/profile",
            data={"csrf_token": token2, "action": "revoke_api_key"},
            follow_redirects=True,
        )
        rev_html = rev_resp.get_data(as_text=True)
        self.assertIn("API key has been revoked", rev_html)
        self.assertIn("No Personal API Key Provisioned", rev_html)

    # =========================================================================
    # 5. REST API AUTHENTICATION VIA INDIVIDUAL API KEY
    # =========================================================================

    def test_rest_api_authenticates_with_individual_analyst_key(self):
        """REST API endpoints authenticate successfully with personal analyst API key."""
        ok, msg, token = generate_user_api_key(self.analyst_id, label="Analyst Script")
        self.assertTrue(ok)

        client = self.app.test_client()

        # 1. Query with personal X-API-Key header returns 200
        resp = client.get(
            "/api/v2/indicators",
            headers={"X-API-Key": token},
        )
        self.assertEqual(resp.status_code, 200)
        data = json.loads(resp.get_data(as_text=True))
        self.assertIn("items", data)
        self.assertIsInstance(data["items"], list)

        # 2. Query with invalid X-API-Key header returns 401
        bad_resp = client.get(
            "/api/v2/indicators",
            headers={"X-API-Key": "tip_live_invalidtoken12345"},
        )
        self.assertEqual(bad_resp.status_code, 401)

        # 3. Revoke key and verify programmatic query is immediately rejected
        revoke_user_api_key(self.analyst_id)
        revoked_resp = client.get(
            "/api/v2/indicators",
            headers={"X-API-Key": token},
        )
        self.assertEqual(revoked_resp.status_code, 401)

    # =========================================================================
    # 6. ADMIN PANEL 2FA RESET & RBAC
    # =========================================================================

    def test_admin_panel_displays_2fa_and_allows_admin_reset(self):
        """Admin panel displays TOTP status and enables admin to reset 2FA for locked-out user."""
        secret = generate_mfa_secret()
        backup_codes = generate_backup_codes(8)
        confirm_and_enable_mfa(self.analyst_id, secret, pyotp.TOTP(secret).now(), backup_codes)

        client = self.app.test_client()
        self._login(client, self.admin.email, _ADMIN_PWD)

        # 1. Admin panel displays TOTP badge
        admin_page = client.get("/admin")
        self.assertEqual(admin_page.status_code, 200)
        page_html = admin_page.get_data(as_text=True)
        self.assertIn("TOTP", page_html)
        self.assertIn("Reset 2FA", page_html)

        # 2. Admin submits action="reset_mfa"
        token = self._get_csrf_token(client, "/admin")
        reset_resp = client.post(
            "/admin",
            data={
                "csrf_token": token,
                "user_id": self.analyst_id,
                "action": "reset_mfa",
            },
            follow_redirects=True,
        )
        self.assertEqual(reset_resp.status_code, 200)
        reset_html = reset_resp.get_data(as_text=True)
        self.assertIn("Multi-Factor Authentication disabled for", reset_html)

        # Verify MFA disabled in DB
        u = db.session.get(User, self.analyst_id)
        self.assertFalse(u.mfa_enabled)
        self.assertIsNone(u.mfa_secret)

    def test_non_admin_cannot_reset_mfa(self):
        """Analyst or regular user cannot call reset_mfa on admin panel (403 Forbidden)."""
        client = self.app.test_client()
        self._login(client, self.analyst.email, _ANALYST_PWD)

        token = self._get_csrf_token(client, "/profile")
        resp = client.post(
            "/admin",
            data={
                "csrf_token": token,
                "user_id": self.user_id,
                "action": "reset_mfa",
            },
        )
        self.assertEqual(resp.status_code, 403)


if __name__ == "__main__":
    unittest.main()
