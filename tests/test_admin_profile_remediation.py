"""
Tests for Admin Panel Remediation: G-1, G-2, G-9
================================================
Covers:
1. G-1 Admin-Initiated Password Reset:
   - Admin authorized reset with generated secure temporary password
   - Admin authorized reset with valid custom password
   - Audit trail records actor, target, timestamp, and outcome WITHOUT secrets
   - Non-admin (analyst, regular user) cannot reset other users' passwords
   - Invalid user ID handled safely without unhandled exceptions
   - Weak custom password rejected by complexity policy
   - Token-based reset generation, consumption, single-use invalidation
2. G-2 & G-9 Functional Profile Backend & Real User Data:
   - Self-service password change requires current password
   - Wrong current password rejected
   - Weak new password rejected by complexity policy
   - Mismatched confirmation rejected
   - Same-as-current password rejected
   - Successful password change updates hash and logs audit entry
   - Privilege escalation attempt via profile rejected (role/status immutable)
   - Profile page renders real current_user attributes (no hardcoded Alice/Vance)
   - CSRF protection enforced on profile POST
"""

import re
import unittest
from flask import g
from werkzeug.security import generate_password_hash, check_password_hash

from app import create_app, db, limiter
from app.models import User, AuditLog
from app.services.admin_service import (
    reset_user_password,
    generate_password_reset_token,
    reset_password_with_token,
)
from app.services.security_service import validate_password_complexity

_TEST_PREFIX = "remed_test_"
_ADMIN_PWD = "AdminSecure2026!#"
_ANALYST_PWD = "AnalystSecure2026!#"
_USER_PWD = "UserSecure2026!#"


class TestAdminProfileRemediation(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.app = create_app()
        cls.app.config["TESTING"] = True
        cls.app.config["WTF_CSRF_ENABLED"] = True
        cls.app.config["RATELIMIT_ENABLED"] = True
        cls.app.config["RATELIMIT_STORAGE_URI"] = "memory://"
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
        )
        self.analyst = User(
            username=f"{_TEST_PREFIX}analyst",
            email=f"{_TEST_PREFIX}analyst@tip.local",
            password_hash=generate_password_hash(_ANALYST_PWD),
            role="analyst",
            is_active=True,
        )
        self.regular_user = User(
            username=f"{_TEST_PREFIX}regular",
            email=f"{_TEST_PREFIX}regular@tip.local",
            password_hash=generate_password_hash(_USER_PWD),
            role="user",
            is_active=True,
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
    # G-1: ADMIN-INITIATED PASSWORD RESET TESTS
    # =========================================================================

    def test_admin_can_reset_password_with_temporary_password(self):
        """Admin resets another user's password; system generates a secure temporary password."""
        c = self.app.test_client()
        self._login(c, self.admin.email, _ADMIN_PWD)

        # GET admin panel for CSRF token
        token = self._get_csrf_token(c, "/admin")

        # POST reset_password action
        resp = c.post(
            "/admin",
            data={
                "csrf_token": token,
                "action": "reset_password",
                "user_id": self.analyst_id,
            },
            follow_redirects=True,
        )
        self.assertEqual(resp.status_code, 200)
        html = resp.get_data(as_text=True)
        self.assertIn("Password reset for", html)
        self.assertIn("Temporary password:", html)

        # Extract generated temporary password from response
        import html as html_lib
        html_clean = html_lib.unescape(html)
        temp_pwd_match = re.search(r'Temporary password:\s*([^\s<]+)', html_clean)
        self.assertIsNotNone(temp_pwd_match, "Temporary password must be displayed to admin")
        temp_pwd = temp_pwd_match.group(1).rstrip('.')

        # Validate that temporary password satisfies complexity
        is_valid, _ = validate_password_complexity(temp_pwd)
        self.assertTrue(is_valid, f"Temporary password '{temp_pwd}' must satisfy complexity policy")

        # Verify old password no longer works
        c_analyst = self.app.test_client()
        old_login = self._login(c_analyst, self.analyst.email, _ANALYST_PWD)
        self.assertIn("Invalid email or password", old_login.get_data(as_text=True))

        # Verify analyst can log in with the new temporary password
        new_login = self._login(c_analyst, self.analyst.email, temp_pwd)
        self.assertEqual(new_login.status_code, 200)
        self.assertIn(f"Welcome, {_TEST_PREFIX}analyst", new_login.get_data(as_text=True))

        # Verify audit log recorded without secrets
        log = AuditLog.query.filter_by(
            user_id=self.admin_id,
            target_id=self.analyst_id,
        ).order_by(AuditLog.id.desc()).first()
        self.assertIsNotNone(log)
        self.assertIn("admin_reset_password", log.action)
        # CRITICAL: Verify temporary password is NEVER in the audit log
        self.assertNotIn(temp_pwd, log.action)

    def test_admin_can_reset_password_with_custom_password(self):
        """Admin sets a specific strong password for target user."""
        c = self.app.test_client()
        self._login(c, self.admin.email, _ADMIN_PWD)

        token = self._get_csrf_token(c, "/admin")

        custom_pwd = "CustomAdminSet2026!#"
        resp = c.post(
            "/admin",
            data={
                "csrf_token": token,
                "action": "reset_password",
                "user_id": self.user_id,
                "new_password": custom_pwd,
            },
            follow_redirects=True,
        )
        self.assertEqual(resp.status_code, 200)
        self.assertIn("Password successfully reset", resp.get_data(as_text=True))

        # Verify user can log in with the custom password
        c_user = self.app.test_client()
        login_resp = self._login(c_user, self.regular_user.email, custom_pwd)
        self.assertEqual(login_resp.status_code, 200)
        self.assertIn(f"Welcome, {_TEST_PREFIX}regular", login_resp.get_data(as_text=True))

    def test_admin_reset_weak_password_rejected(self):
        """Admin reset rejects weak custom password failing complexity."""
        ok, msg, _ = reset_user_password(self.admin_id, self.analyst_id, "weak")
        self.assertFalse(ok)
        self.assertTrue("character" in msg or "uppercase" in msg or "digit" in msg)

        # Target user password hash must remain unchanged
        analyst_fresh = db.session.get(User, self.analyst_id)
        self.assertTrue(check_password_hash(analyst_fresh.password_hash, _ANALYST_PWD))

    def test_non_admin_cannot_reset_passwords(self):
        """Analyst and regular users are strictly forbidden from resetting other accounts."""
        # 1. Analyst via service
        ok, msg, _ = reset_user_password(self.analyst_id, self.user_id)
        self.assertFalse(ok)
        self.assertIn("Unauthorized", msg)

        # 2. Regular user via service
        ok, msg, _ = reset_user_password(self.user_id, self.analyst_id)
        self.assertFalse(ok)
        self.assertIn("Unauthorized", msg)

        # 3. Analyst via HTTP route with valid CSRF token -> rejected with 403 Forbidden
        c_analyst = self.app.test_client()
        self._login(c_analyst, self.analyst.email, _ANALYST_PWD)
        token = self._get_csrf_token(c_analyst, "/profile")
        resp = c_analyst.post(
            "/admin",
            data={"csrf_token": token, "action": "reset_password", "user_id": self.user_id},
        )
        self.assertEqual(resp.status_code, 403)

    def test_admin_reset_invalid_user_handled_safely(self):
        """Invalid or non-existent user IDs are handled safely without crashing."""
        ok, msg, _ = reset_user_password(self.admin_id, 999999)
        self.assertFalse(ok)
        self.assertIn("not found", msg)

    def test_token_based_password_reset_workflow(self):
        """Verifies cryptographically signed reset token generation and consumption."""
        # 1. Admin generates reset token for analyst
        ok, msg, token = generate_password_reset_token(self.admin_id, self.analyst_id)
        self.assertTrue(ok)
        self.assertIsNotNone(token)

        # 2. Consume token with valid new password
        new_pwd = "TokenReset2026!#$"
        reset_ok, reset_msg = reset_password_with_token(token, new_pwd)
        self.assertTrue(reset_ok, f"Expected token consumption to succeed, got: {reset_msg}")

        # 3. Verify analyst can log in with new password
        c = self.app.test_client()
        login_resp = self._login(c, self.analyst.email, new_pwd)
        self.assertEqual(login_resp.status_code, 200)
        self.assertIn(f"Welcome, {_TEST_PREFIX}analyst", login_resp.get_data(as_text=True))

        # 4. Verify token cannot be reused (single-use validation)
        reuse_ok, reuse_msg = reset_password_with_token(token, "AnotherPass2026!#$")
        self.assertFalse(reuse_ok)
        self.assertIn("already been used", reuse_msg)

    # =========================================================================
    # G-2 & G-9: FUNCTIONAL PROFILE BACKEND & DATA TESTS
    # =========================================================================

    def test_profile_requires_current_password(self):
        """Self-service password change fails if current password is omitted."""
        c = self.app.test_client()
        self._login(c, self.analyst.email, _ANALYST_PWD)

        token = self._get_csrf_token(c, "/profile")

        post_resp = c.post(
            "/profile",
            data={
                "csrf_token": token,
                "action": "change_password",
                "current_password": "",
                "new_password": "NewValidPass2026!#",
                "confirm_password": "NewValidPass2026!#",
            },
            follow_redirects=True,
        )
        self.assertEqual(post_resp.status_code, 200)
        self.assertIn("Current password is required", post_resp.get_data(as_text=True))

    def test_profile_wrong_current_password_rejected(self):
        """Self-service password change fails if current password is incorrect."""
        c = self.app.test_client()
        self._login(c, self.analyst.email, _ANALYST_PWD)

        token = self._get_csrf_token(c, "/profile")

        post_resp = c.post(
            "/profile",
            data={
                "csrf_token": token,
                "action": "change_password",
                "current_password": "WrongCurrentPassword123!",
                "new_password": "NewValidPass2026!#",
                "confirm_password": "NewValidPass2026!#",
            },
            follow_redirects=True,
        )
        self.assertEqual(post_resp.status_code, 200)
        self.assertIn("Current password is incorrect", post_resp.get_data(as_text=True))

    def test_profile_weak_new_password_rejected(self):
        """Self-service password change fails if new password fails complexity."""
        c = self.app.test_client()
        self._login(c, self.analyst.email, _ANALYST_PWD)

        token = self._get_csrf_token(c, "/profile")

        post_resp = c.post(
            "/profile",
            data={
                "csrf_token": token,
                "action": "change_password",
                "current_password": _ANALYST_PWD,
                "new_password": "weak",
                "confirm_password": "weak",
            },
            follow_redirects=True,
        )
        self.assertEqual(post_resp.status_code, 200)
        self.assertTrue(
            "character" in post_resp.get_data(as_text=True)
            or "uppercase" in post_resp.get_data(as_text=True)
        )

    def test_profile_mismatched_confirmation_rejected(self):
        """Self-service password change fails if new password and confirmation differ."""
        c = self.app.test_client()
        self._login(c, self.analyst.email, _ANALYST_PWD)

        token = self._get_csrf_token(c, "/profile")

        post_resp = c.post(
            "/profile",
            data={
                "csrf_token": token,
                "action": "change_password",
                "current_password": _ANALYST_PWD,
                "new_password": "NewValidPass2026!#",
                "confirm_password": "DifferentPass2026!#",
            },
            follow_redirects=True,
        )
        self.assertEqual(post_resp.status_code, 200)
        self.assertIn("do not match", post_resp.get_data(as_text=True))

    def test_profile_same_as_current_rejected(self):
        """Self-service password change fails if new password is identical to current."""
        c = self.app.test_client()
        self._login(c, self.analyst.email, _ANALYST_PWD)

        token = self._get_csrf_token(c, "/profile")

        post_resp = c.post(
            "/profile",
            data={
                "csrf_token": token,
                "action": "change_password",
                "current_password": _ANALYST_PWD,
                "new_password": _ANALYST_PWD,
                "confirm_password": _ANALYST_PWD,
            },
            follow_redirects=True,
        )
        self.assertEqual(post_resp.status_code, 200)
        self.assertIn("cannot be the same", post_resp.get_data(as_text=True))

    def test_profile_successful_password_change_updates_hash_and_audit(self):
        """Self-service password change successfully updates password hash and writes audit log."""
        c = self.app.test_client()
        self._login(c, self.analyst.email, _ANALYST_PWD)

        token = self._get_csrf_token(c, "/profile")

        new_pwd = "BrandNewAnalystPass2026!#"
        post_resp = c.post(
            "/profile",
            data={
                "csrf_token": token,
                "action": "change_password",
                "current_password": _ANALYST_PWD,
                "new_password": new_pwd,
                "confirm_password": new_pwd,
            },
            follow_redirects=True,
        )
        self.assertEqual(post_resp.status_code, 200)
        self.assertIn("successfully updated", post_resp.get_data(as_text=True))

        # Verify DB hash was updated
        analyst_fresh = db.session.get(User, self.analyst_id)
        self.assertTrue(check_password_hash(analyst_fresh.password_hash, new_pwd))

        # Verify analyst can log in with new password
        c_fresh = self.app.test_client()
        login_resp = self._login(c_fresh, self.analyst.email, new_pwd)
        self.assertEqual(login_resp.status_code, 200)
        self.assertIn(f"Welcome, {_TEST_PREFIX}analyst", login_resp.get_data(as_text=True))

        # Verify audit log exists without exposing the password
        log = AuditLog.query.filter_by(
            user_id=self.analyst_id,
            action="self_service_password_change",
        ).first()
        self.assertIsNotNone(log)
        self.assertNotIn(new_pwd, log.action)

    def test_profile_renders_actual_user_data_no_alice_vance(self):
        """Profile page renders authenticated user attributes and not hardcoded Alice/Vance mock data (G-9)."""
        c = self.app.test_client()
        self._login(c, self.analyst.email, _ANALYST_PWD)

        resp = c.get("/profile")
        self.assertEqual(resp.status_code, 200)
        html = resp.get_data(as_text=True)

        # Real user attributes must be present
        self.assertIn(self.analyst.username, html)
        self.assertIn(self.analyst.email, html)
        self.assertIn("ANALYST", html)

        # Hardcoded mock credentials from old template must NOT be present
        self.assertNotIn("alice.vance@org.com", html)
        self.assertNotIn('value="Alice"', html)
        self.assertNotIn('value="Vance"', html)

        # MFA status accurately presented (Functional RFC 6238 TOTP in Phase 3)
        self.assertTrue("Enterprise IdP Integration" in html or "2FA Disabled" in html or "2FA Is Active" in html)
        self.assertIn("disabled", html.lower())

    def test_profile_cannot_escalate_privileges(self):
        """Submitting modified role/status through profile contact form does not alter privileges."""
        c = self.app.test_client()
        self._login(c, self.analyst.email, _ANALYST_PWD)

        token = self._get_csrf_token(c, "/profile")

        # Attempt to escalate to admin
        c.post(
            "/profile",
            data={
                "csrf_token": token,
                "action": "update_contact",
                "role": "admin",
                "is_active": "0",
            },
            follow_redirects=True,
        )

        analyst_fresh = db.session.get(User, self.analyst_id)
        self.assertEqual(analyst_fresh.role, "analyst")
        self.assertTrue(analyst_fresh.is_active)

    def test_profile_csrf_enforcement(self):
        """Submitting profile password change without CSRF token is rejected with HTTP 400."""
        c = self.app.test_client()
        self._login(c, self.analyst.email, _ANALYST_PWD)

        # POST without CSRF token
        post_resp = c.post(
            "/profile",
            data={
                "action": "change_password",
                "current_password": _ANALYST_PWD,
                "new_password": "NewValidPass2026!#",
                "confirm_password": "NewValidPass2026!#",
            },
        )
        self.assertEqual(post_resp.status_code, 400)


if __name__ == "__main__":
    unittest.main()
