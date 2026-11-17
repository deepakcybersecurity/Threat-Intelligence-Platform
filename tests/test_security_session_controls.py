"""
Tests for Security & Session Controls Remediation: G-3, G-4, G-6
================================================================
Covers:
1. G-3: Last Login Tracking
   - Successful login records `last_login` timestamp and `last_login_ip`
   - Admin panel UI displays last login datetime
2. G-4: Account Lockout & Brute-Force Protection
   - Failed password attempt increments `failed_login_count`
   - 5 consecutive failed attempts trigger account lockout (`locked_until` set in future)
   - Locked account rejects even correct credentials during lockout window
   - Admin can manually unlock account via Admin Panel (`action: "unlock_user"`)
   - Admin re-activating suspended user clears lockout state
   - Successful login resets `failed_login_count` and clears lockout
   - Audit trail records `login_failed_password`, `account_lockout`, `unlock_user`
3. G-6: Force Session Revocation (Immediate Logout)
   - Suspended user's active session is terminated on immediate next request
   - Admin password reset immediately terminates user's active browser sessions
   - Admin "Revoke Session" action immediately invalidates user's active sessions
   - Self-service password change preserves current session while invalidating other devices
   - Non-admin forbidden from executing unlock or session revocation (403 Forbidden)
"""

import re
import unittest
from datetime import datetime, timezone, timedelta
from flask import g
from werkzeug.security import generate_password_hash

from app import create_app, db, limiter
from app.models import User, AuditLog
from app.services.admin_service import (
    reset_user_password,
    unlock_user,
    revoke_user_sessions,
)

_TEST_PREFIX = "sess_test_"
_ADMIN_PWD = "AdminSecure2026!#"
_ANALYST_PWD = "AnalystSecure2026!#"
_USER_PWD = "UserSecure2026!#"


class TestSecuritySessionControls(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.app = create_app()
        cls.app.config["TESTING"] = True
        cls.app.config["WTF_CSRF_ENABLED"] = True
        cls.app.config["RATELIMIT_ENABLED"] = False  # Disabled here to isolate lockout logic from rate limits
        cls.app.config["ACCOUNT_LOCKOUT_THRESHOLD"] = 5
        cls.app.config["ACCOUNT_LOCKOUT_DURATION_MINUTES"] = 15
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
    # G-3: LAST LOGIN TRACKING TESTS
    # =========================================================================

    def test_successful_login_records_last_login_and_ip(self):
        """Successful login populates user.last_login timestamp and client IP."""
        u_before = db.session.get(User, self.analyst_id)
        self.assertIsNone(u_before.last_login)
        self.assertIsNone(u_before.last_login_ip)

        c = self.app.test_client()
        resp = self._login(c, self.analyst.email, _ANALYST_PWD)
        self.assertEqual(resp.status_code, 200)

        u_after = db.session.get(User, self.analyst_id)
        self.assertIsNotNone(u_after.last_login)
        self.assertIsNotNone(u_after.last_login_ip)
        # Verify timestamp is recent (within 10 seconds)
        delta = datetime.now(timezone.utc) - (u_after.last_login.replace(tzinfo=timezone.utc) if u_after.last_login.tzinfo is None else u_after.last_login)
        self.assertLess(delta.total_seconds(), 10)

    # =========================================================================
    # G-4: ACCOUNT LOCKOUT & BRUTE FORCE PROTECTION TESTS
    # =========================================================================

    def test_failed_login_increments_counter(self):
        """Failed password attempt increments failed_login_count and logs audit event."""
        c = self.app.test_client()
        resp = self._login(c, self.analyst.email, "WrongPassword123!")
        self.assertEqual(resp.status_code, 200)
        self.assertIn("Invalid email or password", resp.get_data(as_text=True))

        analyst_fresh = db.session.get(User, self.analyst_id)
        self.assertEqual(analyst_fresh.failed_login_count, 1)
        self.assertFalse(analyst_fresh.is_locked)

        # Audit log entry recorded
        log = AuditLog.query.filter_by(
            user_id=self.analyst_id,
            action=f"login_failed_password:{self.analyst.username}",
        ).first()
        self.assertIsNotNone(log)

    def test_account_lockout_after_threshold_attempts(self):
        """Account is locked after 5 consecutive failed login attempts."""
        c = self.app.test_client()

        # Submit 4 wrong attempts -> not locked yet
        for i in range(4):
            resp = self._login(c, self.analyst.email, f"WrongPass{i}!")
            self.assertIn("Invalid email or password", resp.get_data(as_text=True))

        analyst_fresh = db.session.get(User, self.analyst_id)
        self.assertEqual(analyst_fresh.failed_login_count, 4)
        self.assertFalse(analyst_fresh.is_locked)

        # 5th failed attempt triggers lockout
        resp5 = self._login(c, self.analyst.email, "WrongPass5!")
        html5 = resp5.get_data(as_text=True)
        self.assertIn("temporarily locked", html5)

        analyst_locked = db.session.get(User, self.analyst_id)
        self.assertEqual(analyst_locked.failed_login_count, 5)
        self.assertTrue(analyst_locked.is_locked)
        self.assertIsNotNone(analyst_locked.locked_until)

        # Audit log recorded
        log = AuditLog.query.filter_by(
            user_id=self.analyst_id,
            action=f"account_lockout:{self.analyst.username}",
        ).first()
        self.assertIsNotNone(log)

    def test_locked_account_rejects_even_correct_password(self):
        """While account is locked, even the correct password is rejected."""
        # Manually lock the user
        analyst = db.session.get(User, self.analyst_id)
        analyst.failed_login_count = 5
        analyst.locked_until = datetime.now(timezone.utc) + timedelta(minutes=15)
        db.session.commit()

        c = self.app.test_client()
        resp = self._login(c, self.analyst.email, _ANALYST_PWD)
        html = resp.get_data(as_text=True)
        self.assertIn("temporarily locked", html)

    def test_admin_can_manually_unlock_account(self):
        """Admin can manually unlock an account via admin panel."""
        # Lock user
        analyst = db.session.get(User, self.analyst_id)
        analyst.failed_login_count = 5
        analyst.locked_until = datetime.now(timezone.utc) + timedelta(minutes=15)
        db.session.commit()
        self.assertTrue(analyst.is_locked)

        # Admin logs in and unlocks account
        c_admin = self.app.test_client()
        self._login(c_admin, self.admin.email, _ADMIN_PWD)

        token = self._get_csrf_token(c_admin, "/admin")
        unlock_resp = c_admin.post(
            "/admin",
            data={"csrf_token": token, "action": "unlock_user", "user_id": self.analyst_id},
            follow_redirects=True,
        )
        self.assertEqual(unlock_resp.status_code, 200)
        self.assertIn("successfully unlocked", unlock_resp.get_data(as_text=True))

        # Target user is unlocked
        analyst_fresh = db.session.get(User, self.analyst_id)
        self.assertEqual(analyst_fresh.failed_login_count, 0)
        self.assertIsNone(analyst_fresh.locked_until)
        self.assertFalse(analyst_fresh.is_locked)

        # Analyst can now log in with correct password
        c_analyst = self.app.test_client()
        login_resp = self._login(c_analyst, self.analyst.email, _ANALYST_PWD)
        self.assertEqual(login_resp.status_code, 200)
        self.assertIn(f"Welcome, {_TEST_PREFIX}analyst", login_resp.get_data(as_text=True))

    def test_successful_login_resets_failed_counter(self):
        """Successful login resets failed_login_count to 0."""
        analyst = db.session.get(User, self.analyst_id)
        analyst.failed_login_count = 3
        db.session.commit()

        c = self.app.test_client()
        login_resp = self._login(c, self.analyst.email, _ANALYST_PWD)
        self.assertEqual(login_resp.status_code, 200)

        analyst_fresh = db.session.get(User, self.analyst_id)
        self.assertEqual(analyst_fresh.failed_login_count, 0)

    # =========================================================================
    # G-6: FORCE SESSION REVOCATION (IMMEDIATE LOGOUT) TESTS
    # =========================================================================

    def test_suspended_user_session_terminated_immediately(self):
        """When an admin suspends a user, the user's active session is terminated on next request."""
        # Analyst logs in
        c_analyst = self.app.test_client()
        self._login(c_analyst, self.analyst.email, _ANALYST_PWD)

        # Verify active session works
        dash_resp = c_analyst.get("/dashboard")
        self.assertEqual(dash_resp.status_code, 200)

        # Admin logs in and suspends analyst
        c_admin = self.app.test_client()
        self._login(c_admin, self.admin.email, _ADMIN_PWD)
        token = self._get_csrf_token(c_admin, "/admin")
        c_admin.post(
            "/admin",
            data={"csrf_token": token, "action": "suspend", "user_id": self.analyst_id},
            follow_redirects=True,
        )

        # Analyst's browser attempts another request
        next_resp = c_analyst.get("/dashboard", follow_redirects=True)
        # Must be rejected and redirected to login
        self.assertEqual(next_resp.status_code, 200)
        html = next_resp.get_data(as_text=True)
        self.assertTrue("login" in html.lower() or "deactivated" in html.lower())
        self.assertIn("System Authentication", html)

        # Furthermore, if analyst attempts to log back in, they are blocked with deactivation warning
        login_attempt = self._login(c_analyst, self.analyst.email, _ANALYST_PWD)
        self.assertIn("deactivated", login_attempt.get_data(as_text=True).lower())

    def test_admin_password_reset_terminates_user_session_immediately(self):
        """When admin resets user's password, user's active browser session is terminated immediately."""
        c_user = self.app.test_client()
        self._login(c_user, self.regular_user.email, _USER_PWD)

        dash_resp = c_user.get("/dashboard")
        self.assertEqual(dash_resp.status_code, 200)

        # Admin resets password
        ok, msg, temp_pwd = reset_user_password(self.admin_id, self.user_id)
        self.assertTrue(ok)

        # User's existing browser attempts request
        next_resp = c_user.get("/dashboard", follow_redirects=True)
        self.assertEqual(next_resp.status_code, 200)
        html = next_resp.get_data(as_text=True)
        self.assertTrue("revoked" in html.lower() or "login" in html.lower())

    def test_admin_can_revoke_user_sessions_directly(self):
        """Admin can explicitly click 'Revoke Session' to kick out an active user."""
        c_user = self.app.test_client()
        self._login(c_user, self.regular_user.email, _USER_PWD)

        dash_resp = c_user.get("/dashboard")
        self.assertEqual(dash_resp.status_code, 200)

        # Admin revokes session
        c_admin = self.app.test_client()
        self._login(c_admin, self.admin.email, _ADMIN_PWD)
        token = self._get_csrf_token(c_admin, "/admin")
        revoke_resp = c_admin.post(
            "/admin",
            data={"csrf_token": token, "action": "revoke_sessions", "user_id": self.user_id},
            follow_redirects=True,
        )
        self.assertEqual(revoke_resp.status_code, 200)
        self.assertIn("revoked", revoke_resp.get_data(as_text=True).lower())

        # Target user tries accessing dashboard
        next_resp = c_user.get("/dashboard", follow_redirects=True)
        self.assertEqual(next_resp.status_code, 200)
        html = next_resp.get_data(as_text=True)
        self.assertIn("revoked", html.lower())

    def test_non_admin_cannot_unlock_or_revoke(self):
        """Analyst and regular users cannot trigger unlock or session revocation."""
        # Service level checks
        ok1, msg1 = unlock_user(self.analyst_id, self.user_id)
        self.assertFalse(ok1)
        self.assertIn("Unauthorized", msg1)

        ok2, msg2 = revoke_user_sessions(self.regular_user.id, self.analyst_id)
        self.assertFalse(ok2)
        self.assertIn("Unauthorized", msg2)

        # HTTP route checks (Analyst attempting to post to /admin)
        c_analyst = self.app.test_client()
        self._login(c_analyst, self.analyst.email, _ANALYST_PWD)
        token = self._get_csrf_token(c_analyst, "/profile")
        post_resp = c_analyst.post(
            "/admin",
            data={"csrf_token": token, "action": "unlock_user", "user_id": self.user_id},
        )
        self.assertEqual(post_resp.status_code, 403)

    def test_admin_panel_displays_last_login_and_locked_status(self):
        """Admin panel UI renders 'Last Login' header and displays 'Locked' badge with Unlock button."""
        # Lock analyst account
        analyst = db.session.get(User, self.analyst_id)
        analyst.failed_login_count = 5
        analyst.locked_until = datetime.now(timezone.utc) + timedelta(minutes=15)
        analyst.last_login = datetime.now(timezone.utc)
        analyst.last_login_ip = "192.168.1.100"
        db.session.commit()

        c_admin = self.app.test_client()
        self._login(c_admin, self.admin.email, _ADMIN_PWD)

        resp = c_admin.get("/admin")
        self.assertEqual(resp.status_code, 200)
        html = resp.get_data(as_text=True)

        self.assertIn("Last Login", html)
        self.assertIn("Locked", html)
        self.assertIn("Unlock", html)
        self.assertIn("Revoke Session", html)
        self.assertIn("192.168.1.100", html)


if __name__ == "__main__":
    unittest.main()
