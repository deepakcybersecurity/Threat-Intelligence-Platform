"""
Tests for Admin UI & Compliance Tools Remediation: G-5, G-7, G-8, G-10
======================================================================
Covers:
1. G-5: Audit Log Search, Filter & Pagination (Web UI)
   - Search by free-text keyword (action, target table, IP address, username)
   - Filter by user ID, action, target table, date range (from / to)
   - Pagination calculation (items per page, total pages, page boundaries, prev/next)
2. G-7: Audit Log CSV Export
   - Admin 1-click CSV download endpoint (/admin/audit-logs/export-csv and /admin/export-audit-csv)
   - RFC 4180 compliance, Content-Type text/csv, attachment filename
   - Respects active search and filter parameters
   - Non-admin (analyst / user / anon) denied access (403 Forbidden / Login redirect)
   - Audit trail records the export event itself
3. G-8: Analyst Activity & SOC Performance Metrics Dashboard
   - Aggregates per-analyst indicators created, reports published, malware cataloged, alerts resolved
   - Computes top contributor and platform summary KPIs
   - Admin panel GET renders analyst metric cards and performance breakdown table
4. G-10: Bulk User Actions
   - Bulk suspend: deactivates accounts, revokes sessions, skips actor self, logs audit
   - Bulk activate: re-activates accounts, clears lockout status, logs audit
   - Bulk role update: changes roles, preserves last admin safeguard, logs audit
   - Bulk session revocation: rotates session tokens across selected users, logs audit
   - Non-admin blocked (403 Forbidden)
   - CSRF protection enforcement
"""

import csv
import io
import re
import unittest
from datetime import datetime, timedelta
from flask import g
from werkzeug.security import generate_password_hash

from app import create_app, db, limiter
from app.models import (
    User,
    AuditLog,
    ThreatIndicator,
    ThreatReport,
    Malware,
    Alert,
)
from app.services.admin_service import (
    get_analyst_activity_metrics,
    bulk_suspend_users,
    bulk_activate_users,
    bulk_update_user_roles,
    bulk_revoke_user_sessions,
)
from app.services.audit_service import (
    filter_audit_logs,
    export_audit_logs_csv_data,
)

_TEST_PREFIX = "comp_test_"
_ADMIN_PWD = "AdminSecure2026!#"
_ANALYST1_PWD = "AnalystOne2026!#"
_ANALYST2_PWD = "AnalystTwo2026!#"
_USER1_PWD = "UserOneSecure2026!#"
_USER2_PWD = "UserTwoSecure2026!#"


class TestAdminComplianceTools(unittest.TestCase):

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
        self.ctx.pop()

    def _cleanup(self):
        """Clean up test fixtures prefixed with _TEST_PREFIX."""
        db.session.rollback()
        test_users = User.query.filter(User.username.like(f"{_TEST_PREFIX}%")).all()
        user_ids = [u.id for u in test_users]
        if user_ids:
            # Delete dependent entities
            Alert.query.filter(Alert.user_id.in_(user_ids)).delete(synchronize_session=False)
            ThreatReport.query.filter(ThreatReport.user_id.in_(user_ids)).delete(synchronize_session=False)
            Malware.query.filter(Malware.created_by_user_id.in_(user_ids)).delete(synchronize_session=False)
            ThreatIndicator.query.filter(ThreatIndicator.added_by_user_id.in_(user_ids)).delete(synchronize_session=False)
            AuditLog.query.filter(
                (AuditLog.user_id.in_(user_ids)) | (AuditLog.target_id.in_(user_ids))
            ).delete(synchronize_session=False)
            for u in test_users:
                db.session.delete(u)
            db.session.commit()

        # Delete any remaining audit logs with _TEST_PREFIX in action
        AuditLog.query.filter(AuditLog.action.like(f"%{_TEST_PREFIX}%")).delete(synchronize_session=False)
        db.session.commit()

    def _seed(self):
        """Seed test admin, 2 analysts, and 2 regular users along with sample audit logs and metrics."""
        self.admin = User(
            username=f"{_TEST_PREFIX}admin",
            email=f"{_TEST_PREFIX}admin@test.com",
            password_hash=generate_password_hash(_ADMIN_PWD),
            role="admin",
            is_active=True,
        )
        self.analyst1 = User(
            username=f"{_TEST_PREFIX}analyst1",
            email=f"{_TEST_PREFIX}analyst1@test.com",
            password_hash=generate_password_hash(_ANALYST1_PWD),
            role="analyst",
            is_active=True,
        )
        self.analyst2 = User(
            username=f"{_TEST_PREFIX}analyst2",
            email=f"{_TEST_PREFIX}analyst2@test.com",
            password_hash=generate_password_hash(_ANALYST2_PWD),
            role="analyst",
            is_active=True,
        )
        self.user1 = User(
            username=f"{_TEST_PREFIX}user1",
            email=f"{_TEST_PREFIX}user1@test.com",
            password_hash=generate_password_hash(_USER1_PWD),
            role="user",
            is_active=True,
        )
        self.user2 = User(
            username=f"{_TEST_PREFIX}user2",
            email=f"{_TEST_PREFIX}user2@test.com",
            password_hash=generate_password_hash(_USER2_PWD),
            role="user",
            is_active=True,
        )
        db.session.add_all([self.admin, self.analyst1, self.analyst2, self.user1, self.user2])
        db.session.commit()

        self.admin_id = self.admin.id
        self.analyst1_id = self.analyst1.id
        self.analyst2_id = self.analyst2.id
        self.user1_id = self.user1.id
        self.user2_id = self.user2.id

        # Seed Threat Indicators
        ioc1 = ThreatIndicator(
            indicator_value=f"198.51.100.{self.analyst1_id}",
            indicator_type="ip",
            confidence_score=85,
            severity="High",
            status="Active",
            source="SOC Ingest",
            added_by_user_id=self.analyst1_id,
        )
        ioc2 = ThreatIndicator(
            indicator_value=f"203.0.113.{self.analyst1_id}",
            indicator_type="ip",
            confidence_score=90,
            severity="Critical",
            status="Active",
            source="Firewall Log",
            added_by_user_id=self.analyst1_id,
        )
        ioc3 = ThreatIndicator(
            indicator_value=f"malicious-domain-{self.analyst2_id}.org",
            indicator_type="domain",
            confidence_score=75,
            severity="Medium",
            status="Active",
            source="DNS Sinkhole",
            added_by_user_id=self.analyst2_id,
        )
        db.session.add_all([ioc1, ioc2, ioc3])

        # Seed Threat Report
        rep1 = ThreatReport(
            user_id=self.analyst1_id,
            title=f"{_TEST_PREFIX} Ransomware Campaign Advisory",
            description="Detailed operational analysis of active ransomware vector.",
            category="Ransomware",
            severity="High",
            status="Open",
            tlp_level="AMBER",
            target_sector="Financial",
        )
        db.session.add(rep1)

        # Seed Malware
        mal1 = Malware(
            malware_name=f"{_TEST_PREFIX}BlackCat Variant",
            malware_type="Ransomware",
            platform="Windows",
            severity="Critical",
            created_by_user_id=self.analyst1_id,
        )
        db.session.add(mal1)

        # Seed Alerts
        alt1 = Alert(
            title=f"{_TEST_PREFIX} Alert 1",
            severity="High",
            status="Resolved",
            user_id=self.analyst1_id,
        )
        alt2 = Alert(
            title=f"{_TEST_PREFIX} Alert 2",
            severity="Medium",
            status="Open",
            user_id=self.analyst2_id,
        )
        db.session.add_all([alt1, alt2])

        # Seed Audit Logs
        now = datetime.utcnow()
        log1 = AuditLog(
            user_id=self.admin_id,
            action=f"{_TEST_PREFIX}update_role:analyst->admin",
            target_table="users",
            target_id=self.analyst1_id,
            ip_address="192.168.10.1",
            created_at=now - timedelta(days=2),
        )
        log2 = AuditLog(
            user_id=self.analyst1_id,
            action=f"{_TEST_PREFIX}create_ioc:198.51.100.10",
            target_table="threat_indicators",
            target_id=101,
            ip_address="192.168.10.2",
            created_at=now - timedelta(days=1),
        )
        log3 = AuditLog(
            user_id=self.analyst2_id,
            action=f"{_TEST_PREFIX}resolve_alert:42",
            target_table="alerts",
            target_id=42,
            ip_address="192.168.10.3",
            created_at=now,
        )
        db.session.add_all([log1, log2, log3])
        db.session.commit()

    def _get_csrf_token(self, client, url="/admin"):
        """Extract valid CSRF token from page."""
        resp = client.get(url)
        match = re.search(r'name="csrf_token"\s+value="([^"]+)"', resp.get_data(as_text=True))
        if match:
            return match.group(1)
        match_meta = re.search(r'name="csrf-token"\s+content="([^"]+)"', resp.get_data(as_text=True))
        if match_meta:
            return match_meta.group(1)
        return ""

    def _login(self, client, email, password):
        """Helper to log in a user and return the POST response."""
        g.pop("_login_user", None)
        token = self._get_csrf_token(client, "/login")
        return client.post(
            "/login",
            data={"email": email, "password": password, "csrf_token": token},
            follow_redirects=True,
        )

    # ═════════════════════════════════════════════════════════════════════════
    # G-5: Audit Log Search, Filter & Pagination Tests
    # ═════════════════════════════════════════════════════════════════════════

    def test_g5_audit_log_search_by_keyword(self):
        """Audit logs can be searched by keyword matching action, table, IP, or username."""
        # Search by action substring
        res = filter_audit_logs(q=f"{_TEST_PREFIX}update_role")
        self.assertGreaterEqual(res["total_count"], 1)
        self.assertTrue(any(_TEST_PREFIX in item.action for item in res["items"]))

        # Search by username
        res_user = filter_audit_logs(q=f"{_TEST_PREFIX}analyst1")
        self.assertGreaterEqual(res_user["total_count"], 1)
        self.assertTrue(all(item.user.username == f"{_TEST_PREFIX}analyst1" for item in res_user["items"]))

        # Search by IP
        res_ip = filter_audit_logs(q="192.168.10.3")
        self.assertGreaterEqual(res_ip["total_count"], 1)
        self.assertEqual(res_ip["items"][0].ip_address, "192.168.10.3")

    def test_g5_audit_log_filter_by_user_table_and_action(self):
        """Audit logs can be filtered specifically by user_id, target_table, and action."""
        # Filter by user_id
        res_uid = filter_audit_logs(user_id=self.analyst1_id)
        self.assertGreaterEqual(res_uid["total_count"], 1)
        for item in res_uid["items"]:
            self.assertEqual(item.user_id, self.analyst1_id)

        # Filter by target_table
        res_table = filter_audit_logs(target_table="threat_indicators")
        self.assertGreaterEqual(res_table["total_count"], 1)
        for item in res_table["items"]:
            self.assertEqual(item.target_table, "threat_indicators")

        # Filter by action substring
        res_act = filter_audit_logs(action="resolve_alert")
        self.assertGreaterEqual(res_act["total_count"], 1)
        for item in res_act["items"]:
            self.assertIn("resolve_alert", item.action)

    def test_g5_audit_log_date_range_filtering(self):
        """Audit logs can be filtered by date_from and date_to boundaries."""
        now = datetime.utcnow()
        yesterday_str = (now - timedelta(days=1)).strftime("%Y-%m-%d")
        today_str = now.strftime("%Y-%m-%d")

        # Filter for today only
        res_today = filter_audit_logs(date_from=today_str, date_to=today_str)
        self.assertGreaterEqual(res_today["total_count"], 1)
        for item in res_today["items"]:
            self.assertEqual(item.created_at.strftime("%Y-%m-%d"), today_str)

        # Filter from yesterday to today
        res_range = filter_audit_logs(date_from=yesterday_str, date_to=today_str)
        self.assertGreaterEqual(res_range["total_count"], 2)

    def test_g5_audit_log_pagination(self):
        """Audit logs pagination correctly splits items across pages."""
        # Add 10 additional logs for pagination test
        for i in range(10):
            db.session.add(AuditLog(
                user_id=self.admin_id,
                action=f"{_TEST_PREFIX}pagination_test_{i}",
                target_table="users",
                ip_address=f"10.0.0.{i}",
            ))
        db.session.commit()

        # Page 1 with per_page=5
        page1 = filter_audit_logs(q=f"{_TEST_PREFIX}pagination_test", page=1, per_page=5)
        self.assertEqual(len(page1["items"]), 5)
        self.assertEqual(page1["page"], 1)
        self.assertEqual(page1["total_count"], 10)
        self.assertEqual(page1["total_pages"], 2)
        self.assertTrue(page1["has_next"])
        self.assertFalse(page1["has_prev"])

        # Page 2
        page2 = filter_audit_logs(q=f"{_TEST_PREFIX}pagination_test", page=2, per_page=5)
        self.assertEqual(len(page2["items"]), 5)
        self.assertEqual(page2["page"], 2)
        self.assertFalse(page2["has_next"])
        self.assertTrue(page2["has_prev"])

    # ═════════════════════════════════════════════════════════════════════════
    # G-7: Audit Log CSV Export Tests
    # ═════════════════════════════════════════════════════════════════════════

    def test_g7_admin_can_export_audit_logs_csv(self):
        """Admin can download audit trail logs as RFC 4180 CSV attachment."""
        c = self.app.test_client()
        self._login(c, self.admin.email, _ADMIN_PWD)

        resp = c.get("/admin/audit-logs/export-csv")
        self.assertEqual(resp.status_code, 200)
        self.assertTrue(resp.content_type.startswith("text/csv"))
        self.assertIn("attachment", resp.headers.get("Content-Disposition", ""))
        self.assertIn(".csv", resp.headers.get("Content-Disposition", ""))

        # Parse CSV content
        csv_text = resp.get_data(as_text=True)
        reader = csv.reader(io.StringIO(csv_text))
        rows = list(reader)
        self.assertGreaterEqual(len(rows), 4)  # 1 header + at least 3 logs

        # Verify header structure
        header = rows[0]
        self.assertEqual(header, [
            "Timestamp (UTC)",
            "Log ID",
            "Actor User ID",
            "Actor Username",
            "Action Verb",
            "Target Table",
            "Target ID",
            "Client IP Address",
        ])

        # Verify export audit event was recorded in AuditLog
        export_log = AuditLog.query.filter_by(
            user_id=self.admin_id,
            action="export_audit_logs_csv",
        ).first()
        self.assertIsNotNone(export_log)

    def test_g7_audit_log_csv_respects_active_filters(self):
        """CSV export endpoint adheres to query filters (e.g. target_table, user_id)."""
        c = self.app.test_client()
        self._login(c, self.admin.email, _ADMIN_PWD)

        resp = c.get(f"/admin/audit-logs/export-csv?target_table=threat_indicators")
        self.assertEqual(resp.status_code, 200)

        reader = csv.reader(io.StringIO(resp.get_data(as_text=True)))
        rows = list(reader)
        self.assertGreaterEqual(len(rows), 2)  # Header + at least 1 record
        for row in rows[1:]:
            # Target Table is column index 5
            self.assertEqual(row[5], "threat_indicators")

    def test_g7_non_admin_forbidden_from_exporting_csv(self):
        """Analyst and regular users cannot export compliance audit CSV (403 Forbidden)."""
        c_analyst = self.app.test_client()
        self._login(c_analyst, self.analyst1.email, _ANALYST1_PWD)

        resp_analyst = c_analyst.get("/admin/audit-logs/export-csv")
        self.assertEqual(resp_analyst.status_code, 403)

        c_anon = self.app.test_client()
        resp_anon = c_anon.get("/admin/audit-logs/export-csv")
        self.assertEqual(resp_anon.status_code, 302)
        self.assertIn("/login", resp_anon.headers.get("Location", ""))

    # ═════════════════════════════════════════════════════════════════════════
    # G-8: Analyst Activity & Performance Metrics Tests
    # ═════════════════════════════════════════════════════════════════════════

    def test_g8_analyst_activity_metrics_calculation(self):
        """get_analyst_activity_metrics correctly calculates output per analyst."""
        metrics = get_analyst_activity_metrics()
        self.assertIn("users", metrics)
        self.assertIn("summary", metrics)

        # Summary KPIs
        self.assertGreaterEqual(metrics["summary"]["total_indicators"], 3)
        self.assertGreaterEqual(metrics["summary"]["total_reports"], 1)
        self.assertGreaterEqual(metrics["summary"]["total_malware"], 1)
        self.assertGreaterEqual(metrics["summary"]["total_alerts_resolved"], 1)

        # Verify Analyst 1 metrics
        a1_metric = next((m for m in metrics["users"] if m["user_id"] == self.analyst1_id), None)
        self.assertIsNotNone(a1_metric)
        self.assertEqual(a1_metric["indicators_count"], 2)
        self.assertEqual(a1_metric["reports_count"], 1)
        self.assertEqual(a1_metric["malware_count"], 1)
        self.assertEqual(a1_metric["alerts_count"], 1)
        self.assertEqual(a1_metric["total_contributions"], 5)  # 2 + 1 + 1 + 1

        # Verify top contributor is computed
        top = metrics["summary"]["top_contributor"]
        self.assertIsNotNone(top)
        self.assertIn("user_id", top)
        self.assertIn("username", top)
        self.assertGreaterEqual(top["total_contributions"], a1_metric["total_contributions"])

    def test_g8_admin_panel_renders_analyst_metrics_dashboard(self):
        """Admin panel GET renders analyst metric cards and performance table."""
        c = self.app.test_client()
        self._login(c, self.admin.email, _ADMIN_PWD)

        resp = c.get("/admin")
        self.assertEqual(resp.status_code, 200)
        html = resp.get_data(as_text=True)

        self.assertIn("Analyst Activity &amp; SOC Contribution Metrics", html)
        self.assertIn("Total IOCs Ingested", html)
        self.assertIn("Threat Reports Published", html)
        self.assertIn("Malware Cataloged", html)
        self.assertIn("Top Contributor:", html)
        self.assertIn(self.analyst1.username, html)

    # ═════════════════════════════════════════════════════════════════════════
    # G-10: Bulk User Actions Tests
    # ═════════════════════════════════════════════════════════════════════════

    def test_g10_bulk_suspend_users(self):
        """Admin can bulk suspend selected users while self-account is protected."""
        c = self.app.test_client()
        self._login(c, self.admin.email, _ADMIN_PWD)
        token = self._get_csrf_token(c, "/admin")

        resp = c.post(
            "/admin",
            data={
                "csrf_token": token,
                "action": "bulk_action",
                "bulk_type": "bulk_suspend",
                "selected_user_ids": [self.user1_id, self.user2_id, self.admin_id],
            },
            follow_redirects=True,
        )
        self.assertEqual(resp.status_code, 200)
        html = resp.get_data(as_text=True)
        self.assertIn("Successfully suspended 2 user(s)", html)
        self.assertIn("Your own account was skipped", html)

        # Verify DB state
        u1 = db.session.get(User, self.user1_id)
        u2 = db.session.get(User, self.user2_id)
        admin = db.session.get(User, self.admin_id)
        self.assertFalse(u1.is_active)
        self.assertFalse(u2.is_active)
        self.assertTrue(admin.is_active)

        # Verify audit logs
        log_u1 = AuditLog.query.filter_by(
            user_id=self.admin_id,
            action=f"bulk_suspend_user:{u1.username}",
        ).first()
        self.assertIsNotNone(log_u1)

    def test_g10_bulk_activate_users(self):
        """Admin can bulk activate suspended accounts and clear any lockout states."""
        # Pre-condition: suspend user1 and user2 and set locked_until
        u1 = db.session.get(User, self.user1_id)
        u2 = db.session.get(User, self.user2_id)
        u1.is_active = False
        u1.failed_login_count = 5
        u1.locked_until = datetime.utcnow() + timedelta(minutes=15)
        u2.is_active = False
        db.session.commit()

        c = self.app.test_client()
        self._login(c, self.admin.email, _ADMIN_PWD)
        token = self._get_csrf_token(c, "/admin")

        resp = c.post(
            "/admin",
            data={
                "csrf_token": token,
                "action": "bulk_action",
                "bulk_type": "bulk_activate",
                "selected_user_ids": [self.user1_id, self.user2_id],
            },
            follow_redirects=True,
        )
        self.assertEqual(resp.status_code, 200)
        self.assertIn("Successfully activated 2 user(s)", resp.get_data(as_text=True))

        # Refresh
        db.session.refresh(u1)
        db.session.refresh(u2)
        self.assertTrue(u1.is_active)
        self.assertTrue(u2.is_active)
        self.assertEqual(u1.failed_login_count, 0)
        self.assertIsNone(u1.locked_until)

    def test_g10_bulk_update_user_roles_with_last_admin_safeguard(self):
        """Admin can bulk change user roles; prevents demoting all administrators."""
        c = self.app.test_client()
        self._login(c, self.admin.email, _ADMIN_PWD)
        token = self._get_csrf_token(c, "/admin")

        # Promote user1 and user2 to analyst
        resp = c.post(
            "/admin",
            data={
                "csrf_token": token,
                "action": "bulk_action",
                "bulk_type": "bulk_change_role",
                "bulk_role": "analyst",
                "selected_user_ids": [self.user1_id, self.user2_id],
            },
            follow_redirects=True,
        )
        self.assertEqual(resp.status_code, 200)
        self.assertIn("Updated 2 user(s) to role &#39;analyst&#39;", resp.get_data(as_text=True))

        u1 = db.session.get(User, self.user1_id)
        u2 = db.session.get(User, self.user2_id)
        self.assertEqual(u1.role, "analyst")
        self.assertEqual(u2.role, "analyst")

        # Attempt to demote all admins to user -> must be rejected by last-admin safeguard
        all_admin_ids = [u.id for u in User.query.filter_by(role="admin").all()]
        resp_demote = c.post(
            "/admin",
            data={
                "csrf_token": self._get_csrf_token(c, "/admin"),
                "action": "bulk_action",
                "bulk_type": "bulk_change_role",
                "bulk_role": "user",
                "selected_user_ids": all_admin_ids,
            },
            follow_redirects=True,
        )
        self.assertEqual(resp_demote.status_code, 200)
        self.assertIn("Cannot demote all administrators", resp_demote.get_data(as_text=True))
        admin = db.session.get(User, self.admin_id)
        self.assertEqual(admin.role, "admin")

    def test_g10_bulk_revoke_user_sessions(self):
        """Admin can bulk revoke active sessions by rotating session tokens."""
        u1 = db.session.get(User, self.user1_id)
        u2 = db.session.get(User, self.user2_id)
        old_tok1 = u1.session_token = "old_token_1111111111111111111111"
        old_tok2 = u2.session_token = "old_token_2222222222222222222222"
        db.session.commit()

        c = self.app.test_client()
        self._login(c, self.admin.email, _ADMIN_PWD)
        token = self._get_csrf_token(c, "/admin")

        resp = c.post(
            "/admin",
            data={
                "csrf_token": token,
                "action": "bulk_action",
                "bulk_type": "bulk_revoke_sessions",
                "selected_user_ids": [self.user1_id, self.user2_id],
            },
            follow_redirects=True,
        )
        self.assertEqual(resp.status_code, 200)
        self.assertIn("Revoked active sessions for 2 user(s)", resp.get_data(as_text=True))

        db.session.refresh(u1)
        db.session.refresh(u2)
        self.assertNotEqual(u1.session_token, old_tok1)
        self.assertNotEqual(u2.session_token, old_tok2)

    def test_g10_non_admin_cannot_execute_bulk_actions(self):
        """Non-admin users cannot trigger bulk actions (403 Forbidden)."""
        c_analyst = self.app.test_client()
        self._login(c_analyst, self.analyst1.email, _ANALYST1_PWD)
        token = self._get_csrf_token(c_analyst, "/profile")

        resp = c_analyst.post(
            "/admin",
            data={
                "csrf_token": token,
                "action": "bulk_action",
                "bulk_type": "bulk_suspend",
                "selected_user_ids": [self.user1_id],
            },
        )
        self.assertEqual(resp.status_code, 403)


if __name__ == "__main__":
    unittest.main()
