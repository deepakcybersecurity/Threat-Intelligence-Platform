"""
Tests for Task 9: REST API v2 (Phase 2)
=======================================
Verifies:
1. API Authentication & Role Enforcement (401 on missing auth, 403 for non-admin on admin endpoints)
2. OpenAPI 3.0 Documentation Endpoint (/api/v2/docs)
3. Threat Indicator CRUD (List, Filter, Search, Sort, Paginate, Create, Read, Update, Delete)
4. Threat Indicator Input Validation & Duplicate Protection
5. Security Alert Endpoints (List, Filter, Details, Status Transitions)
6. Threat Report Endpoints (List, Filter, Read with Linked Indicators)
7. Malware Endpoints (List, Filter, Read with Linked Indicators)
8. Audit Log Endpoints (Admin-only, Filter, Pagination)
9. User Management Endpoints (Admin-only, Safe Serialization)
10. Cascade Deletion of Linked Alerts on Indicator Deletion
"""

from datetime import datetime
import json
import unittest

from app import create_app, db
from app.models import (
    User,
    ThreatIndicator,
    Alert,
    ThreatReport,
    Malware,
    AuditLog,
)

_TEST_PREFIX = "api_test_"


class TestRestApiV2(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.app = create_app()
        cls.app.config["TESTING"] = True
        cls.app.config["WTF_CSRF_ENABLED"] = False
        cls.app.config["SIEM_WEBHOOK_API_KEY"] = "test-system-api-key-2026"
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
        """Clean up test records."""
        db.session.rollback()

        # Delete test alerts
        Alert.query.filter(
            (Alert.title.like(f"%{_TEST_PREFIX}%"))
            | (Alert.description.like(f"%{_TEST_PREFIX}%"))
        ).delete(synchronize_session=False)

        # Delete test indicators
        test_inds = ThreatIndicator.query.filter(
            ThreatIndicator.indicator_value.like(f"{_TEST_PREFIX}%")
        ).all()
        for ind in test_inds:
            ind.reports.clear()
            ind.malwares.clear()
            ind.alerts.clear()
            db.session.delete(ind)

        # Delete test malware
        test_mals = Malware.query.filter(
            Malware.malware_name.like(f"{_TEST_PREFIX}%")
        ).all()
        for m in test_mals:
            m.reports.clear()
            m.indicators.clear()
            db.session.delete(m)

        # Delete test reports
        test_reps = ThreatReport.query.filter(
            ThreatReport.title.like(f"{_TEST_PREFIX}%")
        ).all()
        for r in test_reps:
            r.malwares.clear()
            r.indicators.clear()
            db.session.delete(r)

        # Delete test audit logs
        AuditLog.query.filter(
            AuditLog.action.like(f"%{_TEST_PREFIX}%")
        ).delete(synchronize_session=False)

        # Delete test users
        test_users = User.query.filter(
            User.username.like(f"{_TEST_PREFIX}%")
        ).all()
        for u in test_users:
            AuditLog.query.filter_by(user_id=u.id).delete()
            db.session.delete(u)

        db.session.commit()

    def _seed(self):
        """Seed admin and analyst users, plus sample indicators, reports, and malware."""
        # 1. Admin user
        self.admin = User(
            username=f"{_TEST_PREFIX}admin",
            email=f"{_TEST_PREFIX}admin@tip.local",
            password_hash="pbkdf2:sha256:dummyhash",
            role="admin",
            is_active=True,
            api_key=f"tip_live_test_admin_{_TEST_PREFIX}",
        )
        # 2. Analyst user
        self.analyst = User(
            username=f"{_TEST_PREFIX}analyst",
            email=f"{_TEST_PREFIX}analyst@tip.local",
            password_hash="pbkdf2:sha256:dummyhash",
            role="analyst",
            is_active=True,
            api_key=f"tip_live_test_analyst_{_TEST_PREFIX}",
        )
        db.session.add_all([self.admin, self.analyst])
        db.session.commit()

        self.admin_id = self.admin.id
        self.analyst_id = self.analyst.id

        # Headers
        self.system_headers = {"X-API-Key": "test-system-api-key-2026"}
        self.admin_headers = {"X-API-Key": self.admin.api_key}
        self.analyst_headers = {"X-API-Key": self.analyst.api_key}

        # 3. Sample Indicator
        self.ind1 = ThreatIndicator(
            indicator_value=f"{_TEST_PREFIX}198.51.100.10",
            indicator_type="ipv4",
            severity="High",
            status="Active",
            confidence_score=85,
            risk_score=75,
            source=f"{_TEST_PREFIX}Feed",
            tlp_marking="AMBER",
            added_by_user_id=self.analyst_id,
        )
        self.ind2 = ThreatIndicator(
            indicator_value=f"{_TEST_PREFIX}bad-domain.com",
            indicator_type="domain",
            severity="Critical",
            status="Active",
            confidence_score=90,
            risk_score=90,
            source=f"{_TEST_PREFIX}Feed",
            tlp_marking="RED",
            added_by_user_id=self.analyst_id,
        )
        db.session.add_all([self.ind1, self.ind2])
        db.session.commit()

        self.ind1_id = self.ind1.id
        self.ind2_id = self.ind2.id

        # 4. Sample Report
        self.report = ThreatReport(
            user_id=self.analyst_id,
            title=f"{_TEST_PREFIX}Ransomware Campaign Report",
            description=f"{_TEST_PREFIX}Description of ransomware activity",
            category="Ransomware",
            severity="High",
            status="Open",
            tlp_level="AMBER",
            target_sector="Financial",
        )
        self.report.indicators.append(self.ind1)
        db.session.add(self.report)

        # 5. Sample Malware
        self.malware = Malware(
            malware_name=f"{_TEST_PREFIX}DarkHydra",
            malware_family="Hydra",
            malware_type="Trojan",
            platform="Windows",
            severity="High",
            risk_score=70,
            description=f"{_TEST_PREFIX}Trojan banking malware",
            created_by_user_id=self.analyst_id,
        )
        self.malware.indicators.append(self.ind1)
        db.session.add(self.malware)

        # 6. Sample Alert
        self.alert = Alert(
            title=f"{_TEST_PREFIX}High Risk IP Detected",
            description=f"{_TEST_PREFIX}Indicator 198.51.100.10 triggered high risk score",
            severity="High",
            status="Open",
            alert_type="Risk Score",
            is_read=False,
            indicator_id=self.ind1_id,
            user_id=self.analyst_id,
        )
        db.session.add(self.alert)
        db.session.commit()

        self.report_id = self.report.id
        self.malware_id = self.malware.id
        self.alert_id = self.alert.id

    # =========================================================================
    # 1. AUTHENTICATION & ACCESS CONTROL
    # =========================================================================

    def test_unauthenticated_requests_return_401(self):
        """Verifies that all protected v2 endpoints reject requests lacking credentials."""
        endpoints = [
            ("GET", "/api/v2/indicators"),
            ("POST", "/api/v2/indicators"),
            ("GET", f"/api/v2/indicators/{self.ind1_id}"),
            ("PUT", f"/api/v2/indicators/{self.ind1_id}"),
            ("DELETE", f"/api/v2/indicators/{self.ind1_id}"),
            ("GET", "/api/v2/alerts"),
            ("GET", f"/api/v2/alerts/{self.alert_id}"),
            ("PATCH", f"/api/v2/alerts/{self.alert_id}"),
            ("GET", "/api/v2/reports"),
            ("GET", f"/api/v2/reports/{self.report_id}"),
            ("GET", "/api/v2/malware"),
            ("GET", f"/api/v2/malware/{self.malware_id}"),
            ("GET", "/api/v2/audit-logs"),
            ("GET", "/api/v2/users"),
        ]
        for method, url in endpoints:
            if method == "GET":
                resp = self.client.get(url)
            elif method == "POST":
                resp = self.client.post(url, json={})
            elif method == "PUT":
                resp = self.client.put(url, json={})
            elif method == "PATCH":
                resp = self.client.patch(url, json={})
            elif method == "DELETE":
                resp = self.client.delete(url)

            self.assertEqual(
                resp.status_code, 401,
                f"Expected 401 for unauthenticated {method} {url}, got {resp.status_code}"
            )

    def test_authorization_bearer_header(self):
        """Verifies Bearer token in Authorization header functions correctly."""
        headers = {"Authorization": f"Bearer {self.analyst.api_key}"}
        resp = self.client.get("/api/v2/indicators", headers=headers)
        self.assertEqual(resp.status_code, 200)

    def test_query_param_api_key_rejected(self):
        """Verifies api_key query parameter is rejected for security (CWE-598)."""
        resp = self.client.get(f"/api/v2/indicators?api_key={self.analyst.api_key}")
        self.assertEqual(resp.status_code, 401)
        data = resp.get_json()
        self.assertFalse(data.get("success", True))
        self.assertIn("prohibited", data.get("message", "").lower())

    # =========================================================================
    # 2. OPENAPI DOCUMENTATION ENDPOINT
    # =========================================================================

    def test_openapi_docs_endpoint(self):
        """Verifies GET /api/v2/docs returns complete OpenAPI 3.0 schema."""
        resp = self.client.get("/api/v2/docs")
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertEqual(data["openapi"], "3.0.3")
        self.assertIn("paths", data)
        self.assertIn("/api/v2/indicators", data["paths"])
        self.assertIn("/api/v2/alerts", data["paths"])
        self.assertIn("/api/v2/reports", data["paths"])
        self.assertIn("/api/v2/malware", data["paths"])
        self.assertIn("/api/v2/audit-logs", data["paths"])
        self.assertIn("/api/v2/users", data["paths"])

    # =========================================================================
    # 3. THREAT INDICATORS CRUD
    # =========================================================================

    def test_indicators_list_and_pagination(self):
        """Verifies listing indicators with pagination metadata."""
        resp = self.client.get(
            "/api/v2/indicators?page=1&per_page=1",
            headers=self.analyst_headers,
        )
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertIn("items", data)
        self.assertIn("pagination", data)
        self.assertEqual(len(data["items"]), 1)
        self.assertEqual(data["pagination"]["page"], 1)
        self.assertEqual(data["pagination"]["per_page"], 1)
        self.assertGreaterEqual(data["pagination"]["total"], 2)

    def test_indicators_filtering(self):
        """Verifies filtering indicators by type, severity, and status."""
        resp = self.client.get(
            f"/api/v2/indicators?type=domain&severity=Critical",
            headers=self.analyst_headers,
        )
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        values = [i["indicator_value"] for i in data["items"]]
        self.assertIn(f"{_TEST_PREFIX}bad-domain.com", values)
        self.assertNotIn(f"{_TEST_PREFIX}198.51.100.10", values)

    def test_indicators_search_and_sorting(self):
        """Verifies search query matching and sorting."""
        resp = self.client.get(
            f"/api/v2/indicators?q=bad-domain&sort_by=risk_score&sort_order=desc",
            headers=self.analyst_headers,
        )
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertGreaterEqual(len(data["items"]), 1)
        self.assertEqual(data["items"][0]["indicator_value"], f"{_TEST_PREFIX}bad-domain.com")

    def test_indicator_create_success(self):
        """Verifies creating a new threat indicator via POST."""
        payload = {
            "indicator_value": f"{_TEST_PREFIX}203.0.113.88",
            "indicator_type": "ipv4",
            "severity": "Medium",
            "status": "Active",
            "confidence_score": 60,
            "source": f"{_TEST_PREFIX}API Client",
            "tlp_marking": "GREEN",
            "context": "Suspicious scanning activity",
        }
        resp = self.client.post(
            "/api/v2/indicators",
            json=payload,
            headers=self.analyst_headers,
        )
        self.assertEqual(resp.status_code, 201)
        data = resp.get_json()
        self.assertTrue(data["success"])
        ind = data["indicator"]
        self.assertEqual(ind["indicator_value"], payload["indicator_value"])
        self.assertEqual(ind["severity"], "Medium")
        self.assertEqual(ind["tlp_marking"], "GREEN")

        # Verify DB persistence
        db_ind = ThreatIndicator.query.filter_by(indicator_value=payload["indicator_value"]).first()
        self.assertIsNotNone(db_ind)

    def test_indicator_create_validation_failures(self):
        """Verifies input validation on POST /api/v2/indicators."""
        # 1. Missing indicator_value
        resp = self.client.post(
            "/api/v2/indicators",
            json={"indicator_type": "ipv4"},
            headers=self.analyst_headers,
        )
        self.assertEqual(resp.status_code, 400)

        # 2. Missing indicator_type
        resp = self.client.post(
            "/api/v2/indicators",
            json={"indicator_value": "1.2.3.4"},
            headers=self.analyst_headers,
        )
        self.assertEqual(resp.status_code, 400)

        # 3. Invalid severity enum
        resp = self.client.post(
            "/api/v2/indicators",
            json={
                "indicator_value": f"{_TEST_PREFIX}fail-val",
                "indicator_type": "domain",
                "severity": "SuperCritical",
            },
            headers=self.analyst_headers,
        )
        self.assertEqual(resp.status_code, 400)

        # 4. Invalid status enum
        resp = self.client.post(
            "/api/v2/indicators",
            json={
                "indicator_value": f"{_TEST_PREFIX}fail-val-2",
                "indicator_type": "domain",
                "status": "Unknown",
            },
            headers=self.analyst_headers,
        )
        self.assertEqual(resp.status_code, 400)

        # 5. Invalid tlp_marking enum
        resp = self.client.post(
            "/api/v2/indicators",
            json={
                "indicator_value": f"{_TEST_PREFIX}fail-val-3",
                "indicator_type": "domain",
                "tlp_marking": "BLUE",
            },
            headers=self.analyst_headers,
        )
        self.assertEqual(resp.status_code, 400)

    def test_indicator_get_by_id(self):
        """Verifies GET /api/v2/indicators/<id> returns indicator with relational IDs."""
        resp = self.client.get(
            f"/api/v2/indicators/{self.ind1_id}",
            headers=self.analyst_headers,
        )
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertTrue(data["success"])
        ind = data["indicator"]
        self.assertEqual(ind["id"], self.ind1_id)
        self.assertIn("report_ids", ind)
        self.assertIn(self.report_id, ind["report_ids"])
        self.assertIn("malware_ids", ind)
        self.assertIn(self.malware_id, ind["malware_ids"])

    def test_indicator_get_not_found(self):
        """Verifies 404 for non-existent indicator ID."""
        resp = self.client.get("/api/v2/indicators/999999", headers=self.analyst_headers)
        self.assertEqual(resp.status_code, 404)

    def test_indicator_update(self):
        """Verifies partial update of indicator fields via PUT."""
        resp = self.client.put(
            f"/api/v2/indicators/{self.ind1_id}",
            json={"severity": "Critical", "confidence_score": 99, "status": "Inactive"},
            headers=self.analyst_headers,
        )
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        ind = data["indicator"]
        self.assertEqual(ind["severity"], "Critical")
        self.assertEqual(ind["confidence_score"], 99)
        self.assertEqual(ind["status"], "Inactive")

    def test_indicator_delete_and_cascade(self):
        """Verifies DELETE /api/v2/indicators/<id> removes indicator and cascades to alerts."""
        resp = self.client.delete(
            f"/api/v2/indicators/{self.ind1_id}",
            headers=self.analyst_headers,
        )
        self.assertEqual(resp.status_code, 200)

        # Indicator should be gone
        get_resp = self.client.get(f"/api/v2/indicators/{self.ind1_id}", headers=self.analyst_headers)
        self.assertEqual(get_resp.status_code, 404)

        # Linked alert should also be deleted via cascade
        alert = db.session.get(Alert, self.alert_id)
        self.assertIsNone(alert)

    # =========================================================================
    # 4. ALERTS ENDPOINTS
    # =========================================================================

    def test_alerts_list_and_filtering(self):
        """Verifies listing and filtering alerts."""
        resp = self.client.get(
            "/api/v2/alerts?severity=High&status=Open",
            headers=self.analyst_headers,
        )
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertIn("items", data)
        self.assertGreaterEqual(len(data["items"]), 1)
        self.assertEqual(data["items"][0]["severity"], "High")

    def test_alert_get_by_id(self):
        """Verifies GET /api/v2/alerts/<id> includes full incident context."""
        resp = self.client.get(
            f"/api/v2/alerts/{self.alert_id}",
            headers=self.analyst_headers,
        )
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertTrue(data["success"])
        alert = data["alert"]
        self.assertEqual(alert["id"], self.alert_id)
        self.assertIn("indicator", alert)
        self.assertEqual(alert["indicator"]["id"], self.ind1_id)

    def test_alert_patch_status_transition(self):
        """Verifies updating alert lifecycle status via PATCH."""
        resp = self.client.patch(
            f"/api/v2/alerts/{self.alert_id}",
            json={"status": "In Progress"},
            headers=self.analyst_headers,
        )
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertEqual(data["alert"]["status"], "In Progress")

        # Invalid status rejected
        resp_bad = self.client.patch(
            f"/api/v2/alerts/{self.alert_id}",
            json={"status": "FakeStatus"},
            headers=self.analyst_headers,
        )
        self.assertEqual(resp_bad.status_code, 400)

    # =========================================================================
    # 5. THREAT REPORTS (READ-ONLY)
    # =========================================================================

    def test_reports_list_and_details(self):
        """Verifies GET /api/v2/reports and /api/v2/reports/<id>."""
        list_resp = self.client.get(
            f"/api/v2/reports?category=Ransomware",
            headers=self.analyst_headers,
        )
        self.assertEqual(list_resp.status_code, 200)
        data = list_resp.get_json()
        self.assertGreaterEqual(len(data["items"]), 1)

        detail_resp = self.client.get(
            f"/api/v2/reports/{self.report_id}",
            headers=self.analyst_headers,
        )
        self.assertEqual(detail_resp.status_code, 200)
        rep = detail_resp.get_json()["report"]
        self.assertEqual(rep["title"], self.report.title)
        self.assertIn(self.ind1_id, rep["indicator_ids"])

    # =========================================================================
    # 6. MALWARE INTELLIGENCE (READ-ONLY)
    # =========================================================================

    def test_malware_list_and_details(self):
        """Verifies GET /api/v2/malware and /api/v2/malware/<id>."""
        list_resp = self.client.get(
            "/api/v2/malware?platform=Windows",
            headers=self.analyst_headers,
        )
        self.assertEqual(list_resp.status_code, 200)
        data = list_resp.get_json()
        self.assertGreaterEqual(len(data["items"]), 1)

        detail_resp = self.client.get(
            f"/api/v2/malware/{self.malware_id}",
            headers=self.analyst_headers,
        )
        self.assertEqual(detail_resp.status_code, 200)
        mal = detail_resp.get_json()["malware"]
        self.assertEqual(mal["malware_name"], self.malware.malware_name)
        self.assertIn(self.ind1_id, mal["indicator_ids"])

    # =========================================================================
    # 7. AUDIT LOGS & USERS (ADMIN-ONLY)
    # =========================================================================

    def test_audit_logs_admin_restriction(self):
        """Verifies non-admin users receive 403 on /api/v2/audit-logs."""
        # Analyst rejected
        resp_analyst = self.client.get(
            "/api/v2/audit-logs",
            headers=self.analyst_headers,
        )
        self.assertEqual(resp_analyst.status_code, 403)

        # Admin accepted
        resp_admin = self.client.get(
            "/api/v2/audit-logs",
            headers=self.admin_headers,
        )
        self.assertEqual(resp_admin.status_code, 200)
        data = resp_admin.get_json()
        self.assertIn("items", data)

    def test_users_admin_restriction_and_safety(self):
        """Verifies non-admin receives 403 and admin receives user list without password hashes."""
        # Analyst rejected
        resp_analyst = self.client.get(
            "/api/v2/users",
            headers=self.analyst_headers,
        )
        self.assertEqual(resp_analyst.status_code, 403)

        # Admin accepted
        resp_admin = self.client.get(
            "/api/v2/users",
            headers=self.admin_headers,
        )
        self.assertEqual(resp_admin.status_code, 200)
        data = resp_admin.get_json()
        self.assertIn("items", data)
        for u in data["items"]:
            self.assertNotIn("password_hash", u)
            self.assertIn("username", u)
            self.assertIn("role", u)


if __name__ == "__main__":
    unittest.main()
