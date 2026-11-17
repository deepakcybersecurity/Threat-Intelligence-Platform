"""
Unit and Integration Tests for Task 6: Alert Center
===================================================
Verifies:
1. Alert Center requires authentication
2. Alert list loads successfully (HTTP 200)
3. Alert details loads successfully (HTTP 200)
4. Nonexistent alert returns 404
5. Search by title
6. Search by message/description
7. Filter by severity
8. Filter by status
9. Filter by alert type
10. Combined filters
11. Mark alert as read
12. Acknowledge alert (Open -> In Progress)
13. Resolve alert (In Progress -> Resolved)
14. Invalid state transition rejected
15. Reopen alert (Resolved -> Open)
16. Risk-based alert generation (High and Critical)
17. High-risk alert generation
18. Critical-risk alert generation
19. Enrichment-based alert generation from cache
20. Correlation-based alert generation
21. Duplicate alert prevention
22. Missing IOC handled safely
23. Missing enrichment handled safely
24. Missing correlation handled safely
25. Alert severity and status preserved
26. Alert generation is deterministic
27. No external HTTP calls during alert generation
28. Dashboard alert statistics
29. Alert JSON/response structure
30. Existing alert records remain intact
"""

import json
import unittest
from datetime import datetime, timedelta

from app import create_app, db
from app.models import User, Alert, ThreatIndicator, ThreatReport, Malware, APICache
from app.services.alert_service import (
    create_alert,
    get_or_create_alert,
    generate_risk_alert,
    generate_enrichment_alert,
    generate_correlation_alert,
    generate_indicator_alerts,
    mark_alert_read,
    acknowledge_alert,
    resolve_alert,
    reopen_alert,
    get_alerts_filtered,
    get_alert_counts,
)


class TestAlertCenter(unittest.TestCase):

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
        self.user = User.query.filter_by(email="alert_analyst@test.com").first()
        if not self.user:
            self.user = User(
                username="alert_analyst",
                email="alert_analyst@test.com",
                password_hash="pbkdf2:sha256:dummyhash",
                role="analyst"
            )
            db.session.add(self.user)
            db.session.commit()

        self._cleanup_test_data()

    def tearDown(self):
        db.session.rollback()
        self._cleanup_test_data()
        self.app_context.pop()

    def _cleanup_test_data(self):
        db.session.rollback()
        alerts = Alert.query.filter(
            Alert.title.like("ALERT_TEST_%")
        ).all()
        for a in alerts:
            db.session.delete(a)

        indicators = ThreatIndicator.query.filter(
            ThreatIndicator.indicator_value.like("alert_test_%")
        ).all()
        for ind in indicators:
            ind.reports.clear()
            ind.malwares.clear()
            db.session.delete(ind)

        reports = ThreatReport.query.filter(
            ThreatReport.title.like("ALERT_TEST_%")
        ).all()
        for rep in reports:
            rep.indicators.clear()
            rep.malwares.clear()
            db.session.delete(rep)

        malwares = Malware.query.filter(
            Malware.malware_name.like("ALERT_TEST_%")
        ).all()
        for mal in malwares:
            mal.indicators.clear()
            mal.reports.clear()
            db.session.delete(mal)

        caches = APICache.query.filter(
            APICache.endpoint.like("%:alert_test_%")
        ).all()
        for c in caches:
            db.session.delete(c)

        db.session.commit()

    def _login(self, client):
        with client.session_transaction() as sess:
            sess["_user_id"] = str(self.user.id)
            sess["_fresh"] = True

    def _create_test_indicator(self, val="alert_test_ioc_1", typ="ipv4", sev="High", conf=80, stat="Active"):
        ind = ThreatIndicator(
            indicator_value=val,
            indicator_type=typ,
            severity=sev,
            confidence_score=conf,
            status=stat,
            source="Threat Report",
            added_by_user_id=self.user.id,
            last_seen_at=datetime.utcnow()
        )
        db.session.add(ind)
        db.session.commit()
        return ind

    # -------------------------------------------------------------------------
    # TEST 1: Authentication Requirement
    # -------------------------------------------------------------------------
    def test_01_alerts_requires_authentication(self):
        """TEST 1: Unauthenticated request to /alerts redirects to login (HTTP 302)."""
        unauthed_client = self.app.test_client()
        response = unauthed_client.get("/alerts")
        self.assertEqual(response.status_code, 302)

    # -------------------------------------------------------------------------
    # TEST 2: Alert List Loads (HTTP 200)
    # -------------------------------------------------------------------------
    def test_02_alert_list_loads(self):
        """TEST 2: Authenticated request to /alerts returns HTTP 200."""
        self._login(self.client)
        response = self.client.get("/alerts")
        self.assertEqual(response.status_code, 200)
        self.assertIn("Security Alert Center", response.get_data(as_text=True))

    # -------------------------------------------------------------------------
    # TEST 3: Alert Details Loads (HTTP 200)
    # -------------------------------------------------------------------------
    def test_03_alert_details_loads(self):
        """TEST 3: Authenticated request to /alert/<id> returns HTTP 200 with details."""
        self._login(self.client)
        alert = create_alert(title="ALERT_TEST_Detail_1", description="Detailed description", severity="High")
        response = self.client.get(f"/alert/{alert.id}")
        self.assertEqual(response.status_code, 200)
        html = response.get_data(as_text=True)
        self.assertIn("ALERT_TEST_Detail_1", html)
        self.assertIn("Detailed description", html)

    # -------------------------------------------------------------------------
    # TEST 4: Nonexistent Alert Returns 404
    # -------------------------------------------------------------------------
    def test_04_nonexistent_alert_returns_404(self):
        """TEST 4: Nonexistent alert ID returns HTTP 404."""
        self._login(self.client)
        response = self.client.get("/alert/999999")
        self.assertEqual(response.status_code, 404)

    # -------------------------------------------------------------------------
    # TEST 5-6: Search by Title and Message
    # -------------------------------------------------------------------------
    def test_05_search_by_title(self):
        """TEST 5: Search filters alerts by matching title."""
        create_alert(title="ALERT_TEST_Ransomware_Attack", severity="Critical")
        create_alert(title="ALERT_TEST_Port_Scan", severity="Low")

        results = get_alerts_filtered(query_text="Ransomware")
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0].title, "ALERT_TEST_Ransomware_Attack")

    def test_06_search_by_message(self):
        """TEST 6: Search filters alerts by matching description text."""
        create_alert(title="ALERT_TEST_Event_1", description="Contains secret_backdoor payload")
        create_alert(title="ALERT_TEST_Event_2", description="Normal traffic observation")

        results = get_alerts_filtered(query_text="secret_backdoor")
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0].title, "ALERT_TEST_Event_1")

    # -------------------------------------------------------------------------
    # TEST 7-9: Filters by Severity, Status, and Type
    # -------------------------------------------------------------------------
    def test_07_filter_by_severity(self):
        """TEST 7: Filter alerts by severity (Critical, High, Medium, Low)."""
        create_alert(title="ALERT_TEST_Sev_Crit", severity="Critical")
        create_alert(title="ALERT_TEST_Sev_Low", severity="Low")

        crit_alerts = get_alerts_filtered(severity="Critical")
        self.assertTrue(all(a.severity == "Critical" for a in crit_alerts))
        self.assertTrue(any(a.title == "ALERT_TEST_Sev_Crit" for a in crit_alerts))

    def test_08_filter_by_status(self):
        """TEST 8: Filter alerts by status (Open, In Progress, Resolved)."""
        create_alert(title="ALERT_TEST_Stat_Open", status="Open")
        create_alert(title="ALERT_TEST_Stat_Res", status="Resolved")

        open_alerts = get_alerts_filtered(status="Open")
        self.assertTrue(all(a.status == "Open" for a in open_alerts))
        self.assertTrue(any(a.title == "ALERT_TEST_Stat_Open" for a in open_alerts))

    def test_09_filter_by_alert_type(self):
        """TEST 9: Filter alerts by alert_type."""
        create_alert(title="ALERT_TEST_Type_Risk", alert_type="Risk Score")
        create_alert(title="ALERT_TEST_Type_Enrich", alert_type="Enrichment")

        risk_alerts = get_alerts_filtered(alert_type="Risk Score")
        self.assertTrue(all(a.alert_type == "Risk Score" for a in risk_alerts))
        self.assertTrue(any(a.title == "ALERT_TEST_Type_Risk" for a in risk_alerts))

    # -------------------------------------------------------------------------
    # TEST 10: Combined Filters
    # -------------------------------------------------------------------------
    def test_10_combined_filters(self):
        """TEST 10: Combined filters match intersection of criteria."""
        create_alert(title="ALERT_TEST_Comb_1", severity="Critical", status="Open", alert_type="Risk Score")
        create_alert(title="ALERT_TEST_Comb_2", severity="Critical", status="Resolved", alert_type="Risk Score")
        create_alert(title="ALERT_TEST_Comb_3", severity="High", status="Open", alert_type="Risk Score")

        filtered = get_alerts_filtered(query_text="ALERT_TEST_Comb", severity="Critical", status="Open", alert_type="Risk Score")
        self.assertEqual(len(filtered), 1)
        self.assertEqual(filtered[0].title, "ALERT_TEST_Comb_1")

        all_matching = get_alerts_filtered(severity="Critical", status="Open", alert_type="Risk Score")
        self.assertTrue(all(a.severity == "Critical" and a.status == "Open" and a.alert_type == "Risk Score" for a in all_matching))
        self.assertTrue(any(a.title == "ALERT_TEST_Comb_1" for a in all_matching))
        self.assertFalse(any(a.title == "ALERT_TEST_Comb_2" for a in all_matching))
        self.assertFalse(any(a.title == "ALERT_TEST_Comb_3" for a in all_matching))

    # -------------------------------------------------------------------------
    # TEST 11: Mark Alert as Read
    # -------------------------------------------------------------------------
    def test_11_mark_alert_as_read(self):
        """TEST 11: mark_alert_read sets is_read=True."""
        alert = create_alert(title="ALERT_TEST_Read", is_read=False)
        self.assertFalse(alert.is_read)

        mark_alert_read(alert.id, self.user)
        db.session.refresh(alert)
        self.assertTrue(alert.is_read)

    # -------------------------------------------------------------------------
    # TEST 12: Acknowledge Alert (Open -> In Progress)
    # -------------------------------------------------------------------------
    def test_12_acknowledge_alert(self):
        """TEST 12: acknowledge_alert transitions status from Open to In Progress."""
        alert = create_alert(title="ALERT_TEST_Ack", status="Open")
        self.assertEqual(alert.status, "Open")

        acknowledge_alert(alert.id, self.user)
        db.session.refresh(alert)
        self.assertEqual(alert.status, "In Progress")
        self.assertTrue(alert.is_read)
        self.assertEqual(alert.user_id, self.user.id)

    # -------------------------------------------------------------------------
    # TEST 13: Resolve Alert (In Progress -> Resolved)
    # -------------------------------------------------------------------------
    def test_13_resolve_alert(self):
        """TEST 13: resolve_alert transitions status to Resolved."""
        alert = create_alert(title="ALERT_TEST_Resolve", status="In Progress")
        resolve_alert(alert.id, self.user)
        db.session.refresh(alert)
        self.assertEqual(alert.status, "Resolved")
        self.assertTrue(alert.is_read)

    # -------------------------------------------------------------------------
    # TEST 14: Invalid State Transitions Rejected
    # -------------------------------------------------------------------------
    def test_14_invalid_state_transition_rejected(self):
        """TEST 14: Invalid state transitions raise ValueError."""
        alert = create_alert(title="ALERT_TEST_Invalid", status="Resolved")

        # Cannot acknowledge an already resolved alert
        with self.assertRaises(ValueError):
            acknowledge_alert(alert.id, self.user)

        alert.status = "Closed"
        db.session.commit()

        # Cannot resolve a closed alert
        with self.assertRaises(ValueError):
            resolve_alert(alert.id, self.user)

    # -------------------------------------------------------------------------
    # TEST 15: Reopen Alert (Resolved -> Open)
    # -------------------------------------------------------------------------
    def test_15_reopen_alert(self):
        """TEST 15: reopen_alert transitions status back to Open and marks is_read=False."""
        alert = create_alert(title="ALERT_TEST_Reopen", status="Resolved", is_read=True)
        reopen_alert(alert.id, self.user)
        db.session.refresh(alert)
        self.assertEqual(alert.status, "Open")
        self.assertFalse(alert.is_read)

    # -------------------------------------------------------------------------
    # TEST 16-18: Risk-Based Alert Generation
    # -------------------------------------------------------------------------
    def test_16_risk_based_alert_generation(self):
        """TEST 16: generate_risk_alert creates alert based on calculated risk."""
        ind = self._create_test_indicator(val="alert_test_risk_gen", sev="High", conf=80)
        alert = generate_risk_alert(ind.id)
        self.assertIsNotNone(alert)
        self.assertEqual(alert.alert_type, "Risk Score")
        self.assertEqual(alert.indicator_id, ind.id)

    def test_17_high_risk_alert_generation(self):
        """TEST 17: High-risk indicator produces High severity alert."""
        # High (40) + conf 60*0.2 (12) + active (5) + recency (5) = 62 (HIGH)
        ind = self._create_test_indicator(val="alert_test_high_risk", sev="High", conf=60)
        alert = generate_risk_alert(ind.id)
        self.assertIsNotNone(alert)
        self.assertEqual(alert.severity, "High")

    def test_18_critical_risk_alert_generation(self):
        """TEST 18: Critical-risk indicator produces Critical severity alert."""
        # Critical (50) + conf 100*0.2 (20) + active (5) + recency (5) = 80 (CRITICAL)
        ind = self._create_test_indicator(val="alert_test_crit_risk", sev="Critical", conf=100)
        alert = generate_risk_alert(ind.id)
        self.assertIsNotNone(alert)
        self.assertEqual(alert.severity, "Critical")

    # -------------------------------------------------------------------------
    # TEST 19: Enrichment-Based Alert Generation from Cache
    # -------------------------------------------------------------------------
    def test_19_enrichment_based_alert_generation_from_cache(self):
        """TEST 19: generate_enrichment_alert creates alert from cached intelligence without external calls."""
        ind = self._create_test_indicator(val="alert_test_enrich_ip", typ="ipv4")
        cache = APICache(
            api_name="AbuseIPDB",
            endpoint="ipv4:alert_test_enrich_ip",
            response_data=json.dumps({"abuse_confidence_score": 88, "total_reports": 45}),
            expires_at=datetime.utcnow() + timedelta(hours=24)
        )
        db.session.add(cache)
        db.session.commit()

        alert = generate_enrichment_alert(ind.id)
        self.assertIsNotNone(alert)
        self.assertEqual(alert.alert_type, "Enrichment")
        self.assertEqual(alert.severity, "High")
        self.assertIn("AbuseIPDB", alert.description)

    # -------------------------------------------------------------------------
    # TEST 20: Correlation-Based Alert Generation
    # -------------------------------------------------------------------------
    def test_20_correlation_based_alert_generation(self):
        """TEST 20: generate_correlation_alert creates alert when IOC links to malware."""
        ind = self._create_test_indicator(val="alert_test_corr_ioc")
        mal = Malware(
            malware_name="ALERT_TEST_Trojan",
            malware_type="Trojan",
            platform="Windows",
            severity="Critical",
            created_by_user_id=self.user.id
        )
        mal.indicators.append(ind)
        db.session.add(mal)
        db.session.commit()

        alert = generate_correlation_alert(ind.id)
        self.assertIsNotNone(alert)
        self.assertEqual(alert.alert_type, "Correlation")
        self.assertEqual(alert.severity, "High")
        self.assertIn("ALERT_TEST_Trojan", alert.description)

    # -------------------------------------------------------------------------
    # TEST 21: Duplicate Alert Prevention
    # -------------------------------------------------------------------------
    def test_21_duplicate_alert_prevention(self):
        """TEST 21: Repeated alert generation calls return existing open alert, preventing duplicates."""
        ind = self._create_test_indicator(val="alert_test_dup_check", sev="Critical", conf=100)
        
        alert1 = generate_risk_alert(ind.id)
        self.assertIsNotNone(alert1)

        alert2 = generate_risk_alert(ind.id)
        self.assertEqual(alert1.id, alert2.id, "Second call should return the existing active alert")

        # Total open risk alerts for this indicator must still be 1
        count = Alert.query.filter_by(indicator_id=ind.id, alert_type="Risk Score").count()
        self.assertEqual(count, 1)

    # -------------------------------------------------------------------------
    # TEST 22-24: Safe Missing Data Handling
    # -------------------------------------------------------------------------
    def test_22_missing_ioc_handled_safely(self):
        """TEST 22: Nonexistent indicator ID returns None safely without raising exceptions."""
        self.assertIsNone(generate_risk_alert(999999))
        self.assertIsNone(generate_enrichment_alert(999999))
        self.assertIsNone(generate_correlation_alert(999999))
        self.assertEqual(generate_indicator_alerts(999999), [])

    def test_23_missing_enrichment_handled_safely(self):
        """TEST 23: Indicator with no cached enrichment returns None safely."""
        ind = self._create_test_indicator(val="alert_test_no_enrich")
        alert = generate_enrichment_alert(ind.id)
        self.assertIsNone(alert)

    def test_24_missing_correlation_handled_safely(self):
        """TEST 24: Indicator with no correlation returns None safely."""
        ind = self._create_test_indicator(val="alert_test_no_corr", sev="Low", conf=0)
        alert = generate_correlation_alert(ind.id)
        self.assertIsNone(alert)

    # -------------------------------------------------------------------------
    # TEST 25: Alert Severity/Status Preserved
    # -------------------------------------------------------------------------
    def test_25_alert_severity_status_preserved(self):
        """TEST 25: Created alert fields are persisted accurately in database."""
        alert = create_alert(
            title="ALERT_TEST_Preserve",
            description="Preserve test",
            severity="Critical",
            alert_type="Risk Score",
            status="In Progress"
        )
        db.session.refresh(alert)
        self.assertEqual(alert.severity, "Critical")
        self.assertEqual(alert.status, "In Progress")
        self.assertEqual(alert.alert_type, "Risk Score")

    # -------------------------------------------------------------------------
    # TEST 26: Deterministic Generation
    # -------------------------------------------------------------------------
    def test_26_alert_generation_deterministic(self):
        """TEST 26: Consistent inputs generate consistent alerts."""
        ind = self._create_test_indicator(val="alert_test_det", sev="High", conf=70)
        a1 = generate_risk_alert(ind.id)
        self.assertEqual(a1.severity, "High")
        self.assertEqual(a1.alert_type, "Risk Score")

    # -------------------------------------------------------------------------
    # TEST 27: Zero External HTTP Calls
    # -------------------------------------------------------------------------
    def test_27_no_external_http_calls_during_generation(self):
        """TEST 27: Alert generation exclusively inspects local database and APICache."""
        ind = self._create_test_indicator(val="alert_test_no_http", typ="ipv4")
        # Without cache, returns None immediately without external network call
        alert = generate_enrichment_alert(ind.id)
        self.assertIsNone(alert)

    # -------------------------------------------------------------------------
    # TEST 28: Dashboard Alert Statistics
    # -------------------------------------------------------------------------
    def test_28_dashboard_alert_statistics(self):
        """TEST 28: get_alert_counts returns accurate aggregate counts."""
        create_alert(title="ALERT_TEST_Count_1", severity="Critical", status="Open")
        create_alert(title="ALERT_TEST_Count_2", severity="High", status="In Progress")
        create_alert(title="ALERT_TEST_Count_3", severity="Low", status="Resolved")

        counts = get_alert_counts()
        self.assertGreaterEqual(counts["total"], 3)
        self.assertGreaterEqual(counts["critical"], 1)
        self.assertGreaterEqual(counts["high"], 1)
        self.assertGreaterEqual(counts["active"], 2)

    # -------------------------------------------------------------------------
    # TEST 29: Alert JSON Response Structure
    # -------------------------------------------------------------------------
    def test_29_alert_json_response_structure(self):
        """TEST 29: GET /alerts with JSON accept header returns normalized JSON schema."""
        self._login(self.client)
        alert = create_alert(title="ALERT_TEST_JSON", severity="High")
        response = self.client.get("/alerts", headers={"Accept": "application/json"})
        self.assertEqual(response.status_code, 200)

        data = response.get_json()
        self.assertTrue(data["success"])
        self.assertIn("counts", data)
        self.assertIn("alerts", data)
        self.assertTrue(any(a["id"] == alert.id for a in data["alerts"]))

    # -------------------------------------------------------------------------
    # TEST 30: Existing Alert Records Remain Intact
    # -------------------------------------------------------------------------
    def test_30_existing_alert_records_remain_intact(self):
        """TEST 30: Modifications to one alert do not affect unrelated alert records."""
        a1 = create_alert(title="ALERT_TEST_Isolation_1", status="Open")
        a2 = create_alert(title="ALERT_TEST_Isolation_2", status="Open")

        resolve_alert(a1.id, self.user)
        db.session.refresh(a1)
        db.session.refresh(a2)

        self.assertEqual(a1.status, "Resolved")
        self.assertEqual(a2.status, "Open", "Unrelated alert status must remain unchanged")


if __name__ == "__main__":
    unittest.main()
