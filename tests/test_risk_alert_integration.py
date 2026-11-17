"""
Integration Tests: Automated Alert Generation on IOC Risk Score Persistence
============================================================================
Verifies the automatic evaluation and generation of security alerts upon saving
or updating threat indicator risk scores through the normal application flow.

Test Cases:
1. Risk score >= 75 -> CRITICAL alert created automatically (Open, is_read=False).
2. Risk score 50-74 -> HIGH alert created automatically (Open, is_read=False).
3. Risk score < 50  -> No risk alert created.
4. Saving same high/critical score again -> Deduplication preserves single active alert.
5. Generated alert appears in /alerts.
6. Generated alert appears as NEW / UNREAD in the UI.
"""

import unittest
from datetime import datetime, timedelta
from app import create_app, db
from app.models.user import User
from app.models.threat_indicator import ThreatIndicator
from app.models.alert import Alert
from app.services.risk_scoring import save_indicator_risk
from app.services.alert_service import get_alerts_filtered


class TestRiskAlertIntegration(unittest.TestCase):

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
        self.user = User.query.filter_by(email="risk_alert_test@test.com").first()
        if not self.user:
            self.user = User(
                username="risk_alert_tester",
                email="risk_alert_test@test.com",
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
        # Clean up any test indicators and their alerts
        indicators = ThreatIndicator.query.filter(
            ThreatIndicator.indicator_value.like("auto_alert_%")
        ).all()
        for ind in indicators:
            ind.reports.clear()
            ind.malwares.clear()
            db.session.delete(ind)

        alerts = Alert.query.filter(
            Alert.title.like("%auto_alert_%")
        ).all()
        for a in alerts:
            db.session.delete(a)

        db.session.commit()

    def _login(self, client):
        with client.session_transaction() as sess:
            sess["_user_id"] = str(self.user.id)
            sess["_fresh"] = True

    def _create_indicator(self, value, severity="Medium", confidence=50, status="Active"):
        ind = ThreatIndicator(
            indicator_value=value,
            indicator_type="ipv4",
            severity=severity,
            confidence_score=confidence,
            status=status,
            source="Manual",
            added_by_user_id=self.user.id,
            last_seen_at=datetime.utcnow()
        )
        db.session.add(ind)
        db.session.commit()
        return ind

    # -------------------------------------------------------------------------
    # TEST CASE 1: Risk score >= 75 triggers CRITICAL alert automatically
    # -------------------------------------------------------------------------
    def test_case_1_critical_risk_generates_alert_automatically(self):
        """Test Case 1: Saving an IOC with risk score >= 75 automatically creates a CRITICAL, OPEN, UNREAD alert."""
        self._login(self.client)
        # Severity Critical (50) + Confidence 100 (20) + Status Active (5) + Recency (5) = 80 (CRITICAL)
        ind = self._create_indicator(
            value="auto_alert_crit.1",
            severity="Critical",
            confidence=100,
            status="Active"
        )

        # Trigger normal application flow: POST /threat-indicator/<id>/risk-score
        response = self.client.post(f"/threat-indicator/{ind.id}/risk-score")
        self.assertEqual(response.status_code, 200)
        data = response.get_json()
        self.assertTrue(data["success"])
        self.assertTrue(data["saved"])
        self.assertGreaterEqual(data["risk_score"], 75)

        # Verify alert was automatically created in the database without manual shell execution
        db.session.refresh(ind)
        self.assertGreaterEqual(ind.risk_score, 75)

        alerts = Alert.query.filter_by(indicator_id=ind.id, alert_type="Risk Score").all()
        self.assertEqual(len(alerts), 1, "Exactly one risk alert must be automatically created")
        alert = alerts[0]
        self.assertEqual(alert.severity, "Critical")
        self.assertEqual(alert.status, "Open")
        self.assertFalse(alert.is_read)
        self.assertIn("CRITICAL", alert.title)
        self.assertIn(ind.indicator_value, alert.title)

    # -------------------------------------------------------------------------
    # TEST CASE 2: Risk score 50-74 triggers HIGH alert automatically
    # -------------------------------------------------------------------------
    def test_case_2_high_risk_generates_alert_automatically(self):
        """Test Case 2: Saving an IOC with risk score between 50 and 74 automatically creates a HIGH alert."""
        self._login(self.client)
        # Severity High (40) + Confidence 50 (10) + Status Active (5) + Recency (5) = 60 (HIGH)
        ind = self._create_indicator(
            value="auto_alert_high.2",
            severity="High",
            confidence=50,
            status="Active"
        )

        # Save through normal application flow
        response = self.client.post(f"/threat-indicator/{ind.id}/risk-score")
        self.assertEqual(response.status_code, 200)
        data = response.get_json()
        self.assertTrue(data["success"])
        self.assertTrue(data["saved"])
        self.assertTrue(50 <= data["risk_score"] <= 74)

        # Verify HIGH alert is automatically generated
        alerts = Alert.query.filter_by(indicator_id=ind.id, alert_type="Risk Score").all()
        self.assertEqual(len(alerts), 1)
        alert = alerts[0]
        self.assertEqual(alert.severity, "High")
        self.assertEqual(alert.status, "Open")
        self.assertFalse(alert.is_read)
        self.assertIn("High Risk", alert.title)

    # -------------------------------------------------------------------------
    # TEST CASE 3: Risk score below threshold generates NO alert
    # -------------------------------------------------------------------------
    def test_case_3_low_risk_generates_no_alert(self):
        """Test Case 3: Saving an IOC with risk score < 50 generates NO risk alert."""
        self._login(self.client)
        # Severity Low (10) + Confidence 20 (4) + Status Inactive (0) = 14 (LOW)
        ind = self._create_indicator(
            value="auto_alert_low.3",
            severity="Low",
            confidence=20,
            status="Inactive"
        )

        response = self.client.post(f"/threat-indicator/{ind.id}/risk-score")
        self.assertEqual(response.status_code, 200)
        data = response.get_json()
        self.assertTrue(data["success"])
        self.assertTrue(data["saved"])
        self.assertLess(data["risk_score"], 50)

        # Verify no risk alert is created
        alerts = Alert.query.filter_by(indicator_id=ind.id, alert_type="Risk Score").all()
        self.assertEqual(len(alerts), 0, "No risk alert should be generated for low risk score")

    # -------------------------------------------------------------------------
    # TEST CASE 4: Deduplication on repeated saves
    # -------------------------------------------------------------------------
    def test_case_4_repeated_save_does_not_create_duplicate_alert(self):
        """Test Case 4: Saving the same high/critical risk score again does not create duplicate active alerts."""
        self._login(self.client)
        ind = self._create_indicator(
            value="auto_alert_dupe.4",
            severity="Critical",
            confidence=90,
            status="Active"
        )

        # First save
        resp1 = self.client.post(f"/threat-indicator/{ind.id}/risk-score")
        self.assertEqual(resp1.status_code, 200)
        alerts_first = Alert.query.filter_by(indicator_id=ind.id, alert_type="Risk Score").all()
        self.assertEqual(len(alerts_first), 1)

        # Second save (simulates user clicking save again or automated re-evaluation)
        resp2 = self.client.post(f"/threat-indicator/{ind.id}/risk-score")
        self.assertEqual(resp2.status_code, 200)
        alerts_second = Alert.query.filter_by(indicator_id=ind.id, alert_type="Risk Score").all()
        self.assertEqual(len(alerts_second), 1, "Duplicate active alert must not be created")
        self.assertEqual(alerts_second[0].id, alerts_first[0].id)

    # -------------------------------------------------------------------------
    # TEST CASE 5: Generated alert appears in /alerts
    # -------------------------------------------------------------------------
    def test_case_5_generated_alert_appears_in_alerts_view(self):
        """Test Case 5: The automatically generated alert is listed when querying /alerts."""
        self._login(self.client)
        ind = self._create_indicator(
            value="auto_alert_feed.5",
            severity="Critical",
            confidence=100,
            status="Active"
        )

        # Persist risk score
        self.client.post(f"/threat-indicator/{ind.id}/risk-score")

        # Query /alerts via HTML
        response_html = self.client.get("/alerts")
        self.assertEqual(response_html.status_code, 200)
        self.assertIn("auto_alert_feed.5", response_html.get_data(as_text=True))

        # Query /alerts via JSON
        response_json = self.client.get("/alerts", headers={"Accept": "application/json"})
        self.assertEqual(response_json.status_code, 200)
        data = response_json.get_json()
        matching = [a for a in data["alerts"] if "auto_alert_feed.5" in a["title"]]
        self.assertEqual(len(matching), 1)
        self.assertEqual(matching[0]["severity"], "Critical")

    # -------------------------------------------------------------------------
    # TEST CASE 6: Generated alert appears as NEW / UNREAD in the UI
    # -------------------------------------------------------------------------
    def test_case_6_generated_alert_appears_as_unread_in_ui(self):
        """Test Case 6: Generated alert is flagged as unread (is_read=False) and displays UNREAD in Alert Center."""
        self._login(self.client)
        ind = self._create_indicator(
            value="auto_alert_unread.6",
            severity="High",
            confidence=60,
            status="Active"
        )

        self.client.post(f"/threat-indicator/{ind.id}/risk-score")

        alert = Alert.query.filter_by(indicator_id=ind.id, alert_type="Risk Score").first()
        self.assertIsNotNone(alert)
        self.assertFalse(alert.is_read)

        # Check /alerts page renders UNREAD indicator
        resp = self.client.get("/alerts")
        html = resp.get_data(as_text=True)
        self.assertIn("auto_alert_unread.6", html)
        self.assertIn("New / Unread", html)


if __name__ == "__main__":
    unittest.main()
