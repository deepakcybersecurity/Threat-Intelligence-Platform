"""
Integration Tests for Task 2: Threat Report -> IOC Database Integration
========================================================================
Verifies:
- End-to-End Threat Report creation, automated IOC extraction, and indicator linking
- Re-use of existing ThreatIndicator records across multiple reports
- Duplicate IOC handling within report text
- Empty narrative and no-IOC handling
- Transaction atomicity and rollback safety
- Threat Feed rendering of extracted indicators
"""

import unittest
from datetime import datetime
from io import BytesIO
from flask_login import login_user

from app import create_app, db
from app.models import User, ThreatReport, ThreatIndicator
from app.models.associations import report_indicator


class TestThreatReportIOCIntegration(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.app = create_app()
        cls.app.config["TESTING"] = True
        cls.app.config["WTF_CSRF_ENABLED"] = False
        cls.client = cls.app.test_client()

    def setUp(self):
        self.app_context = self.app.app_context()
        self.app_context.push()

        # Find or create test user
        self.user = User.query.filter_by(email="test_analyst@test.com").first()
        if not self.user:
            self.user = User(
                username="test_analyst",
                email="test_analyst@test.com",
                password_hash="pbkdf2:sha256:dummyhash",
                role="analyst"
            )
            db.session.add(self.user)
            db.session.commit()

        # Clean up test indicators and reports before tests run
        self._cleanup()

    def _cleanup(self):
        db.session.rollback()
        test_indicators = ThreatIndicator.query.filter(
            ThreatIndicator.indicator_value.in_([
                "185.220.101.45",
                "test-integration-evil.com",
                "https://test-integration-evil.com/payload.exe",
                "275a5071de6e79cd437d32e6f007e7729d2b2fe2e317180bc3946ac614289cfa",
                "198.51.100.1",
                "203.0.113.50",
                "rollback-test.org"
            ])
        ).all()

        for ind in test_indicators:
            ind.reports.clear()
            db.session.delete(ind)

        test_reports = ThreatReport.query.filter(
            ThreatReport.title.like("TEST_%")
        ).all()
        for rep in test_reports:
            rep.indicators.clear()
            db.session.delete(rep)

        db.session.commit()

    def tearDown(self):
        self._cleanup()
        self.app_context.pop()

    def _login(self, client):
        with client.session_transaction() as sess:
            sess["_user_id"] = str(self.user.id)
            sess["_fresh"] = True

    def test_section_12_end_to_end_pipeline(self):
        """
        SECTION 12: End-to-End Test
        Submit narrative with IPv4, Domain, URL, and SHA256.
        Verify report, 4 indicators, M2M links, and feed display.
        """
        self._login(self.client)

        sample_narrative = (
            "The investigation identified malicious IP 185.220.101.45. "
            "The attacker-controlled domain was test-integration-evil.com. "
            "The payload was downloaded from https://test-integration-evil.com/payload.exe. "
            "SHA256: 275a5071de6e79cd437d32e6f007e7729d2b2fe2e317180bc3946ac614289cfa"
        )

        response = self.client.post(
            "/threat-report-upload",
            data={
                "title": "TEST_APT_Investigation_Report",
                "summary": sample_narrative,
                "category": "APT Campaign",
                "severity": "high",
                "tlp_level": "amber",
                "sectors": "Energy, Finance",
            },
            follow_redirects=True
        )

        self.assertEqual(response.status_code, 200)

        # 1. Verify ThreatReport created in DB
        report = ThreatReport.query.filter_by(title="TEST_APT_Investigation_Report").first()
        self.assertIsNotNone(report, "ThreatReport should exist in database")
        self.assertEqual(report.severity, "high")
        self.assertEqual(report.tlp_level, "amber")
        self.assertEqual(report.user_id, self.user.id)

        # 2. Verify 4 ThreatIndicator records created
        expected_iocs = {
            "185.220.101.45": "ipv4",
            "test-integration-evil.com": "domain",
            "https://test-integration-evil.com/payload.exe": "url",
            "275a5071de6e79cd437d32e6f007e7729d2b2fe2e317180bc3946ac614289cfa": "sha256"
        }

        indicators = ThreatIndicator.query.filter(
            ThreatIndicator.indicator_value.in_(expected_iocs.keys())
        ).all()
        self.assertEqual(len(indicators), 4, "Exactly 4 indicators should be stored in threat_indicators")

        for ind in indicators:
            self.assertEqual(ind.indicator_type, expected_iocs[ind.indicator_value])
            self.assertEqual(ind.confidence_score, 50)
            self.assertEqual(ind.severity, "High")  # Normalized to TitleCase enum
            self.assertEqual(ind.tlp_marking, "AMBER")  # Normalized to uppercase enum
            self.assertEqual(ind.status, "Active")
            self.assertEqual(ind.source, "Threat Report")
            self.assertEqual(ind.context, "TEST_APT_Investigation_Report")
            self.assertEqual(ind.added_by_user_id, self.user.id)

        # 3. Verify M2M association links
        self.assertEqual(len(report.indicators), 4, "Report should have 4 linked indicators via M2M relationship")
        report_indicator_rows = db.session.execute(
            report_indicator.select().where(report_indicator.c.report_id == report.id)
        ).fetchall()
        self.assertEqual(len(report_indicator_rows), 4, "report_indicator join table must contain 4 rows")

        # 4. Verify display through existing Threat Feed
        feed_response = self.client.get("/threat-feed")
        self.assertEqual(feed_response.status_code, 200)
        feed_html = feed_response.get_data(as_text=True)
        for ioc_val in expected_iocs.keys():
            self.assertIn(ioc_val, feed_html, f"IOC {ioc_val} should be rendered in /threat-feed")

    def test_section_13_case_1_no_iocs(self):
        """Case 1: Report with no IOCs (report created, 0 indicators created)."""
        self._login(self.client)

        response = self.client.post(
            "/threat-report-upload",
            data={
                "title": "TEST_No_IOCs_Report",
                "summary": "This is a purely descriptive report discussing security policy updates.",
                "category": "Policy",
                "severity": "low",
                "tlp_level": "green",
                "sectors": "Corporate",
            },
            follow_redirects=True
        )
        self.assertEqual(response.status_code, 200)

        report = ThreatReport.query.filter_by(title="TEST_No_IOCs_Report").first()
        self.assertIsNotNone(report)
        self.assertEqual(len(report.indicators), 0, "No indicators should be linked")

    def test_section_13_case_2_duplicate_iocs_within_description(self):
        """Case 2: Duplicate IOCs in description (single indicator created & linked)."""
        self._login(self.client)

        duplicate_narrative = (
            "Detected malicious host at 198.51.100.1. "
            "Repeated communication attempt to 198.51.100.1 was blocked by the firewall. "
            "Origin remains 198.51.100.1."
        )

        response = self.client.post(
            "/threat-report-upload",
            data={
                "title": "TEST_Duplicate_IOC_Report",
                "summary": duplicate_narrative,
                "category": "Brute Force",
                "severity": "medium",
                "tlp_level": "white",
                "sectors": "IT",
            },
            follow_redirects=True
        )
        self.assertEqual(response.status_code, 200)

        report = ThreatReport.query.filter_by(title="TEST_Duplicate_IOC_Report").first()
        self.assertIsNotNone(report)
        self.assertEqual(len(report.indicators), 1, "Only 1 unique indicator should be linked")

        indicators = ThreatIndicator.query.filter_by(indicator_value="198.51.100.1").all()
        self.assertEqual(len(indicators), 1, "Database should contain exactly one 198.51.100.1 record")

    def test_section_13_case_3_reuse_existing_indicator(self):
        """Case 3: Second report with existing IOC (indicator reused, both reports linked)."""
        self._login(self.client)

        # Upload Report 1 with 203.0.113.50
        self.client.post(
            "/threat-report-upload",
            data={
                "title": "TEST_Report_Alpha",
                "summary": "First sighting of suspicious C2 IP 203.0.113.50.",
                "category": "C2",
                "severity": "critical",
                "tlp_level": "red",
                "sectors": "Banking",
            },
            follow_redirects=True
        )

        # Upload Report 2 also referencing 203.0.113.50
        self.client.post(
            "/threat-report-upload",
            data={
                "title": "TEST_Report_Beta",
                "summary": "Corroborated malicious activity connecting back to 203.0.113.50.",
                "category": "C2",
                "severity": "high",
                "tlp_level": "amber",
                "sectors": "Government",
            },
            follow_redirects=True
        )

        indicators = ThreatIndicator.query.filter_by(indicator_value="203.0.113.50").all()
        self.assertEqual(len(indicators), 1, "Indicator must be reused without creating duplicates")

        rep_alpha = ThreatReport.query.filter_by(title="TEST_Report_Alpha").first()
        rep_beta = ThreatReport.query.filter_by(title="TEST_Report_Beta").first()

        self.assertIn(indicators[0], rep_alpha.indicators)
        self.assertIn(indicators[0], rep_beta.indicators)

        # Confirm 2 association rows in report_indicator
        associations = db.session.execute(
            report_indicator.select().where(report_indicator.c.indicator_id == indicators[0].id)
        ).fetchall()
        self.assertEqual(len(associations), 2, "Both reports must be associated with the single indicator")

    def test_section_13_case_4_empty_description(self):
        """Case 4: Empty description (handled gracefully without errors)."""
        self._login(self.client)

        response = self.client.post(
            "/threat-report-upload",
            data={
                "title": "TEST_Empty_Summary_Report",
                "summary": "",
                "category": "General",
                "severity": "low",
                "tlp_level": "white",
                "sectors": "Other",
            },
            follow_redirects=True
        )
        self.assertEqual(response.status_code, 200)

        report = ThreatReport.query.filter_by(title="TEST_Empty_Summary_Report").first()
        self.assertIsNotNone(report)
        self.assertEqual(len(report.indicators), 0)

    def test_section_13_case_5_transaction_rollback(self):
        """Case 5: Transaction rollback test (simulating database exception)."""
        self._login(self.client)

        initial_reports_count = ThreatReport.query.filter(ThreatReport.title.like("TEST_%")).count()
        initial_indicators_count = ThreatIndicator.query.filter_by(indicator_value="rollback-test.org").count()

        # We can simulate an error during upload by temporarily monkeypatching or testing with a database error
        # In threat_report_upload, if db.session.commit() raises an exception, it rolls back
        from flask import session
        from unittest.mock import patch

        with self.client:
            self._login(self.client)
            with patch("app.dashboard.routes.db.session.commit", side_effect=RuntimeError("Simulated DB failure")):
                response = self.client.post(
                    "/threat-report-upload",
                    data={
                        "title": "TEST_Rollback_Trigger",
                        "summary": "Payload domain rollback-test.org was observed.",
                        "category": "Phishing",
                        "severity": "medium",
                        "tlp_level": "green",
                        "sectors": "Retail",
                    },
                    follow_redirects=True
                )
                self.assertEqual(response.status_code, 200)
                flashes = session.get("_flashes", [])
                flash_texts = [msg for cat, msg in flashes]
                self.assertTrue(any("Error processing threat report" in m for m in flash_texts))

        # Verify no partial report or indicator was committed
        final_reports_count = ThreatReport.query.filter(ThreatReport.title.like("TEST_%")).count()
        final_indicators_count = ThreatIndicator.query.filter_by(indicator_value="rollback-test.org").count()

        self.assertEqual(initial_reports_count, final_reports_count, "No report should be committed on rollback")
        self.assertEqual(initial_indicators_count, final_indicators_count, "No indicator should be committed on rollback")


if __name__ == "__main__":
    unittest.main()
