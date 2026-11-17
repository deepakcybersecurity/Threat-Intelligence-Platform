"""
Comprehensive Unit and Integration Tests for Task 4: IOC Correlation Engine
=============================================================================
Covers all required test scenarios:
1.  IOC with no relationships (empty lists, 0 counts)
2.  IOC associated with one Threat Report
3.  IOC associated with multiple Threat Reports
4.  IOC associated with Malware
5.  Two IOCs sharing the same Threat Report
6.  Two IOCs sharing the same Malware
7.  IOC sharing both Report and Malware ("Shared Threat Report + Shared Malware")
8.  Duplicate correlation prevention (single entry in related_indicators)
9.  Selected IOC self-exclusion (target indicator not in related_indicators)
10. Invalid indicator ID (handles missing/invalid ID safely)
11. Unauthorized access (unauthenticated request rejected/redirected)
12. Read-only verification: severity, confidence_score, status, source unchanged
13. Empty database relationships handled safely without exception
14. Multi-entity aggregation across multiple reports and malware records
15. API route response structure verification
"""

import unittest
from datetime import datetime

from app import create_app, db
from app.models import User, ThreatIndicator, ThreatReport, Malware
from app.services.ioc_correlation import (
    correlate_indicator,
    correlate_indicator_by_id
)


class TestIOCCorrelationEngine(unittest.TestCase):

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
        self.user = User.query.filter_by(email="corr_analyst@test.com").first()
        if not self.user:
            self.user = User(
                username="corr_analyst",
                email="corr_analyst@test.com",
                password_hash="pbkdf2:sha256:dummyhash",
                role="analyst"
            )
            db.session.add(self.user)
            db.session.commit()

        # Clean existing test entities
        self._cleanup_test_data()

    def tearDown(self):
        db.session.rollback()
        self._cleanup_test_data()
        self.app_context.pop()

    def _cleanup_test_data(self):
        indicators = ThreatIndicator.query.filter(
            ThreatIndicator.indicator_value.like("corr_test_%")
        ).all()
        for ind in indicators:
            ind.reports.clear()
            ind.malwares.clear()
            db.session.delete(ind)

        reports = ThreatReport.query.filter(
            ThreatReport.title.like("CORR_TEST_%")
        ).all()
        for rep in reports:
            rep.indicators.clear()
            rep.malwares.clear()
            db.session.delete(rep)

        malwares = Malware.query.filter(
            Malware.malware_name.like("CORR_TEST_%")
        ).all()
        for mal in malwares:
            mal.indicators.clear()
            mal.reports.clear()
            db.session.delete(mal)

        db.session.commit()

    def _login(self, client):
        with client.session_transaction() as sess:
            sess["_user_id"] = str(self.user.id)
            sess["_fresh"] = True

    def _create_indicator(self, value="corr_test_ip_1", ioc_type="ipv4", severity="High", confidence=75):
        ind = ThreatIndicator(
            indicator_value=value,
            indicator_type=ioc_type,
            confidence_score=confidence,
            severity=severity,
            status="Active",
            source="Threat Report",
            added_by_user_id=self.user.id
        )
        db.session.add(ind)
        db.session.commit()
        return ind

    def _create_report(self, title="CORR_TEST_Report_Alpha", category="APT", severity="High"):
        rep = ThreatReport(
            user_id=self.user.id,
            title=title,
            description="Correlation testing description.",
            category=category,
            severity=severity,
            tlp_level="amber",
            target_sector="Defense"
        )
        db.session.add(rep)
        db.session.commit()
        return rep

    def _create_malware(self, name="CORR_TEST_Trojan", family="TestFamily", malware_type="Trojan"):
        mal = Malware(
            malware_name=name,
            malware_family=family,
            malware_type=malware_type,
            platform="Windows",
            severity="Critical",
            risk_score=85,
            mitre_attack_id="T1059",
            cve_id="CVE-2026-9999",
            created_by_user_id=self.user.id
        )
        db.session.add(mal)
        db.session.commit()
        return mal

    # -------------------------------------------------------------------------
    # TEST 1: IOC with no relationships
    # -------------------------------------------------------------------------
    def test_1_ioc_with_no_relationships(self):
        """TEST 1: IOC with no relationships returns empty lists and 0 counts."""
        ind = self._create_indicator("corr_test_isolated.org", "domain")
        res = correlate_indicator(ind)

        self.assertTrue(res["success"])
        self.assertEqual(res["reports"], [])
        self.assertEqual(res["malware"], [])
        self.assertEqual(res["related_indicators"], [])
        self.assertEqual(res["summary"]["report_count"], 0)
        self.assertEqual(res["summary"]["malware_count"], 0)
        self.assertEqual(res["summary"]["related_indicator_count"], 0)
        self.assertEqual(res["correlation_score"], 0)

    # -------------------------------------------------------------------------
    # TEST 2: IOC associated with one Threat Report
    # -------------------------------------------------------------------------
    def test_2_ioc_associated_with_one_report(self):
        """TEST 2: Verify direct Threat Report association appears correctly."""
        ind = self._create_indicator("corr_test_ip_single", "ipv4")
        rep = self._create_report("CORR_TEST_Single_Report", "Phishing", "Medium")

        ind.reports.append(rep)
        db.session.commit()

        res = correlate_indicator_by_id(ind.id)
        self.assertTrue(res["success"])
        self.assertEqual(res["summary"]["report_count"], 1)
        self.assertEqual(len(res["reports"]), 1)
        self.assertEqual(res["reports"][0]["id"], rep.id)
        self.assertEqual(res["reports"][0]["title"], "CORR_TEST_Single_Report")

    # -------------------------------------------------------------------------
    # TEST 3: IOC associated with multiple Threat Reports
    # -------------------------------------------------------------------------
    def test_3_ioc_associated_with_multiple_reports(self):
        """TEST 3: Verify all multiple associated Threat Reports appear."""
        ind = self._create_indicator("corr_test_ip_multi", "ipv4")
        rep1 = self._create_report("CORR_TEST_Multi_1")
        rep2 = self._create_report("CORR_TEST_Multi_2")
        rep3 = self._create_report("CORR_TEST_Multi_3")

        ind.reports.extend([rep1, rep2, rep3])
        db.session.commit()

        res = correlate_indicator_by_id(ind.id)
        self.assertTrue(res["success"])
        self.assertEqual(res["summary"]["report_count"], 3)
        self.assertEqual(len(res["reports"]), 3)
        report_ids = [r["id"] for r in res["reports"]]
        self.assertIn(rep1.id, report_ids)
        self.assertIn(rep2.id, report_ids)
        self.assertIn(rep3.id, report_ids)

    # -------------------------------------------------------------------------
    # TEST 4: IOC associated with Malware
    # -------------------------------------------------------------------------
    def test_4_ioc_associated_with_malware(self):
        """TEST 4: Verify direct Malware association appears correctly."""
        ind = self._create_indicator("corr_test_hash_mal", "sha256")
        mal = self._create_malware("CORR_TEST_Ransomware", "LockBit", "Ransomware")

        ind.malwares.append(mal)
        db.session.commit()

        res = correlate_indicator_by_id(ind.id)
        self.assertTrue(res["success"])
        self.assertEqual(res["summary"]["malware_count"], 1)
        self.assertEqual(len(res["malware"]), 1)
        self.assertEqual(res["malware"][0]["name"], "CORR_TEST_Ransomware")
        self.assertEqual(res["malware"][0]["family"], "LockBit")

    # -------------------------------------------------------------------------
    # TEST 5: Two IOCs sharing the same Threat Report
    # -------------------------------------------------------------------------
    def test_5_shared_threat_report_correlation(self):
        """TEST 5: Two IOCs sharing the same Threat Report correlate as related."""
        ind1 = self._create_indicator("corr_test_pair_a", "ipv4")
        ind2 = self._create_indicator("corr_test_pair_b", "domain")
        rep = self._create_report("CORR_TEST_Shared_Report")

        rep.indicators.extend([ind1, ind2])
        db.session.commit()

        res = correlate_indicator_by_id(ind1.id)
        self.assertTrue(res["success"])
        self.assertEqual(res["summary"]["related_indicator_count"], 1)

        related = res["related_indicators"][0]
        self.assertEqual(related["id"], ind2.id)
        self.assertEqual(related["value"], "corr_test_pair_b")
        self.assertEqual(related["relationship_reason"], "Shared Threat Report")

    # -------------------------------------------------------------------------
    # TEST 6: Two IOCs sharing the same Malware
    # -------------------------------------------------------------------------
    def test_6_shared_malware_correlation(self):
        """TEST 6: Two IOCs sharing the same Malware correlate as related."""
        ind1 = self._create_indicator("corr_test_mal_pair_a", "ipv4")
        ind2 = self._create_indicator("corr_test_mal_pair_b", "sha256")
        mal = self._create_malware("CORR_TEST_Shared_Malware")

        mal.indicators.extend([ind1, ind2])
        db.session.commit()

        res = correlate_indicator_by_id(ind1.id)
        self.assertTrue(res["success"])
        self.assertEqual(res["summary"]["related_indicator_count"], 1)

        related = res["related_indicators"][0]
        self.assertEqual(related["id"], ind2.id)
        self.assertEqual(related["relationship_reason"], "Shared Malware")

    # -------------------------------------------------------------------------
    # TEST 7: IOC sharing both Report and Malware
    # -------------------------------------------------------------------------
    def test_7_shared_both_report_and_malware(self):
        """TEST 7: Verify reason is 'Shared Threat Report + Shared Malware' when sharing both."""
        ind1 = self._create_indicator("corr_test_both_a", "ipv4")
        ind2 = self._create_indicator("corr_test_both_b", "domain")
        rep = self._create_report("CORR_TEST_Both_Report")
        mal = self._create_malware("CORR_TEST_Both_Malware")

        rep.indicators.extend([ind1, ind2])
        mal.indicators.extend([ind1, ind2])
        db.session.commit()

        res = correlate_indicator_by_id(ind1.id)
        self.assertTrue(res["success"])
        self.assertEqual(res["summary"]["related_indicator_count"], 1)

        related = res["related_indicators"][0]
        self.assertEqual(related["id"], ind2.id)
        self.assertEqual(related["relationship_reason"], "Shared Threat Report + Shared Malware")
        self.assertGreater(related["relationship_strength"], 1)

    # -------------------------------------------------------------------------
    # TEST 8: Duplicate correlation prevention
    # -------------------------------------------------------------------------
    def test_8_duplicate_correlation_prevention(self):
        """TEST 8: IOC sharing multiple reports and malware appears only ONCE in related list."""
        ind1 = self._create_indicator("corr_test_dup_a", "ipv4")
        ind2 = self._create_indicator("corr_test_dup_b", "domain")

        rep1 = self._create_report("CORR_TEST_Dup_Report_1")
        rep2 = self._create_report("CORR_TEST_Dup_Report_2")
        mal1 = self._create_malware("CORR_TEST_Dup_Malware_1")

        rep1.indicators.extend([ind1, ind2])
        rep2.indicators.extend([ind1, ind2])
        mal1.indicators.extend([ind1, ind2])
        db.session.commit()

        res = correlate_indicator_by_id(ind1.id)
        self.assertTrue(res["success"])
        self.assertEqual(res["summary"]["related_indicator_count"], 1)
        self.assertEqual(len(res["related_indicators"]), 1, "ind2 must appear exactly once")
        self.assertEqual(len(res["related_indicators"][0]["shared_reports"]), 2)
        self.assertEqual(len(res["related_indicators"][0]["shared_malware"]), 1)

    # -------------------------------------------------------------------------
    # TEST 9: Selected IOC self-exclusion
    # -------------------------------------------------------------------------
    def test_9_selected_ioc_exclusion(self):
        """TEST 9: Target indicator must never appear in its own related_indicators list."""
        ind1 = self._create_indicator("corr_test_self_ex", "ipv4")
        rep = self._create_report("CORR_TEST_Self_Ex_Report")
        rep.indicators.append(ind1)
        db.session.commit()

        res = correlate_indicator_by_id(ind1.id)
        self.assertTrue(res["success"])
        related_ids = [r["id"] for r in res["related_indicators"]]
        self.assertNotIn(ind1.id, related_ids, "Target IOC must be excluded from related indicators")

    # -------------------------------------------------------------------------
    # TEST 10: Invalid indicator ID
    # -------------------------------------------------------------------------
    def test_10_invalid_indicator_id(self):
        """TEST 10: Non-existent or invalid indicator ID handled safely."""
        res = correlate_indicator_by_id(99999999)
        self.assertFalse(res["success"])
        self.assertEqual(res["error"], "Indicator not found")

        res_none = correlate_indicator(None)
        self.assertFalse(res_none["success"])

    # -------------------------------------------------------------------------
    # TEST 11: Unauthorized access
    # -------------------------------------------------------------------------
    def test_11_unauthorized_access(self):
        """TEST 11: Unauthenticated request to correlation route is rejected/redirected."""
        ind = self._create_indicator("corr_test_auth_check", "ipv4")

        unauth_client = self.app.test_client()
        response = unauth_client.get(f"/threat-indicator/{ind.id}/correlations")
        self.assertIn(response.status_code, [302, 401])

    # -------------------------------------------------------------------------
    # TEST 12: Severity, confidence, risk values remain unchanged
    # -------------------------------------------------------------------------
    def test_12_read_only_values_remain_unchanged(self):
        """TEST 12: Correlation engine does not mutate severity, confidence, or status."""
        ind = self._create_indicator(
            "corr_test_readonly",
            "ipv4",
            severity="Critical",
            confidence=92
        )
        rep = self._create_report("CORR_TEST_ReadOnly_Report")
        ind.reports.append(rep)
        db.session.commit()

        initial_severity = ind.severity
        initial_confidence = ind.confidence_score
        initial_status = ind.status

        # Execute correlation
        correlate_indicator_by_id(ind.id)

        # Refresh from database and assert unchanged
        db.session.refresh(ind)
        self.assertEqual(ind.severity, initial_severity)
        self.assertEqual(ind.confidence_score, initial_confidence)
        self.assertEqual(ind.status, initial_status)

    # -------------------------------------------------------------------------
    # TEST 13: Empty database relationships
    # -------------------------------------------------------------------------
    def test_13_empty_database_relationships(self):
        """TEST 13: Correlation returns safely without exceptions when relationships are empty."""
        ind = self._create_indicator("corr_test_empty_db", "ipv4")
        try:
            res = correlate_indicator_by_id(ind.id)
            self.assertTrue(res["success"])
            self.assertEqual(res["reports"], [])
            self.assertEqual(res["malware"], [])
            self.assertEqual(res["related_indicators"], [])
        except Exception as e:
            self.fail(f"Correlation raised exception on empty relationships: {str(e)}")

    # -------------------------------------------------------------------------
    # TEST 14: Multi-entity aggregation across multiple reports and malware
    # -------------------------------------------------------------------------
    def test_14_complex_multi_entity_aggregation(self):
        """TEST 14: Complex graph of multiple indicators, reports, and malware aggregates accurately."""
        target = self._create_indicator("corr_target_c2", "ipv4")
        peer1 = self._create_indicator("corr_peer_domain_1", "domain")
        peer2 = self._create_indicator("corr_peer_hash_2", "sha256")
        peer3 = self._create_indicator("corr_peer_url_3", "url")

        r1 = self._create_report("CORR_TEST_Complex_R1")
        r2 = self._create_report("CORR_TEST_Complex_R2")
        m1 = self._create_malware("CORR_TEST_Complex_M1")

        # target shares r1 with peer1
        r1.indicators.extend([target, peer1])
        # target shares r2 with peer1 and peer2
        r2.indicators.extend([target, peer1, peer2])
        # target shares m1 with peer2 and peer3
        m1.indicators.extend([target, peer2, peer3])
        db.session.commit()

        res = correlate_indicator_by_id(target.id)
        self.assertTrue(res["success"])
        self.assertEqual(res["summary"]["report_count"], 2)
        self.assertEqual(res["summary"]["malware_count"], 1)
        self.assertEqual(res["summary"]["related_indicator_count"], 3)

        related_by_id = {r["id"]: r for r in res["related_indicators"]}
        # peer1 has shared reports (r1, r2)
        self.assertEqual(related_by_id[peer1.id]["relationship_reason"], "Shared Threat Report")
        self.assertEqual(len(related_by_id[peer1.id]["shared_reports"]), 2)

        # peer2 has both shared report (r2) and shared malware (m1)
        self.assertEqual(related_by_id[peer2.id]["relationship_reason"], "Shared Threat Report + Shared Malware")

        # peer3 has only shared malware (m1)
        self.assertEqual(related_by_id[peer3.id]["relationship_reason"], "Shared Malware")

    # -------------------------------------------------------------------------
    # TEST 15: API route response structure verification
    # -------------------------------------------------------------------------
    def test_15_api_route_response_structure(self):
        """TEST 15: Authenticated GET /threat-indicator/<id>/correlations returns valid JSON structure."""
        self._login(self.client)

        ind = self._create_indicator("corr_test_api_check", "ipv4")
        rep = self._create_report("CORR_TEST_API_Report")
        ind.reports.append(rep)
        db.session.commit()

        response = self.client.get(f"/threat-indicator/{ind.id}/correlations")
        self.assertEqual(response.status_code, 200)

        data = response.get_json()
        self.assertIsNotNone(data)
        self.assertTrue(data["success"])
        self.assertIn("indicator", data)
        self.assertIn("summary", data)
        self.assertIn("reports", data)
        self.assertIn("malware", data)
        self.assertIn("related_indicators", data)
        self.assertIn("correlation_score", data)
        self.assertEqual(data["indicator"]["value"], "corr_test_api_check")
        self.assertEqual(data["summary"]["report_count"], 1)


if __name__ == "__main__":
    unittest.main()
