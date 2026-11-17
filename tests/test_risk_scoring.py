"""
Unit and Integration Tests for Task 5: IOC Risk Scoring Engine
===============================================================
Verifies:
1. LOW severity indicator contribution (+10)
2. MEDIUM severity indicator contribution (+25)
3. HIGH severity indicator contribution (+40)
4. CRITICAL severity indicator contribution (+50)
5. Confidence score contribution (confidence_score * 0.20, max 20)
6. Correlation contribution (+5 report, +10 malware, capped at 20)
7. External enrichment contribution (AbuseIPDB, VirusTotal, OTX, max 10)
8. Recency contribution (<=7d: +5, 8-30d: +3, 31-90d: +1, >90d: +0)
9. Active status contribution (+5)
10. Inactive / non-active status handling (+0)
11. Missing last_seen_at handling (+0)
12. Missing enrichment data handling (+0)
13. Missing correlation data handling (+0)
14. Final score capped at 100
15. Final score never below 0
16. Correct risk level mapping (LOW, MEDIUM, HIGH, CRITICAL)
17. Deterministic calculation consistency
18. Nonexistent indicator ID handling (graceful error / 404)
19. Unauthorized route access (redirect to login)
20. Authenticated GET route JSON schema and values
21. POST route persistence into ThreatIndicator.risk_score
22. Read-only verification: confidence_score, severity, status, source unaltered
"""

import json
import unittest
from datetime import datetime, timedelta

from app import create_app, db
from app.models import User, ThreatIndicator, ThreatReport, Malware, APICache
from app.services.risk_scoring import (
    get_risk_level,
    calculate_indicator_risk,
    calculate_indicator_risk_by_id,
    save_indicator_risk,
)


class TestRiskScoringEngine(unittest.TestCase):

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
        self.user = User.query.filter_by(email="risk_analyst@test.com").first()
        if not self.user:
            self.user = User(
                username="risk_analyst",
                email="risk_analyst@test.com",
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
        indicators = ThreatIndicator.query.filter(
            ThreatIndicator.indicator_value.like("risk_test_%")
        ).all()
        for ind in indicators:
            ind.reports.clear()
            ind.malwares.clear()
            db.session.delete(ind)

        reports = ThreatReport.query.filter(
            ThreatReport.title.like("RISK_TEST_%")
        ).all()
        for rep in reports:
            rep.indicators.clear()
            rep.malwares.clear()
            db.session.delete(rep)

        malwares = Malware.query.filter(
            Malware.malware_name.like("RISK_TEST_%")
        ).all()
        for mal in malwares:
            mal.indicators.clear()
            mal.reports.clear()
            db.session.delete(mal)

        caches = APICache.query.filter(
            APICache.endpoint.like("%:risk_test_%")
        ).all()
        for c in caches:
            db.session.delete(c)

        db.session.commit()

    def _login(self, client):
        with client.session_transaction() as sess:
            sess["_user_id"] = str(self.user.id)
            sess["_fresh"] = True

    def _create_indicator(
        self,
        value="risk_test_ip_1",
        ioc_type="ipv4",
        severity="Medium",
        confidence=50,
        status="Active",
        last_seen=None
    ):
        ind = ThreatIndicator(
            indicator_value=value,
            indicator_type=ioc_type,
            confidence_score=confidence,
            severity=severity,
            status=status,
            source="Threat Report",
            added_by_user_id=self.user.id,
            last_seen_at=last_seen
        )
        db.session.add(ind)
        db.session.commit()
        return ind

    # -------------------------------------------------------------------------
    # TEST 1-4: Severity Contribution (Low, Medium, High, Critical)
    # -------------------------------------------------------------------------
    def test_01_low_severity_contribution(self):
        """TEST 1: Low severity contributes exactly 10 points."""
        ind = self._create_indicator(value="risk_test_sev_low", severity="Low", confidence=0, status="Inactive")
        res = calculate_indicator_risk(ind)
        self.assertTrue(res["success"])
        self.assertEqual(res["breakdown"]["severity"], 10)
        self.assertEqual(res["risk_score"], 10)
        self.assertEqual(res["risk_level"], "LOW")

    def test_02_medium_severity_contribution(self):
        """TEST 2: Medium severity contributes exactly 25 points."""
        ind = self._create_indicator(value="risk_test_sev_med", severity="Medium", confidence=0, status="Inactive")
        res = calculate_indicator_risk(ind)
        self.assertTrue(res["success"])
        self.assertEqual(res["breakdown"]["severity"], 25)
        self.assertEqual(res["risk_score"], 25)
        self.assertEqual(res["risk_level"], "MEDIUM")

    def test_03_high_severity_contribution(self):
        """TEST 3: High severity contributes exactly 40 points."""
        ind = self._create_indicator(value="risk_test_sev_high", severity="High", confidence=0, status="Inactive")
        res = calculate_indicator_risk(ind)
        self.assertTrue(res["success"])
        self.assertEqual(res["breakdown"]["severity"], 40)
        self.assertEqual(res["risk_score"], 40)
        self.assertEqual(res["risk_level"], "MEDIUM")

    def test_04_critical_severity_contribution(self):
        """TEST 4: Critical severity contributes exactly 50 points."""
        ind = self._create_indicator(value="risk_test_sev_crit", severity="Critical", confidence=0, status="Inactive")
        res = calculate_indicator_risk(ind)
        self.assertTrue(res["success"])
        self.assertEqual(res["breakdown"]["severity"], 50)
        self.assertEqual(res["risk_score"], 50)
        self.assertEqual(res["risk_level"], "HIGH")

    # -------------------------------------------------------------------------
    # TEST 5: Confidence Score Contribution
    # -------------------------------------------------------------------------
    def test_05_confidence_score_contribution(self):
        """TEST 5: Confidence score scaled by 0.20 contributes up to 20 points."""
        ind_100 = self._create_indicator(value="risk_test_conf_100", severity="Low", confidence=100, status="Inactive")
        res_100 = calculate_indicator_risk(ind_100)
        self.assertEqual(res_100["breakdown"]["confidence"], 20)

        ind_50 = self._create_indicator(value="risk_test_conf_50", severity="Low", confidence=50, status="Inactive")
        res_50 = calculate_indicator_risk(ind_50)
        self.assertEqual(res_50["breakdown"]["confidence"], 10)

        ind_0 = self._create_indicator(value="risk_test_conf_0", severity="Low", confidence=0, status="Inactive")
        res_0 = calculate_indicator_risk(ind_0)
        self.assertEqual(res_0["breakdown"]["confidence"], 0)

    # -------------------------------------------------------------------------
    # TEST 6: Correlation Contribution
    # -------------------------------------------------------------------------
    def test_06_correlation_contribution(self):
        """TEST 6: Correlation contribution from shared reports (+5) and malware (+10), capped at 20."""
        ind1 = self._create_indicator(value="risk_test_corr_1", severity="Low", confidence=0, status="Inactive")
        ind2 = self._create_indicator(value="risk_test_corr_2", severity="Low", confidence=0, status="Inactive")

        # Link both to a Threat Report (+5)
        rep = ThreatReport(
            user_id=self.user.id,
            title="RISK_TEST_Report_Alpha",
            description="Test report narrative",
            category="APT",
            severity="High",
            tlp_level="amber",
            target_sector="Financial"
        )
        rep.indicators.extend([ind1, ind2])
        db.session.add(rep)
        db.session.commit()

        res_rep = calculate_indicator_risk(ind1)
        self.assertEqual(res_rep["breakdown"]["correlation"], 5)

        # Link both also to Malware (+10, combined 15)
        mal = Malware(
            malware_name="RISK_TEST_Malware_1",
            malware_type="Trojan",
            platform="Windows",
            severity="Critical",
            created_by_user_id=self.user.id
        )
        mal.indicators.extend([ind1, ind2])
        db.session.add(mal)
        db.session.commit()

        res_both = calculate_indicator_risk(ind1)
        self.assertEqual(res_both["breakdown"]["correlation"], 15)

    # -------------------------------------------------------------------------
    # TEST 7: Enrichment Contribution (AbuseIPDB, VirusTotal, OTX)
    # -------------------------------------------------------------------------
    def test_07_enrichment_contribution(self):
        """TEST 7: Enrichment contribution from cached AbuseIPDB, VirusTotal, and OTX."""
        # 7a: AbuseIPDB score > 80 -> +10
        ind_ip = self._create_indicator(value="risk_test_abuse_1", ioc_type="ipv4", severity="Low", confidence=0, status="Inactive")
        cache_ip = APICache(
            api_name="AbuseIPDB",
            endpoint="ipv4:risk_test_abuse_1",
            response_data=json.dumps({"abuse_confidence_score": 85}),
            expires_at=datetime.utcnow() + timedelta(hours=24)
        )
        db.session.add(cache_ip)
        db.session.commit()

        res_ip = calculate_indicator_risk(ind_ip)
        self.assertEqual(res_ip["breakdown"]["enrichment"], 10)

        # 7b: VirusTotal high detections -> +10
        ind_vt = self._create_indicator(value="risk_test_hash_1", ioc_type="sha256", severity="Low", confidence=0, status="Inactive")
        cache_vt = APICache(
            api_name="VirusTotal",
            endpoint="sha256:risk_test_hash_1",
            response_data=json.dumps({
                "malicious_count": 15,
                "suspicious_count": 2,
                "harmless_count": 50,
                "undetected_count": 3
            }),
            expires_at=datetime.utcnow() + timedelta(hours=24)
        )
        db.session.add(cache_vt)
        db.session.commit()

        res_vt = calculate_indicator_risk(ind_vt)
        self.assertEqual(res_vt["breakdown"]["enrichment"], 10)

        # 7c: OTX moderate activity -> +3
        ind_otx = self._create_indicator(value="risk_test_otx_1", ioc_type="domain", severity="Low", confidence=0, status="Inactive")
        cache_otx = APICache(
            api_name="AlienVault OTX",
            endpoint="domain:risk_test_otx_1",
            response_data=json.dumps({"pulse_count": 5}),
            expires_at=datetime.utcnow() + timedelta(hours=24)
        )
        db.session.add(cache_otx)
        db.session.commit()

        res_otx = calculate_indicator_risk(ind_otx)
        self.assertEqual(res_otx["breakdown"]["enrichment"], 3)

    # -------------------------------------------------------------------------
    # TEST 8: Recency Contribution
    # -------------------------------------------------------------------------
    def test_08_recency_contribution(self):
        """TEST 8: Recency contribution based on days since last_seen_at."""
        now = datetime.utcnow()

        # <= 7 days: +5
        ind_7d = self._create_indicator(value="risk_test_rec_7", severity="Low", confidence=0, status="Inactive", last_seen=now - timedelta(days=2))
        res_7d = calculate_indicator_risk(ind_7d)
        self.assertEqual(res_7d["breakdown"]["recency"], 5)

        # 8-30 days: +3
        ind_30d = self._create_indicator(value="risk_test_rec_30", severity="Low", confidence=0, status="Inactive", last_seen=now - timedelta(days=15))
        res_30d = calculate_indicator_risk(ind_30d)
        self.assertEqual(res_30d["breakdown"]["recency"], 3)

        # 31-90 days: +1
        ind_90d = self._create_indicator(value="risk_test_rec_90", severity="Low", confidence=0, status="Inactive", last_seen=now - timedelta(days=60))
        res_90d = calculate_indicator_risk(ind_90d)
        self.assertEqual(res_90d["breakdown"]["recency"], 1)

        # > 90 days: +0
        ind_old = self._create_indicator(value="risk_test_rec_old", severity="Low", confidence=0, status="Inactive", last_seen=now - timedelta(days=120))
        res_old = calculate_indicator_risk(ind_old)
        self.assertEqual(res_old["breakdown"]["recency"], 0)

    # -------------------------------------------------------------------------
    # TEST 9-10: Status Contribution
    # -------------------------------------------------------------------------
    def test_09_active_status_contribution(self):
        """TEST 9: Active status adds exactly +5 points."""
        ind = self._create_indicator(value="risk_test_stat_active", severity="Low", confidence=0, status="Active")
        res = calculate_indicator_risk(ind)
        self.assertEqual(res["breakdown"]["status"], 5)

    def test_10_inactive_status_handling(self):
        """TEST 10: Inactive, Expired, or False Positive statuses add +0 points."""
        ind_inact = self._create_indicator(value="risk_test_stat_inact", severity="Low", confidence=0, status="Inactive")
        self.assertEqual(calculate_indicator_risk(ind_inact)["breakdown"]["status"], 0)

        ind_exp = self._create_indicator(value="risk_test_stat_exp", severity="Low", confidence=0, status="Expired")
        self.assertEqual(calculate_indicator_risk(ind_exp)["breakdown"]["status"], 0)

        ind_fp = self._create_indicator(value="risk_test_stat_fp", severity="Low", confidence=0, status="False Positive")
        self.assertEqual(calculate_indicator_risk(ind_fp)["breakdown"]["status"], 0)

    # -------------------------------------------------------------------------
    # TEST 11-13: Missing Data Handling
    # -------------------------------------------------------------------------
    def test_11_missing_last_seen_at(self):
        """TEST 11: Missing last_seen_at (None) contributes +0 recency points safely."""
        ind = self._create_indicator(value="risk_test_null_last_seen", severity="Low", confidence=0, status="Inactive", last_seen=None)
        res = calculate_indicator_risk(ind)
        self.assertEqual(res["breakdown"]["recency"], 0)

    def test_12_missing_enrichment_data(self):
        """TEST 12: Missing enrichment data contributes +0 enrichment points safely."""
        ind = self._create_indicator(value="risk_test_no_enrich", ioc_type="ipv4", severity="Low", confidence=0, status="Inactive")
        res = calculate_indicator_risk(ind)
        self.assertEqual(res["breakdown"]["enrichment"], 0)

    def test_13_missing_correlation_data(self):
        """TEST 13: Missing correlation links contributes +0 correlation points safely."""
        ind = self._create_indicator(value="risk_test_no_corr", severity="Low", confidence=0, status="Inactive")
        res = calculate_indicator_risk(ind)
        self.assertEqual(res["breakdown"]["correlation"], 0)

    # -------------------------------------------------------------------------
    # TEST 14-15: Clamping Constraints (0 <= score <= 100)
    # -------------------------------------------------------------------------
    def test_14_final_score_capped_at_100(self):
        """TEST 14: Final score is clamped at 100 even if raw sum exceeds 100."""
        # Critical (50) + Conf 100 (20) + Recency (5) + Status (5) = 80
        # + Correlation (20) + Enrichment (10) = 110 raw -> clamped to 100
        ind = self._create_indicator(
            value="risk_test_cap_100",
            ioc_type="ipv4",
            severity="Critical",
            confidence=100,
            status="Active",
            last_seen=datetime.utcnow()
        )
        # Add cached enrichment (+10)
        cache = APICache(
            api_name="AbuseIPDB",
            endpoint="ipv4:risk_test_cap_100",
            response_data=json.dumps({"abuse_confidence_score": 99}),
            expires_at=datetime.utcnow() + timedelta(hours=24)
        )
        db.session.add(cache)

        # Add correlated indicators to reach 20 correlation points
        others = [self._create_indicator(value=f"risk_test_other_{i}", severity="High") for i in range(4)]
        rep = ThreatReport(
            user_id=self.user.id,
            title="RISK_TEST_Cap_Report",
            description="Cap test report",
            category="APT",
            severity="Critical",
            tlp_level="amber",
            target_sector="Financial"
        )
        rep.indicators.append(ind)
        rep.indicators.extend(others)
        db.session.add(rep)
        db.session.commit()

        res = calculate_indicator_risk(ind)
        self.assertEqual(res["risk_score"], 100)
        self.assertEqual(res["risk_level"], "CRITICAL")

    def test_15_final_score_never_below_zero(self):
        """TEST 15: Final score is never negative."""
        ind = self._create_indicator(value="risk_test_floor_0", severity="Low", confidence=0, status="Inactive", last_seen=None)
        res = calculate_indicator_risk(ind)
        self.assertGreaterEqual(res["risk_score"], 0)

    # -------------------------------------------------------------------------
    # TEST 16: Risk Level Mapping
    # -------------------------------------------------------------------------
    def test_16_risk_level_mapping(self):
        """TEST 16: Correct risk level mapping across boundary thresholds."""
        self.assertEqual(get_risk_level(0), "LOW")
        self.assertEqual(get_risk_level(24), "LOW")
        self.assertEqual(get_risk_level(25), "MEDIUM")
        self.assertEqual(get_risk_level(49), "MEDIUM")
        self.assertEqual(get_risk_level(50), "HIGH")
        self.assertEqual(get_risk_level(74), "HIGH")
        self.assertEqual(get_risk_level(75), "CRITICAL")
        self.assertEqual(get_risk_level(100), "CRITICAL")

    # -------------------------------------------------------------------------
    # TEST 17: Deterministic Consistency
    # -------------------------------------------------------------------------
    def test_17_deterministic_calculation(self):
        """TEST 17: Repeated calculations return identical scores and breakdown."""
        ind = self._create_indicator(value="risk_test_det_1", severity="High", confidence=70, status="Active", last_seen=datetime.utcnow())
        res1 = calculate_indicator_risk(ind)
        res2 = calculate_indicator_risk(ind)
        self.assertEqual(res1["risk_score"], res2["risk_score"])
        self.assertEqual(res1["breakdown"], res2["breakdown"])
        self.assertEqual(res1["risk_level"], res2["risk_level"])

    # -------------------------------------------------------------------------
    # TEST 18: Nonexistent Indicator ID
    # -------------------------------------------------------------------------
    def test_18_nonexistent_indicator(self):
        """TEST 18: Nonexistent indicator returns safe error dict / 404."""
        res = calculate_indicator_risk_by_id(999999)
        self.assertFalse(res["success"])
        self.assertIn("not found", res["error"].lower())

    # -------------------------------------------------------------------------
    # TEST 19: Unauthorized Route Access
    # -------------------------------------------------------------------------
    def test_19_unauthorized_route_access(self):
        """TEST 19: Unauthenticated request to /risk-score route is redirected."""
        ind = self._create_indicator(value="risk_test_auth_req")
        unauthed_client = self.app.test_client()
        response = unauthed_client.get(f"/threat-indicator/{ind.id}/risk-score")
        self.assertEqual(response.status_code, 302)

    # -------------------------------------------------------------------------
    # TEST 20: Authenticated GET Route JSON Schema
    # -------------------------------------------------------------------------
    def test_20_authenticated_get_route_json(self):
        """TEST 20: Authenticated GET request returns HTTP 200 with complete JSON schema."""
        self._login(self.client)
        ind = self._create_indicator(
            value="risk_test_route_get",
            ioc_type="ipv4",
            severity="High",
            confidence=60,
            status="Active",
            last_seen=datetime.utcnow()
        )
        response = self.client.get(f"/threat-indicator/{ind.id}/risk-score")
        self.assertEqual(response.status_code, 200)

        data = response.get_json()
        self.assertTrue(data["success"])
        self.assertEqual(data["indicator_id"], ind.id)
        self.assertIn("risk_score", data)
        self.assertIn("risk_level", data)
        self.assertIn("breakdown", data)
        self.assertIn("explanation", data)

        # Expected score: High(40) + Conf 60*0.20(12) + Corr(0) + Enrich(0) + Recency(5) + Status(5) = 62
        self.assertEqual(data["risk_score"], 62)
        self.assertEqual(data["risk_level"], "HIGH")
        self.assertEqual(data["breakdown"]["severity"], 40)
        self.assertEqual(data["breakdown"]["confidence"], 12)
        self.assertEqual(data["breakdown"]["recency"], 5)
        self.assertEqual(data["breakdown"]["status"], 5)

    # -------------------------------------------------------------------------
    # TEST 21: POST Route Persistence
    # -------------------------------------------------------------------------
    def test_21_post_route_persistence(self):
        """TEST 21: POST request persists calculated risk_score into ThreatIndicator record."""
        self._login(self.client)
        ind = self._create_indicator(value="risk_test_persist", severity="High", confidence=80, status="Active")
        self.assertIsNone(ind.risk_score)

        response = self.client.post(f"/threat-indicator/{ind.id}/risk-score")
        self.assertEqual(response.status_code, 200)
        data = response.get_json()
        self.assertTrue(data["success"])
        self.assertTrue(data.get("saved"))

        # Reload from database and verify persistence
        db.session.refresh(ind)
        self.assertEqual(ind.risk_score, data["risk_score"])

    # -------------------------------------------------------------------------
    # TEST 22: Read-Only Verification on GET
    # -------------------------------------------------------------------------
    def test_22_read_only_verification(self):
        """TEST 22: GET calculation does NOT mutate confidence_score, severity, status, or source."""
        ind = self._create_indicator(
            value="risk_test_readonly",
            ioc_type="ipv4",
            severity="Medium",
            confidence=65,
            status="Active"
        )
        initial_confidence = ind.confidence_score
        initial_severity = ind.severity
        initial_status = ind.status
        initial_source = ind.source

        calculate_indicator_risk_by_id(ind.id)

        db.session.refresh(ind)
        self.assertEqual(ind.confidence_score, initial_confidence)
        self.assertEqual(ind.severity, initial_severity)
        self.assertEqual(ind.status, initial_status)
        self.assertEqual(ind.source, initial_source)


if __name__ == "__main__":
    unittest.main()
