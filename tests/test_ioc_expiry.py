"""
Unit and Integration Tests for Task 13: Automated IOC Expiry Job
================================================================
Verifies:
1. Type-Specific TTL Policies:
   - Built-in defaults: IP (30d), Domain (60d), URL (30d), Hash (180d), CVE (365d), Fallback (90d)
   - Custom TTL dictionary overrides
2. Indicator Age Calculation & Expiry Transitions:
   - evaluate_and_expire_iocs in dry-run mode (identifies aged IOCs without mutating database)
   - evaluate_and_expire_iocs in live mode (transitions status from 'Active' to 'Expired')
   - Generates AuditLog records with action='ioc_auto_expire'
   - Fresh indicators within TTL threshold remain 'Active'
   - Type filtering (restricting evaluation to specific indicator types)
3. Reactivation & Telemetry Revival:
   - Single indicator reactivation: resets last_seen_at to now, updates status='Active', logs AuditLog
   - Bulk reactivation across multiple indicator IDs
   - Automated telemetry revival (auto_revive_on_telemetry)
4. Expiry Statistics & Expiring Soon Queries:
   - get_expiry_statistics: total, active, expired, expiring-soon, and type breakdown
   - get_expiring_soon_indicators: windowed query (e.g. next 7 days)
5. REST API Endpoints:
   - POST /api/v1/ioc/expire (dry-run & live execution)
   - GET /api/v1/ioc/expiry/stats
   - GET /api/v1/ioc/expiry/expiring-soon
   - POST /api/v1/ioc/reactivate/<id>
   - POST /api/v1/ioc/bulk-reactivate
   - Verified /api/status catalog includes all Task 13 endpoints
6. Perimeter Blocklist Integration:
   - Expired IOCs are automatically omitted from Task 11 blocklists
7. CLI Commands:
   - flask expire-iocs [--dry-run] [--days N]
   - flask ioc-expiry-stats
"""

from datetime import datetime, timezone, timedelta
import json
import unittest

from app import create_app, db
from app.models import ThreatIndicator, AuditLog, User
from app.services.ioc_expiry_service import (
    evaluate_and_expire_iocs,
    reactivate_indicator,
    bulk_reactivate_indicators,
    auto_revive_on_telemetry,
    get_expiry_statistics,
    get_expiring_soon_indicators,
    get_ttl_for_type,
    calculate_indicator_age_days,
    DEFAULT_TTL_POLICIES,
    DEFAULT_FALLBACK_TTL_DAYS,
)
from app.services.blocklist_service import fetch_blocklist_indicators


class TestIOCExpiryJob(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.app = create_app()
        cls.app.config["TESTING"] = True
        cls.app.config["WTF_CSRF_ENABLED"] = False
        cls.client = cls.app.test_client()

        with cls.app.app_context():
            cls.user = User.query.filter_by(email="expiry_analyst@test.com").first()
            if not cls.user:
                cls.user = User(
                    username="expiry_analyst",
                    email="expiry_analyst@test.com",
                    password_hash="pbkdf2:sha256:dummyhash",
                    role="analyst",
                    api_key="expiry-analyst-test-key-12345"
                )
                db.session.add(cls.user)
                db.session.commit()
            elif not cls.user.api_key:
                cls.user.api_key = "expiry-analyst-test-key-12345"
                db.session.commit()

            cls.api_key = cls.user.api_key
            cls.headers = {"X-API-Key": cls.api_key}
            cls.user_id = cls.user.id
            cls._cleanup_test_data()
            db.session.remove()

    @classmethod
    def tearDownClass(cls):
        with cls.app.app_context():
            cls._cleanup_test_data()
            db.session.remove()

    def setUp(self):
        self.app_ctx = self.app.app_context()
        self.app_ctx.push()

    def tearDown(self):
        self._cleanup_test_data()
        db.session.remove()
        self.app_ctx.pop()

    @classmethod
    def _cleanup_test_data(cls):
        """Purge any indicators created during testing."""
        indicators = ThreatIndicator.query.filter(
            ThreatIndicator.indicator_value.like("EXPIRY_TEST_%")
        ).all()
        ind_ids = [i.id for i in indicators]
        if ind_ids:
            AuditLog.query.filter(
                AuditLog.target_table == "threat_indicators",
                AuditLog.target_id.in_(ind_ids)
            ).delete(synchronize_session=False)

            for ind in indicators:
                ind.reports.clear()
                ind.malwares.clear()
                db.session.delete(ind)

        db.session.commit()

    def _create_indicator(
        self,
        value: str,
        indicator_type: str = "ipv4",
        days_ago: int = 0,
        status: str = "Active",
        severity: str = "High",
        confidence: int = 80,
    ) -> ThreatIndicator:
        """Helper to create a test ThreatIndicator with a simulated age."""
        effective_time = datetime.utcnow() - timedelta(days=days_ago)
        ind = ThreatIndicator(
            indicator_value=value,
            indicator_type=indicator_type,
            confidence_score=confidence,
            severity=severity,
            status=status,
            source="Automated Test Harness",
            first_seen_at=effective_time,
            last_seen_at=effective_time,
            created_at=effective_time,
            updated_at=effective_time,
            added_by_user_id=self.user_id,
            tlp_marking="WHITE",
        )
        db.session.add(ind)
        db.session.commit()
        return ind

    # -------------------------------------------------------------------------
    # 1. TTL Policies & Indicator Age Calculation
    # -------------------------------------------------------------------------

    def test_default_ttl_policies(self):
        """Verify built-in type-specific TTL defaults."""
        self.assertEqual(get_ttl_for_type("ip"), 30)
        self.assertEqual(get_ttl_for_type("ipv4"), 30)
        self.assertEqual(get_ttl_for_type("ipv6"), 30)
        self.assertEqual(get_ttl_for_type("domain"), 60)
        self.assertEqual(get_ttl_for_type("hostname"), 60)
        self.assertEqual(get_ttl_for_type("url"), 30)
        self.assertEqual(get_ttl_for_type("sha256"), 180)
        self.assertEqual(get_ttl_for_type("md5"), 180)
        self.assertEqual(get_ttl_for_type("cve"), 365)
        self.assertEqual(get_ttl_for_type("unknown_type"), DEFAULT_FALLBACK_TTL_DAYS)

    def test_custom_ttl_override(self):
        """Verify custom TTL dictionary overrides built-in defaults."""
        custom = {"ipv4": 7, "domain": 14}
        self.assertEqual(get_ttl_for_type("ipv4", custom), 7)
        self.assertEqual(get_ttl_for_type("domain", custom), 14)
        # Unspecified types in custom should fall back to built-in default
        self.assertEqual(get_ttl_for_type("sha256", custom), 180)

    def test_calculate_indicator_age_days(self):
        """Verify fractional day calculation from last_seen_at."""
        ind = self._create_indicator("EXPIRY_TEST_AGE_10D", days_ago=10)
        now = datetime.now(timezone.utc)
        age = calculate_indicator_age_days(ind, now)
        self.assertAlmostEqual(age, 10.0, delta=0.1)

    # -------------------------------------------------------------------------
    # 2. Expiry Evaluation, Dry-Run, & Live Transitions
    # -------------------------------------------------------------------------

    def test_evaluate_and_expire_iocs_dry_run(self):
        """Verify dry-run mode identifies aged indicators without modifying database."""
        # IP has 30d TTL -> 45d old should be eligible to expire
        ind_aged = self._create_indicator("EXPIRY_TEST_IP_AGED", indicator_type="ipv4", days_ago=45)
        # Fresh IP (5d old) should NOT be eligible
        ind_fresh = self._create_indicator("EXPIRY_TEST_IP_FRESH", indicator_type="ipv4", days_ago=5)

        result = evaluate_and_expire_iocs(dry_run=True, user_id=self.user_id)

        self.assertTrue(result["success"])
        self.assertTrue(result["dry_run"])
        self.assertGreaterEqual(result["expired_count"], 1)

        # Verify indicator status was NOT altered in database
        refreshed_aged = db.session.get(ThreatIndicator, ind_aged.id)
        self.assertEqual(refreshed_aged.status, "Active")

        # Verify NO AuditLog was recorded
        logs = AuditLog.query.filter_by(
            action="ioc_auto_expire",
            target_id=ind_aged.id
        ).all()
        self.assertEqual(len(logs), 0)

    def test_evaluate_and_expire_iocs_live(self):
        """Verify live execution transitions aged indicators to 'Expired' and creates AuditLog."""
        # Domain has 60d TTL -> 75d old indicator should expire
        ind_aged = self._create_indicator("EXPIRY_TEST_DOMAIN_AGED", indicator_type="domain", days_ago=75)
        ind_fresh = self._create_indicator("EXPIRY_TEST_DOMAIN_FRESH", indicator_type="domain", days_ago=10)

        result = evaluate_and_expire_iocs(dry_run=False, user_id=self.user_id)

        self.assertTrue(result["success"])
        self.assertFalse(result["dry_run"])

        # Check DB status
        refreshed_aged = db.session.get(ThreatIndicator, ind_aged.id)
        self.assertEqual(refreshed_aged.status, "Expired")

        refreshed_fresh = db.session.get(ThreatIndicator, ind_fresh.id)
        self.assertEqual(refreshed_fresh.status, "Active")

        # Verify AuditLog recorded
        logs = AuditLog.query.filter_by(
            action="ioc_auto_expire",
            target_id=ind_aged.id
        ).all()
        self.assertEqual(len(logs), 1)
        self.assertEqual(logs[0].target_table, "threat_indicators")

    def test_filter_type_expiration(self):
        """Verify filtering by indicator type restricts expiration to that type only."""
        ind_aged_ip = self._create_indicator("EXPIRY_TEST_IP_AGED_FILT", indicator_type="ipv4", days_ago=40)
        ind_aged_domain = self._create_indicator("EXPIRY_TEST_DOM_AGED_FILT", indicator_type="domain", days_ago=80)

        # Expire only 'domain'
        result = evaluate_and_expire_iocs(dry_run=False, user_id=self.user_id, filter_type="domain")
        self.assertTrue(result["success"])

        # Domain should have expired, but IP should remain Active
        self.assertEqual(db.session.get(ThreatIndicator, ind_aged_domain.id).status, "Expired")
        self.assertEqual(db.session.get(ThreatIndicator, ind_aged_ip.id).status, "Active")

    # -------------------------------------------------------------------------
    # 3. Reactivation & Telemetry Revival
    # -------------------------------------------------------------------------

    def test_reactivate_single_indicator(self):
        """Verify single indicator reactivation sets status='Active' and refreshes last_seen_at."""
        ind = self._create_indicator("EXPIRY_TEST_REACTIVATE_ME", days_ago=50, status="Expired")

        res = reactivate_indicator(ind.id, user_id=self.user_id, reason="Analyst validated threat")
        self.assertTrue(res["success"])
        self.assertEqual(res["indicator"]["status"], "Active")

        refreshed = db.session.get(ThreatIndicator, ind.id)
        self.assertEqual(refreshed.status, "Active")
        # last_seen_at should now be very recent (within 5 seconds)
        now_utc = datetime.utcnow()
        self.assertLess((now_utc - refreshed.last_seen_at).total_seconds(), 10)

        # AuditLog recorded
        log = AuditLog.query.filter(
            AuditLog.target_id == ind.id,
            AuditLog.action.like("ioc_reactivate%")
        ).first()
        self.assertIsNotNone(log)

    def test_bulk_reactivate_indicators(self):
        """Verify bulk reactivation of multiple expired indicators."""
        ind1 = self._create_indicator("EXPIRY_TEST_BULK_1", days_ago=50, status="Expired")
        ind2 = self._create_indicator("EXPIRY_TEST_BULK_2", days_ago=60, status="Expired")

        res = bulk_reactivate_indicators([ind1.id, ind2.id], user_id=self.user_id)
        self.assertTrue(res["success"])
        self.assertEqual(res["reactivated_count"], 2)

        self.assertEqual(db.session.get(ThreatIndicator, ind1.id).status, "Active")
        self.assertEqual(db.session.get(ThreatIndicator, ind2.id).status, "Active")

    def test_auto_revive_on_telemetry(self):
        """Verify expired indicator is revived to 'Active' upon fresh telemetry observation."""
        ind = self._create_indicator("EXPIRY_TEST_AUTO_REVIVE", days_ago=90, status="Expired")

        revived = auto_revive_on_telemetry("EXPIRY_TEST_AUTO_REVIVE", user_id=self.user_id)
        self.assertIsNotNone(revived)
        self.assertEqual(revived.status, "Active")

        # Verify in DB
        refreshed = db.session.get(ThreatIndicator, ind.id)
        self.assertEqual(refreshed.status, "Active")

    # -------------------------------------------------------------------------
    # 4. Statistics & Expiring-Soon Queries
    # -------------------------------------------------------------------------

    def test_get_expiry_statistics(self):
        """Verify get_expiry_statistics aggregates indicator lifecycle counts."""
        self._create_indicator("EXPIRY_TEST_STAT_ACT", status="Active")
        self._create_indicator("EXPIRY_TEST_STAT_EXP", status="Expired")

        stats = get_expiry_statistics()
        self.assertIn("total_indicators", stats)
        self.assertIn("active_indicators", stats)
        self.assertIn("expired_indicators", stats)
        self.assertIn("type_summary", stats)
        self.assertGreaterEqual(stats["active_indicators"], 1)
        self.assertGreaterEqual(stats["expired_indicators"], 1)

    def test_get_expiring_soon_indicators(self):
        """Verify get_expiring_soon_indicators identifies active indicators close to expiry."""
        # IP has 30d TTL -> 25d old indicator has 5 days remaining (<= 7d threshold)
        ind_soon = self._create_indicator("EXPIRY_TEST_SOON_IP", indicator_type="ipv4", days_ago=25)
        # 5d old indicator has 25 days remaining (> 7d threshold)
        ind_far = self._create_indicator("EXPIRY_TEST_FAR_IP", indicator_type="ipv4", days_ago=5)

        expiring = get_expiring_soon_indicators(days_threshold=7)
        found_soon = any(item["value"] == "EXPIRY_TEST_SOON_IP" for item in expiring)
        found_far = any(item["value"] == "EXPIRY_TEST_FAR_IP" for item in expiring)

        self.assertTrue(found_soon)
        self.assertFalse(found_far)

    # -------------------------------------------------------------------------
    # 5. REST API Endpoints
    # -------------------------------------------------------------------------

    def test_api_status_includes_expiry_endpoints(self):
        """Verify /api/status endpoint exposes all Task 13 route paths."""
        res = self.client.get("/api/status")
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        endpoints = data.get("endpoints", {})

        self.assertIn("ioc_expire", endpoints)
        self.assertIn("ioc_expiry_stats", endpoints)
        self.assertIn("ioc_expiring_soon", endpoints)
        self.assertIn("ioc_reactivate", endpoints)
        self.assertIn("ioc_bulk_reactivate", endpoints)

    def test_api_ioc_expiry_stats(self):
        """Verify GET /api/v1/ioc/expiry/stats returns 200 and lifecycle stats."""
        res = self.client.get("/api/v1/ioc/expiry/stats")
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertTrue(data["success"])
        self.assertIn("statistics", data)
        self.assertIn("active_indicators", data["statistics"])

    def test_api_ioc_expiring_soon(self):
        """Verify GET /api/v1/ioc/expiry/expiring-soon accepts parameters and returns list."""
        res = self.client.get("/api/v1/ioc/expiry/expiring-soon?days=14&limit=10")
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertTrue(data["success"])
        self.assertEqual(data["days_threshold"], 14)
        self.assertIsInstance(data["expiring_soon"], list)

    def test_api_ioc_expire_dry_run(self):
        """Verify POST /api/v1/ioc/expire triggers execution with dry_run support."""
        self._create_indicator("EXPIRY_TEST_API_DRY", indicator_type="ipv4", days_ago=45)

        res = self.client.post("/api/v1/ioc/expire?dry_run=true", headers=self.headers)
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertTrue(data["success"])
        self.assertTrue(data["dry_run"])
        self.assertGreaterEqual(data["expired_count"], 1)

    def test_api_ioc_reactivate_single(self):
        """Verify POST /api/v1/ioc/reactivate/<id> successfully reactivates indicator."""
        ind = self._create_indicator("EXPIRY_TEST_API_REACT", status="Expired")

        res = self.client.post(
            f"/api/v1/ioc/reactivate/{ind.id}",
            json={"reason": "Test API reactivation"},
            headers=self.headers
        )
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertTrue(data["success"])
        self.assertEqual(data["indicator"]["status"], "Active")

        # 404 test for non-existent indicator
        res_404 = self.client.post("/api/v1/ioc/reactivate/999999", headers=self.headers)
        self.assertEqual(res_404.status_code, 404)

    def test_api_ioc_bulk_reactivate(self):
        """Verify POST /api/v1/ioc/bulk-reactivate reactivates batch of indicators."""
        ind1 = self._create_indicator("EXPIRY_TEST_API_BULK_1", status="Expired")
        ind2 = self._create_indicator("EXPIRY_TEST_API_BULK_2", status="Expired")

        res = self.client.post(
            "/api/v1/ioc/bulk-reactivate",
            json={"indicator_ids": [ind1.id, ind2.id], "reason": "Batch API"},
            headers=self.headers
        )
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertTrue(data["success"])
        self.assertEqual(data["reactivated_count"], 2)

        # 400 test for invalid payload
        res_400 = self.client.post("/api/v1/ioc/bulk-reactivate", json={}, headers=self.headers)
        self.assertEqual(res_400.status_code, 400)

    # -------------------------------------------------------------------------
    # 6. Perimeter Blocklist Integration
    # -------------------------------------------------------------------------

    def test_expired_iocs_excluded_from_blocklists(self):
        """
        Verify that indicators transitioned to 'Expired' are automatically omitted
        from perimeter blocklists (Task 11), ensuring firewalls do not block stale IPs.
        """
        # Active high-severity IP -> eligible for blocklist
        ind = self._create_indicator(
            "EXPIRY_TEST_192.0.2.100",
            indicator_type="ipv4",
            severity="High",
            days_ago=45,
            status="Active",
        )

        # Before expiry: appears in blocklist indicators
        active_list = fetch_blocklist_indicators(indicator_types=["ipv4"], min_risk=0)
        self.assertTrue(any(i.indicator_value == "EXPIRY_TEST_192.0.2.100" for i in active_list))

        # Run live expiry job
        evaluate_and_expire_iocs(dry_run=False, user_id=self.user_id)

        # After expiry: must NOT appear in blocklist indicators!
        expired_list = fetch_blocklist_indicators(indicator_types=["ipv4"], min_risk=0)
        self.assertFalse(any(i.indicator_value == "EXPIRY_TEST_192.0.2.100" for i in expired_list))

    # -------------------------------------------------------------------------
    # 7. CLI Commands
    # -------------------------------------------------------------------------

    def test_flask_cli_expire_iocs_and_stats(self):
        """Verify Flask CLI commands execute successfully with exit code 0."""
        runner = self.app.test_cli_runner()

        # Test expire-iocs --dry-run
        res_expire = runner.invoke(args=["expire-iocs", "--dry-run"])
        self.assertEqual(res_expire.exit_code, 0)
        self.assertIn("Automated IOC Expiry Job", res_expire.output)
        self.assertIn("DRY RUN (Simulation)", res_expire.output)

        # Test ioc-expiry-stats
        res_stats = runner.invoke(args=["ioc-expiry-stats"])
        self.assertEqual(res_stats.exit_code, 0)
        self.assertIn("IOC Lifecycle & Expiry Statistics", res_stats.output)
        self.assertIn("Total Indicators", res_stats.output)


if __name__ == "__main__":
    unittest.main()
