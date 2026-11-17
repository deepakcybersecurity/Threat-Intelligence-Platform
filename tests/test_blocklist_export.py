"""
Unit and Integration Tests for Task 11: Automated IOC Blocklist Export API
==========================================================================
Verifies:
1. Blocklist Service:
   - fetch_blocklist_indicators: type filtering, risk score thresholds, active status
   - compute_feed_etag: deterministic MD5 checksums
   - generate_plain_blocklist: newline-delimited feed (with/without headers)
   - generate_hosts_sinkhole_blocklist: Pi-hole / AdGuard hosts format
   - generate_dns_rpz_blocklist: BIND9 / PowerDNS RPZ zone files
   - generate_suricata_snort_rules: IDS/IPS signatures with SID incrementation
   - generate_csv_blocklist: SIEM-compatible RFC 4180 CSV export
   - get_blocklist_statistics: aggregate metrics and type distribution
2. REST API Endpoints:
   - GET /api/v1/blocklist/ip
   - GET /api/v1/blocklist/domains
   - GET /api/v1/blocklist/urls
   - GET /api/v1/blocklist/hashes
   - GET /api/v1/blocklist/hosts
   - GET /api/v1/blocklist/rpz
   - GET /api/v1/blocklist/suricata
   - GET /api/v1/blocklist/csv
   - GET /api/v1/blocklist/stats
3. HTTP Caching & ETag:
   - ETag generation and Cache-Control headers
   - Conditional GET with If-None-Match returning 304 Not Modified
4. Backward Compatibility:
   - GET /api/v1/feed/blocklist (JSON format)
   - GET /api/v1/feed/blocklist/plain (plaintext format)
"""

from datetime import datetime, timezone
import json
import unittest

from app import create_app, db
from app.models import ThreatIndicator, User
from app.services.blocklist_service import (
    compute_feed_etag,
    fetch_blocklist_indicators,
    generate_csv_blocklist,
    generate_dns_rpz_blocklist,
    generate_hosts_sinkhole_blocklist,
    generate_plain_blocklist,
    generate_suricata_snort_rules,
    get_blocklist_statistics,
)


class TestBlocklistExport(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.app = create_app()
        cls.app.config["TESTING"] = True
        cls.app.config["WTF_CSRF_ENABLED"] = False
        cls.client = cls.app.test_client()

        with cls.app.app_context():
            # Seed an analyst user for added_by_user_id (non-nullable)
            cls.user = User.query.filter_by(email="blocklist_analyst@test.com").first()
            if not cls.user:
                cls.user = User(
                    username="blocklist_analyst",
                    email="blocklist_analyst@test.com",
                    password_hash="pbkdf2:sha256:dummyhash",
                    role="analyst",
                )
                db.session.add(cls.user)
                db.session.commit()

            cls._cleanup_all()
            cls._seed_test_data()
            db.session.remove()

    @classmethod
    def tearDownClass(cls):
        with cls.app.app_context():
            cls._cleanup_all()
            db.session.remove()

    @classmethod
    def _cleanup_all(cls):
        inds = ThreatIndicator.query.filter(
            ThreatIndicator.indicator_value.like("bltest_%")
        ).all()
        for i in inds:
            i.reports.clear()
            i.malwares.clear()
            i.alerts.clear()
            db.session.delete(i)
        db.session.commit()

    @classmethod
    def _seed_test_data(cls):
        # 1. High-risk active IPv4
        cls.ind_ip = ThreatIndicator(
            indicator_value="bltest_198.51.100.99",
            indicator_type="IPv4",
            severity="Critical",
            confidence_score=95,
            risk_score=90,
            status="Active",
            tlp_marking="AMBER",
            source="Task11 Unit Test",
            context="Active Cobalt Strike C2 listener",
            added_by_user_id=cls.user.id,
        )

        # 2. High-risk active Domain
        cls.ind_domain = ThreatIndicator(
            indicator_value="bltest_malware-c2.org",
            indicator_type="Domain",
            severity="High",
            confidence_score=85,
            risk_score=75,
            status="Active",
            tlp_marking="WHITE",
            source="Task11 Unit Test",
            context="Domain hosting Emotet loader",
            added_by_user_id=cls.user.id,
        )

        # 3. High-risk active URL
        cls.ind_url = ThreatIndicator(
            indicator_value="bltest_http://bltest_malware-c2.org/payload.exe",
            indicator_type="URL",
            severity="High",
            confidence_score=80,
            risk_score=70,
            status="Active",
            tlp_marking="GREEN",
            source="Task11 Unit Test",
            context="Direct binary download URL",
            added_by_user_id=cls.user.id,
        )

        # 4. High-risk active SHA256 Hash
        cls.ind_hash = ThreatIndicator(
            indicator_value="bltest_e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            indicator_type="SHA256",
            severity="Critical",
            confidence_score=99,
            risk_score=98,
            status="Active",
            tlp_marking="RED",
            source="Task11 Unit Test",
            context="LockBit 3.0 encryptor binary",
            added_by_user_id=cls.user.id,
        )

        # 5. Low-risk indicator (should be filtered out by default min_risk=50)
        cls.ind_low = ThreatIndicator(
            indicator_value="bltest_lowrisk.example.com",
            indicator_type="Domain",
            severity="Low",
            confidence_score=30,
            risk_score=20,
            status="Active",
            tlp_marking="WHITE",
            source="Task11 Unit Test",
            context="Low risk domain",
            added_by_user_id=cls.user.id,
        )

        # 6. Inactive indicator (should be excluded)
        cls.ind_inactive = ThreatIndicator(
            indicator_value="bltest_198.51.100.100",
            indicator_type="IPv4",
            severity="Critical",
            confidence_score=90,
            risk_score=85,
            status="Inactive",
            tlp_marking="WHITE",
            source="Task11 Unit Test",
            context="Old decommissioned C2",
            added_by_user_id=cls.user.id,
        )

        db.session.add_all([
            cls.ind_ip, cls.ind_domain, cls.ind_url,
            cls.ind_hash, cls.ind_low, cls.ind_inactive
        ])
        db.session.commit()

    def setUp(self):
        self.app_context = self.app.app_context()
        self.app_context.push()

    def tearDown(self):
        db.session.rollback()
        db.session.remove()
        self.app_context.pop()

    # =========================================================================
    # SERVICE UNIT TESTS
    # =========================================================================

    def test_fetch_blocklist_indicators_filters(self):
        """Test fetch_blocklist_indicators respects status, risk, and type filters."""
        # Active and high risk only
        inds = fetch_blocklist_indicators(min_risk=50)
        vals = [i.indicator_value for i in inds if i.indicator_value.startswith("bltest_")]
        self.assertIn("bltest_198.51.100.99", vals)
        self.assertIn("bltest_malware-c2.org", vals)
        self.assertNotIn("bltest_lowrisk.example.com", vals)
        self.assertNotIn("bltest_198.51.100.100", vals)

        # Filter by type
        ip_inds = fetch_blocklist_indicators(indicator_types=["ipv4"], min_risk=50)
        ip_vals = [i.indicator_value for i in ip_inds if i.indicator_value.startswith("bltest_")]
        self.assertEqual(ip_vals, ["bltest_198.51.100.99"])

    def test_compute_feed_etag(self):
        """Test ETag is a 32-character MD5 hex string and deterministic."""
        etag1 = compute_feed_etag("indicator1\nindicator2\n")
        etag2 = compute_feed_etag("indicator1\nindicator2\n")
        etag3 = compute_feed_etag("indicator1\nindicator3\n")
        self.assertEqual(len(etag1), 32)
        self.assertEqual(etag1, etag2)
        self.assertNotEqual(etag1, etag3)

    def test_generate_plain_blocklist(self):
        """Test generate_plain_blocklist outputs newline-delimited list."""
        ind_ip = ThreatIndicator.query.filter_by(indicator_value="bltest_198.51.100.99").first()
        ind_domain = ThreatIndicator.query.filter_by(indicator_value="bltest_malware-c2.org").first()
        indicators = [ind_ip, ind_domain]

        feed_no_hdr = generate_plain_blocklist(indicators, include_header=False)
        self.assertEqual(feed_no_hdr, "bltest_198.51.100.99\nbltest_malware-c2.org\n")

        feed_with_hdr = generate_plain_blocklist(indicators, include_header=True)
        self.assertTrue(feed_with_hdr.startswith("# ThreatIntel Platform Automated Blocklist Feed"))
        self.assertIn("bltest_198.51.100.99", feed_with_hdr)
        self.assertIn("bltest_malware-c2.org", feed_with_hdr)

    def test_generate_hosts_sinkhole_blocklist(self):
        """Test DNS Sinkhole hosts format (0.0.0.0 domain)."""
        ind_domain = ThreatIndicator.query.filter_by(indicator_value="bltest_malware-c2.org").first()
        indicators = [ind_domain]
        hosts_feed = generate_hosts_sinkhole_blocklist(indicators, sinkhole_ip="0.0.0.0")
        self.assertIn("# ThreatIntel Platform DNS Sinkhole Feed", hosts_feed)
        self.assertIn("0.0.0.0 bltest_malware-c2.org", hosts_feed)

        # Test custom sinkhole IP
        hosts_custom = generate_hosts_sinkhole_blocklist(indicators, sinkhole_ip="127.0.0.1")
        self.assertIn("127.0.0.1 bltest_malware-c2.org", hosts_custom)

    def test_generate_dns_rpz_blocklist(self):
        """Test BIND9 RPZ zone file formatting."""
        ind_domain = ThreatIndicator.query.filter_by(indicator_value="bltest_malware-c2.org").first()
        indicators = [ind_domain]
        rpz_feed = generate_dns_rpz_blocklist(indicators, zone_name="rpz.tip.local")
        self.assertIn("; ThreatIntel Platform DNS RPZ Policy Zone Feed: rpz.tip.local", rpz_feed)
        self.assertIn("$TTL 300", rpz_feed)
        self.assertIn("bltest_malware-c2.org CNAME .", rpz_feed)
        self.assertIn("*.bltest_malware-c2.org CNAME .", rpz_feed)

    def test_generate_suricata_snort_rules(self):
        """Test Suricata and Snort IDS alert rule generation."""
        ind_ip = ThreatIndicator.query.filter_by(indicator_value="bltest_198.51.100.99").first()
        ind_domain = ThreatIndicator.query.filter_by(indicator_value="bltest_malware-c2.org").first()
        indicators = [ind_ip, ind_domain]

        rules = generate_suricata_snort_rules(indicators, base_sid=1900000)
        self.assertIn("# ThreatIntel Platform Suricata / Snort IDS Signatures", rules)
        # IP Rule
        self.assertIn('alert ip any any -> bltest_198.51.100.99 any', rules)
        self.assertIn('sid:1900000;', rules)
        # Domain Rule
        self.assertIn('alert dns any any -> any 53', rules)
        self.assertIn('content:"bltest_malware-c2.org"', rules)
        self.assertIn('sid:1900001;', rules)

    def test_generate_csv_blocklist(self):
        """Test CSV blocklist contains valid RFC 4180 headers and rows."""
        ind_ip = ThreatIndicator.query.filter_by(indicator_value="bltest_198.51.100.99").first()
        indicators = [ind_ip]
        csv_feed = generate_csv_blocklist(indicators)
        lines = csv_feed.strip().split("\n")
        self.assertTrue(lines[0].startswith("indicator_value,indicator_type,risk_score,severity"))
        self.assertIn('"bltest_198.51.100.99"', lines[1])
        self.assertIn('"IPv4"', lines[1])
        self.assertIn('90', lines[1])

    def test_get_blocklist_statistics(self):
        """Test get_blocklist_statistics returns valid summary counts."""
        stats = get_blocklist_statistics()
        self.assertEqual(stats["status"], "healthy")
        self.assertGreaterEqual(stats["total_active_indicators"], 4)
        self.assertGreaterEqual(stats["high_risk_blocked_total"], 4)
        self.assertIn("formats_available", stats)
        self.assertIn("suricata", stats["formats_available"])
        self.assertIn("type_breakdown", stats)

    # =========================================================================
    # REST API ENDPOINT TESTS
    # =========================================================================

    def test_api_blocklist_ip(self):
        """GET /api/v1/blocklist/ip returns plaintext IPs with caching headers."""
        resp = self.client.get("/api/v1/blocklist/ip")
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.mimetype, "text/plain")
        self.assertIn("ETag", resp.headers)
        self.assertIn("Cache-Control", resp.headers)
        self.assertIn("bltest_198.51.100.99", resp.get_data(as_text=True))
        self.assertNotIn("bltest_malware-c2.org", resp.get_data(as_text=True))

    def test_api_blocklist_domains(self):
        """GET /api/v1/blocklist/domains returns plaintext domains."""
        resp = self.client.get("/api/v1/blocklist/domains")
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.mimetype, "text/plain")
        self.assertIn("bltest_malware-c2.org", resp.get_data(as_text=True))
        self.assertNotIn("bltest_198.51.100.99", resp.get_data(as_text=True))

    def test_api_blocklist_urls(self):
        """GET /api/v1/blocklist/urls returns plaintext URLs."""
        resp = self.client.get("/api/v1/blocklist/urls")
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.mimetype, "text/plain")
        self.assertIn("bltest_http://bltest_malware-c2.org/payload.exe", resp.get_data(as_text=True))

    def test_api_blocklist_hashes(self):
        """GET /api/v1/blocklist/hashes returns file hashes."""
        resp = self.client.get("/api/v1/blocklist/hashes")
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.mimetype, "text/plain")
        self.assertIn("bltest_e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", resp.get_data(as_text=True))

    def test_api_blocklist_hosts(self):
        """GET /api/v1/blocklist/hosts returns Pi-hole sinkhole format."""
        resp = self.client.get("/api/v1/blocklist/hosts?ip=0.0.0.0")
        self.assertEqual(resp.status_code, 200)
        self.assertIn("0.0.0.0 bltest_malware-c2.org", resp.get_data(as_text=True))

    def test_api_blocklist_rpz(self):
        """GET /api/v1/blocklist/rpz returns BIND9 RPZ zone file."""
        resp = self.client.get("/api/v1/blocklist/rpz?zone=corp.local")
        self.assertEqual(resp.status_code, 200)
        data = resp.get_data(as_text=True)
        self.assertIn("corp.local", data)
        self.assertIn("bltest_malware-c2.org CNAME .", data)

    def test_api_blocklist_suricata(self):
        """GET /api/v1/blocklist/suricata returns IDS rules."""
        resp = self.client.get("/api/v1/blocklist/suricata")
        self.assertEqual(resp.status_code, 200)
        data = resp.get_data(as_text=True)
        self.assertIn("alert ip any any -> bltest_198.51.100.99 any", data)
        self.assertIn('dns.query; content:"bltest_malware-c2.org"', data)

    def test_api_blocklist_csv(self):
        """GET /api/v1/blocklist/csv returns CSV with metadata."""
        resp = self.client.get("/api/v1/blocklist/csv")
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.mimetype, "text/csv")
        data = resp.get_data(as_text=True)
        self.assertIn("indicator_value,indicator_type", data)
        self.assertIn("bltest_198.51.100.99", data)

    def test_api_blocklist_stats(self):
        """GET /api/v1/blocklist/stats returns real-time metrics JSON."""
        resp = self.client.get("/api/v1/blocklist/stats")
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertEqual(data["status"], "healthy")
        self.assertIn("total_active_indicators", data)
        self.assertIn("high_risk_blocked_total", data)
        self.assertIn("type_breakdown", data)

    def test_http_caching_etag_304_not_modified(self):
        """Test conditional GET with If-None-Match responds with 304 Not Modified."""
        # 1. Initial request to obtain ETag
        resp1 = self.client.get("/api/v1/blocklist/ip")
        self.assertEqual(resp1.status_code, 200)
        etag = resp1.headers.get("ETag")
        self.assertIsNotNone(etag)

        # 2. Subsequent request with matching If-None-Match
        resp2 = self.client.get("/api/v1/blocklist/ip", headers={"If-None-Match": etag})
        self.assertEqual(resp2.status_code, 304)
        self.assertEqual(resp2.get_data(), b"")

        # 3. Subsequent request with stale / mismatched ETag
        resp3 = self.client.get("/api/v1/blocklist/ip", headers={"If-None-Match": '"different-hash"'})
        self.assertEqual(resp3.status_code, 200)
        self.assertIn("bltest_198.51.100.99", resp3.get_data(as_text=True))

    def test_backward_compatibility_feeds(self):
        """Verify legacy /api/v1/feed/blocklist and /api/v1/feed/blocklist/plain work."""
        # JSON feed
        resp_json = self.client.get("/api/v1/feed/blocklist")
        self.assertEqual(resp_json.status_code, 200)
        data = resp_json.get_json()
        self.assertIn("total", data)
        self.assertIn("indicators", data)

        # Plaintext feed
        resp_plain = self.client.get("/api/v1/feed/blocklist/plain")
        self.assertEqual(resp_plain.status_code, 200)
        self.assertIn("bltest_198.51.100.99", resp_plain.get_data(as_text=True))


if __name__ == "__main__":
    unittest.main()
