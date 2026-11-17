"""
Unit and Integration Tests for Task 10: STIX 2.1 & TAXII 2.1 Threat Intel Export
================================================================================
Verifies:
1. STIX 2.1 Bundle Schema & Deterministic Identifier Generation (OASIS standard)
2. STIX Observable Pattern Syntax across IOC types (IPv4, Domain, URL, MD5, SHA256)
3. STIX Domain Objects (SDOs): Indicator, Malware, Report
4. STIX Relationship Objects (SROs): 'indicates' linking indicator to malware
5. External References: MITRE ATT&CK Technique URLs & CVE references
6. REST API Endpoints:
   - GET /api/v1/stix/bundle (with type, min_risk, severity, report_id filters)
   - GET /api/v1/stix/download (file attachment with Content-Disposition)
   - GET /api/v1/stix/indicator/<id> (single indicator export & 404 handling)
   - GET /api/v1/taxii/collections (TAXII 2.1 collection discovery manifest)
"""

from datetime import datetime, timezone
import json
import re
import unittest

from app import create_app, db
from app.models import Malware, ThreatIndicator, ThreatReport, User
from app.services.stix_service import (
    build_stix_bundle,
    build_stix_pattern,
    create_stix_relationship,
    export_stix_bundle,
    generate_stix_id,
    get_taxii_collections_manifest,
    indicator_to_stix,
    malware_to_stix,
    report_to_stix,
)


class TestStixTaxiiExport(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.app = create_app()
        cls.app.config["TESTING"] = True
        cls.app.config["WTF_CSRF_ENABLED"] = False
        cls.client = cls.app.test_client()

    def setUp(self):
        self.app_context = self.app.app_context()
        self.app_context.push()

        # Seed an analyst user if needed
        self.user = User.query.filter_by(email="stix_analyst@test.com").first()
        if not self.user:
            self.user = User(
                username="stix_analyst",
                email="stix_analyst@test.com",
                password_hash="pbkdf2:sha256:dummyhash",
                role="analyst",
            )
            db.session.add(self.user)
            db.session.commit()

        self._cleanup()
        self._seed_test_data()

    def tearDown(self):
        db.session.rollback()
        self._cleanup()
        self.app_context.pop()

    def _cleanup(self):
        # Clean indicators
        inds = ThreatIndicator.query.filter(
            ThreatIndicator.indicator_value.like("stix_test_%")
        ).all()
        for i in inds:
            i.reports.clear()
            i.malwares.clear()
            i.alerts.clear()
            db.session.delete(i)

        # Clean malwares
        mals = Malware.query.filter(
            Malware.malware_name.like("STIX-TEST-%")
        ).all()
        for m in mals:
            m.indicators.clear()
            m.reports.clear()
            db.session.delete(m)

        # Clean reports
        reps = ThreatReport.query.filter(
            ThreatReport.title.like("STIX_TEST_%")
        ).all()
        for r in reps:
            r.indicators.clear()
            r.malwares.clear()
            db.session.delete(r)

        db.session.commit()

    def _seed_test_data(self):
        now = datetime.now(timezone.utc)

        # 1. Indicator: IPv4
        self.ind_ip = ThreatIndicator(
            indicator_value="stix_test_198.51.100.99",
            indicator_type="ipv4",
            confidence_score=85,
            risk_score=80,
            severity="Critical",
            status="Active",
            source="STIX Unit Test",
            first_seen_at=now,
            last_seen_at=now,
            created_at=now,
            updated_at=now,
            added_by_user_id=self.user.id,
            tlp_marking="AMBER",
            context="C2 IP beaconing infrastructure",
        )

        # 2. Indicator: Domain
        self.ind_domain = ThreatIndicator(
            indicator_value="stix_test_evil-c2.example.org",
            indicator_type="domain",
            confidence_score=70,
            risk_score=60,
            severity="High",
            status="Active",
            source="STIX Unit Test",
            first_seen_at=now,
            last_seen_at=now,
            created_at=now,
            updated_at=now,
            added_by_user_id=self.user.id,
            tlp_marking="GREEN",
            context="Phishing and credential harvesting domain",
        )

        # 3. Indicator: Hash
        self.ind_hash = ThreatIndicator(
            indicator_value="stix_test_44d88612fea8a8f36de82e1278abb02f44d88612fea8a8f36de82e1278abb02f",
            indicator_type="sha256",
            confidence_score=95,
            risk_score=90,
            severity="Critical",
            status="Active",
            source="STIX Unit Test",
            first_seen_at=now,
            last_seen_at=now,
            created_at=now,
            updated_at=now,
            added_by_user_id=self.user.id,
            tlp_marking="RED",
            context="Ransomware payload binary dropper",
        )

        db.session.add_all([self.ind_ip, self.ind_domain, self.ind_hash])
        db.session.flush()

        # 4. Malware
        self.malware = Malware(
            malware_name="STIX-TEST-DarkLocker",
            malware_family="LockBit",
            malware_type="Ransomware",
            platform="Windows",
            severity="Critical",
            risk_score=90,
            description="High-impact enterprise ransomware family.",
            mitre_attack_id="T1486",
            cve_id="CVE-2024-21412",
            created_by_user_id=self.user.id,
            created_at=now,
        )
        self.malware.indicators.append(self.ind_hash)
        db.session.add(self.malware)
        db.session.flush()

        # 5. Threat Report
        self.report = ThreatReport(
            user_id=self.user.id,
            title="STIX_TEST_Threat_Campaign_2026",
            description="Investigation into coordinated ransomware deployment across target networks.",
            category="APT Campaign",
            severity="Critical",
            status="Open",
            tlp_level="AMBER",
            target_sector="Financial Services",
            created_at=now,
            updated_at=now,
        )
        self.report.indicators.append(self.ind_ip)
        self.report.indicators.append(self.ind_domain)
        self.report.malwares.append(self.malware)
        db.session.add(self.report)
        db.session.commit()

    # =========================================================================
    # 1. STIX PATTERN SYNTAX TESTS
    # =========================================================================

    def test_stix_pattern_syntax_across_observable_types(self):
        """Verifies standard STIX 2.1 pattern syntax for each IOC type."""
        # IPv4
        pat_ip = build_stix_pattern("ipv4", "198.51.100.1")
        self.assertEqual(pat_ip, "[ipv4-addr:value = '198.51.100.1']")

        # Domain
        pat_dom = build_stix_pattern("domain", "evil.com")
        self.assertEqual(pat_dom, "[domain-name:value = 'evil.com']")

        # URL
        pat_url = build_stix_pattern("url", "http://evil.com/payload.exe")
        self.assertEqual(pat_url, "[url:value = 'http://evil.com/payload.exe']")

        # MD5
        pat_md5 = build_stix_pattern("md5", "0123456789abcdef0123456789abcdef")
        self.assertEqual(pat_md5, "[file:hashes.MD5 = '0123456789abcdef0123456789abcdef']")

        # SHA-256
        pat_sha256 = build_stix_pattern("sha256", "44d88612fea8a8f36de82e1278abb02f44d88612fea8a8f36de82e1278abb02f")
        self.assertEqual(pat_sha256, "[file:hashes.'SHA-256' = '44d88612fea8a8f36de82e1278abb02f44d88612fea8a8f36de82e1278abb02f']")

    # =========================================================================
    # 2. SDO & SRO OBJECT CONVERSION TESTS
    # =========================================================================

    def test_indicator_to_stix_sdo(self):
        """Verifies conversion of ThreatIndicator to STIX 2.1 Indicator SDO."""
        stix_ind = indicator_to_stix(self.ind_ip)

        self.assertEqual(stix_ind["type"], "indicator")
        self.assertEqual(stix_ind["spec_version"], "2.1")
        self.assertTrue(stix_ind["id"].startswith("indicator--"))
        self.assertIn("pattern", stix_ind)
        self.assertEqual(stix_ind["pattern_type"], "stix")
        self.assertEqual(stix_ind["confidence"], 85)
        self.assertEqual(stix_ind["x_tip_risk_score"], 80)
        self.assertEqual(stix_ind["x_tip_tlp"], "AMBER")
        self.assertEqual(stix_ind["x_tip_severity"], "Critical")
        self.assertIn("critical", stix_ind["labels"])

    def test_malware_to_stix_sdo(self):
        """Verifies conversion of Malware to STIX 2.1 Malware SDO with MITRE & CVE refs."""
        stix_mal = malware_to_stix(self.malware)

        self.assertEqual(stix_mal["type"], "malware")
        self.assertEqual(stix_mal["spec_version"], "2.1")
        self.assertTrue(stix_mal["id"].startswith("malware--"))
        self.assertEqual(stix_mal["name"], "STIX-TEST-DarkLocker")
        self.assertTrue(stix_mal["is_family"])
        self.assertIn("ransomware", stix_mal["malware_types"])

        # External References check
        ext_refs = stix_mal.get("external_references", [])
        sources = [r["source_name"] for r in ext_refs]
        self.assertIn("mitre-attack", sources)
        self.assertIn("cve", sources)

        mitre_ref = next(r for r in ext_refs if r["source_name"] == "mitre-attack")
        self.assertEqual(mitre_ref["external_id"], "T1486")
        self.assertIn("attack.mitre.org", mitre_ref["url"])

        cve_ref = next(r for r in ext_refs if r["source_name"] == "cve")
        self.assertEqual(cve_ref["external_id"], "CVE-2024-21412")

    def test_report_to_stix_sdo(self):
        """Verifies conversion of ThreatReport to STIX 2.1 Report SDO."""
        refs = ["indicator--1234", "malware--5678"]
        stix_rep = report_to_stix(self.report, refs)

        self.assertEqual(stix_rep["type"], "report")
        self.assertEqual(stix_rep["spec_version"], "2.1")
        self.assertTrue(stix_rep["id"].startswith("report--"))
        self.assertEqual(stix_rep["name"], self.report.title)
        self.assertEqual(stix_rep["object_refs"], refs)

    def test_create_stix_relationship_sro(self):
        """Verifies STIX 2.1 Relationship SRO linking an Indicator to a Malware object."""
        ind_id = "indicator--1111-2222-3333-4444"
        mal_id = "malware--5555-6666-7777-8888"
        rel = create_stix_relationship(ind_id, mal_id, "indicates")

        self.assertEqual(rel["type"], "relationship")
        self.assertEqual(rel["spec_version"], "2.1")
        self.assertTrue(rel["id"].startswith("relationship--"))
        self.assertEqual(rel["relationship_type"], "indicates")
        self.assertEqual(rel["source_ref"], ind_id)
        self.assertEqual(rel["target_ref"], mal_id)

    # =========================================================================
    # 3. BUNDLE COMPOSITION TESTS
    # =========================================================================

    def test_build_stix_bundle(self):
        """Verifies that build_stix_bundle generates a valid STIX 2.1 bundle with SDOs and SROs."""
        bundle = build_stix_bundle(
            indicators=[self.ind_hash],
            malwares=[self.malware],
            reports=[self.report],
        )

        self.assertEqual(bundle["type"], "bundle")
        self.assertEqual(bundle["spec_version"], "2.1")
        self.assertTrue(bundle["id"].startswith("bundle--"))
        self.assertIsInstance(bundle["objects"], list)

        obj_types = {obj["type"] for obj in bundle["objects"]}
        self.assertIn("indicator", obj_types)
        self.assertIn("malware", obj_types)
        self.assertIn("report", obj_types)
        self.assertIn("relationship", obj_types)

    # =========================================================================
    # 4. REST API ENDPOINT INTEGRATION TESTS
    # =========================================================================

    def test_api_stix_bundle_endpoint(self):
        """Verifies GET /api/v1/stix/bundle returns valid STIX 2.1 JSON with correct MIME type."""
        resp = self.client.get("/api/v1/stix/bundle")
        self.assertEqual(resp.status_code, 200)
        self.assertIn("application/vnd.oasis.stix+json", resp.content_type)

        data = json.loads(resp.data)
        self.assertEqual(data["type"], "bundle")
        self.assertEqual(data["spec_version"], "2.1")
        self.assertGreaterEqual(len(data["objects"]), 3)

    def test_api_stix_bundle_filtering_by_min_risk(self):
        """Verifies GET /api/v1/stix/bundle?min_risk=85 filters out indicators below 85 risk score."""
        resp = self.client.get("/api/v1/stix/bundle?min_risk=85")
        self.assertEqual(resp.status_code, 200)
        data = json.loads(resp.data)

        # Only ind_hash has risk 90; ind_ip has 80, ind_domain has 60
        ind_objects = [o for o in data["objects"] if o["type"] == "indicator"]
        for ind in ind_objects:
            self.assertGreaterEqual(ind["x_tip_risk_score"], 85)

    def test_api_stix_bundle_filtering_by_type(self):
        """Verifies GET /api/v1/stix/bundle?type=ipv4 returns only IP indicators."""
        resp = self.client.get("/api/v1/stix/bundle?type=ipv4")
        self.assertEqual(resp.status_code, 200)
        data = json.loads(resp.data)

        ind_objects = [o for o in data["objects"] if o["type"] == "indicator"]
        for ind in ind_objects:
            self.assertIn("ipv4-addr", ind["pattern"])

    def test_api_stix_bundle_filtering_by_report_id(self):
        """Verifies exporting indicators & malwares for a specific Threat Report."""
        resp = self.client.get(f"/api/v1/stix/bundle?report_id={self.report.id}")
        self.assertEqual(resp.status_code, 200)
        data = json.loads(resp.data)

        obj_types = [o["type"] for o in data["objects"]]
        self.assertIn("report", obj_types)
        report_obj = next(o for o in data["objects"] if o["type"] == "report")
        self.assertEqual(report_obj["name"], self.report.title)

    def test_api_stix_download_endpoint(self):
        """Verifies GET /api/v1/stix/download returns attachment header with filename."""
        resp = self.client.get("/api/v1/stix/download")
        self.assertEqual(resp.status_code, 200)
        self.assertIn("attachment", resp.headers.get("Content-Disposition", ""))
        self.assertIn("stix_bundle_", resp.headers.get("Content-Disposition", ""))

        data = json.loads(resp.data)
        self.assertEqual(data["type"], "bundle")

    def test_api_stix_single_indicator_endpoint(self):
        """Verifies GET /api/v1/stix/indicator/<id> returns standalone STIX bundle."""
        resp = self.client.get(f"/api/v1/stix/indicator/{self.ind_ip.id}")
        self.assertEqual(resp.status_code, 200)
        data = json.loads(resp.data)
        self.assertEqual(data["type"], "bundle")

        ind_objs = [o for o in data["objects"] if o["type"] == "indicator"]
        self.assertEqual(len(ind_objs), 1)
        self.assertEqual(ind_objs[0]["name"], f"IPV4: {self.ind_ip.indicator_value}")

    def test_api_stix_single_indicator_not_found(self):
        """Verifies GET /api/v1/stix/indicator/9999999 returns 404."""
        resp = self.client.get("/api/v1/stix/indicator/9999999")
        self.assertEqual(resp.status_code, 404)

    def test_api_taxii_collections_endpoint(self):
        """Verifies GET /api/v1/taxii/collections returns valid TAXII 2.1 collection manifest."""
        resp = self.client.get("/api/v1/taxii/collections")
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()

        self.assertIn("collections", data)
        self.assertGreaterEqual(len(data["collections"]), 1)
        first_col = data["collections"][0]
        self.assertIn("can_read", first_col)
        self.assertTrue(first_col["can_read"])
        self.assertIn("application/vnd.oasis.stix+json; version=2.1", first_col["media_types"])


if __name__ == "__main__":
    unittest.main()
