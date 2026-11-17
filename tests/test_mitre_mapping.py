"""
Unit and Integration Tests for Task 12: MITRE ATT&CK Mapping & Matrix Integration
==================================================================================
Verifies:
1. MITRE ATT&CK Knowledge Base Service:
   - get_all_tactics: 14 tactics in kill-chain order (Reconnaissance to Impact)
   - get_tactic: lookup by ID, name, or short-name
   - normalize_technique_id: format normalization (t1059.001 -> T1059.001)
   - get_technique: catalog technique metadata, sub-technique link, dynamic fallback
   - search_techniques: filtering by text query, tactic ID, platform, and limits
   - extract_mitre_techniques_from_text: regex extraction from unstructured narratives
2. Threat-to-MITRE Correlation:
   - map_threat_to_mitre for Malware with single/multiple technique IDs
   - map_threat_to_mitre for ThreatReport and Alert
3. Platform Matrix Coverage & Navigator Layer:
   - get_mitre_matrix_coverage: active tactic counts, coverage %, top tactic
   - generate_attack_navigator_layer: MITRE ATT&CK Navigator v4.5 JSON schema
4. REST API Endpoints:
   - GET /api/v1/mitre/tactics
   - GET /api/v1/mitre/techniques (with search & filters)
   - GET /api/v1/mitre/technique/<id> (and 404 handling)
   - GET /api/v1/mitre/coverage
   - GET /api/v1/mitre/navigator (and attachment download)
   - POST /api/v1/mitre/extract (and 400 validation)
5. Web Dashboard Route:
   - GET /mitre-matrix (authenticated analyst access & template rendering)
"""

from datetime import datetime, timezone
import json
import unittest

from app import create_app, db
from app.models import Alert, Malware, ThreatReport, User
from app.services.mitre_service import (
    extract_mitre_techniques_from_text,
    generate_attack_navigator_layer,
    get_all_tactics,
    get_mitre_matrix_coverage,
    get_tactic,
    get_technique,
    map_threat_to_mitre,
    normalize_technique_id,
    search_techniques,
)


class TestMitreAttackMapping(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.app = create_app()
        cls.app.config["TESTING"] = True
        cls.app.config["WTF_CSRF_ENABLED"] = False
        cls.client = cls.app.test_client()

        with cls.app.app_context():
            # Seed test user
            cls.user = User.query.filter_by(email="mitre_analyst@test.com").first()
            if not cls.user:
                cls.user = User(
                    username="mitre_analyst",
                    email="mitre_analyst@test.com",
                    password_hash="pbkdf2:sha256:dummyhash",
                    role="analyst",
                    api_key="mitre-analyst-test-key-12345"
                )
                db.session.add(cls.user)
                db.session.commit()
            elif not cls.user.api_key:
                cls.user.api_key = "mitre-analyst-test-key-12345"
                db.session.commit()

            cls.api_key = cls.user.api_key
            cls.headers = {"X-API-Key": cls.api_key}
            cls.user_id = cls.user.id
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
        # Clean alerts
        alerts = Alert.query.filter(Alert.title.like("MITRE_TEST_%")).all()
        for a in alerts:
            db.session.delete(a)

        # Clean malwares
        mals = Malware.query.filter(Malware.malware_name.like("MITRE_TEST_%")).all()
        for m in mals:
            m.reports.clear()
            m.indicators.clear()
            db.session.delete(m)

        # Clean reports
        reps = ThreatReport.query.filter(ThreatReport.title.like("MITRE_TEST_%")).all()
        for r in reps:
            r.malwares.clear()
            db.session.delete(r)

        db.session.commit()

    @classmethod
    def _seed_test_data(cls):
        # 1. Seed Malware with MITRE T1059.001 (PowerShell) and T1055 (Process Injection)
        cls.malware1 = Malware(
            malware_name="MITRE_TEST_CobaltStrike",
            malware_family="CobaltStrike",
            malware_type="Trojan",
            platform="Windows",
            severity="Critical",
            risk_score=95,
            description="Adversary leveraged PowerShell (T1059.001) for memory injection (T1055).",
            mitre_attack_id="T1059.001, T1055",
            cve_id="CVE-2023-38831",
            created_by_user_id=cls.user.id,
        )

        # 2. Seed Malware with Ransomware Impact T1486
        cls.malware2 = Malware(
            malware_name="MITRE_TEST_LockBit",
            malware_family="LockBit",
            malware_type="Ransomware",
            platform="Windows",
            severity="Critical",
            risk_score=98,
            description="Ransomware encrypts victim disks with T1486 and stops services with T1489.",
            mitre_attack_id="T1486",
            created_by_user_id=cls.user.id,
        )

        db.session.add_all([cls.malware1, cls.malware2])
        db.session.commit()

        # 3. Seed Alert with MITRE techniques in description
        cls.alert1 = Alert(
            title="MITRE_TEST_EDR Mimikatz Alert",
            description="Detected LSASS memory access via procdump. Techniques: T1003.001, T1059.003.",
            severity="High",
            status="Open",
            alert_type="Security Incident",
            is_read=False,
            user_id=cls.user.id,
            malware_id=cls.malware1.id,
        )
        db.session.add(cls.alert1)
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

    def test_get_all_tactics(self):
        """Test get_all_tactics returns exactly 14 tactics in kill-chain order."""
        tactics = get_all_tactics()
        self.assertEqual(len(tactics), 14)
        # Verify first is Reconnaissance and last is Impact
        self.assertEqual(tactics[0]["id"], "TA0043")
        self.assertEqual(tactics[0]["name"], "Reconnaissance")
        self.assertEqual(tactics[-1]["id"], "TA0040")
        self.assertEqual(tactics[-1]["name"], "Impact")
        # Verify orders are 1..14
        orders = [t["order"] for t in tactics]
        self.assertEqual(orders, list(range(1, 15)))

    def test_get_tactic(self):
        """Test get_tactic lookup by ID, name, and short-name."""
        tac_id = get_tactic("TA0001")
        self.assertIsNotNone(tac_id)
        self.assertEqual(tac_id["name"], "Initial Access")

        tac_name = get_tactic("Initial Access")
        self.assertIsNotNone(tac_name)
        self.assertEqual(tac_name["id"], "TA0001")

        tac_short = get_tactic("initial-access")
        self.assertIsNotNone(tac_short)
        self.assertEqual(tac_short["id"], "TA0001")

        self.assertIsNone(get_tactic("NON_EXISTENT_TACTIC"))

    def test_normalize_technique_id(self):
        """Test normalize_technique_id trims whitespace and forces uppercase."""
        self.assertEqual(normalize_technique_id("  t1059.001  "), "T1059.001")
        self.assertEqual(normalize_technique_id("t1055"), "T1055")

    def test_get_technique_known(self):
        """Test get_technique retrieves metadata, tactics, platforms, and mitigations."""
        tech = get_technique("T1059.001")
        self.assertEqual(tech["id"], "T1059.001")
        self.assertIn("PowerShell", tech["name"])
        self.assertEqual(tech["parent_id"], "T1059")
        self.assertIn("TA0002", tech["tactics"])
        self.assertIn("attack.mitre.org", tech["url"])
        self.assertGreater(len(tech["mitigations"]), 0)

    def test_get_technique_dynamic_fallback(self):
        """Test get_technique creates valid dynamic entry for unseen valid T#### pattern."""
        tech = get_technique("T9999.001")
        self.assertEqual(tech["id"], "T9999.001")
        self.assertEqual(tech["parent_id"], "T9999")
        self.assertTrue(tech.get("is_dynamic"))
        self.assertIn("attack.mitre.org/techniques/T9999/001", tech["url"])

        # Invalid format returns empty dict
        self.assertEqual(get_technique("INVALID_FORMAT"), {})

    def test_search_techniques(self):
        """Test search_techniques by query text, tactic, and platform."""
        # Query search
        res_ps = search_techniques(query="powershell")
        self.assertGreaterEqual(len(res_ps), 1)
        self.assertIn("T1059.001", [t["id"] for t in res_ps])

        # Tactic filter (Impact TA0040)
        res_impact = search_techniques(tactic="TA0040")
        self.assertGreaterEqual(len(res_impact), 1)
        self.assertIn("T1486", [t["id"] for t in res_impact])

        # Platform filter
        res_win = search_techniques(platform="Windows")
        self.assertGreater(len(res_win), 5)

    def test_extract_mitre_techniques_from_text(self):
        """Test regex extraction of MITRE IDs from narrative text."""
        narrative = "Attacker used T1059.001 to run script, injected with T1055, and dumped LSASS via T1003.001."
        extracted = extract_mitre_techniques_from_text(narrative)
        extracted_ids = [t["id"] for t in extracted]
        self.assertIn("T1059.001", extracted_ids)
        self.assertIn("T1055", extracted_ids)
        self.assertIn("T1003.001", extracted_ids)
        self.assertEqual(len(extracted_ids), 3)

        # Empty text
        self.assertEqual(extract_mitre_techniques_from_text(""), [])

    def test_map_threat_to_mitre_malware(self):
        """Test map_threat_to_mitre resolves multiple techniques from Malware record."""
        mal = Malware.query.filter_by(malware_name="MITRE_TEST_CobaltStrike").first()
        res = map_threat_to_mitre(mal)
        self.assertEqual(res["entity_type"], "Malware")
        self.assertEqual(res["entity_name"], "MITRE_TEST_CobaltStrike")
        tech_ids = [t["id"] for t in res["mitre_techniques"]]
        self.assertIn("T1059.001", tech_ids)
        self.assertIn("T1055", tech_ids)
        self.assertGreaterEqual(res["tactics_count"], 1)

    def test_map_threat_to_mitre_alert(self):
        """Test map_threat_to_mitre resolves techniques from Alert description & linked malware."""
        alt = Alert.query.filter_by(title="MITRE_TEST_EDR Mimikatz Alert").first()
        res = map_threat_to_mitre(alt)
        self.assertEqual(res["entity_type"], "Alert")
        tech_ids = [t["id"] for t in res["mitre_techniques"]]
        # From alert description
        self.assertIn("T1003.001", tech_ids)
        self.assertIn("T1059.003", tech_ids)
        # From linked malware
        self.assertIn("T1059.001", tech_ids)

    def test_get_mitre_matrix_coverage(self):
        """Test get_mitre_matrix_coverage computes real-time heatmap metrics across database."""
        cov = get_mitre_matrix_coverage()
        self.assertEqual(cov["status"], "healthy")
        self.assertEqual(len(cov["tactics"]), 14)
        summary = cov["summary"]
        self.assertEqual(summary["total_tactics"], 14)
        self.assertGreaterEqual(summary["active_tactics"], 1)
        self.assertGreater(summary["coverage_percentage"], 0.0)
        self.assertGreaterEqual(summary["unique_techniques_observed"], 3)
        self.assertGreaterEqual(summary["total_threat_occurrences"], 3)

    def test_generate_attack_navigator_layer(self):
        """Test generate_attack_navigator_layer produces valid MITRE Navigator schema."""
        layer = generate_attack_navigator_layer()
        self.assertIn("name", layer)
        self.assertEqual(layer["versions"]["attack"], "14")
        self.assertEqual(layer["versions"]["navigator"], "4.5")
        self.assertEqual(layer["domain"], "enterprise-attack")
        self.assertIn("gradient", layer)
        self.assertIn("techniques", layer)
        self.assertGreaterEqual(len(layer["techniques"]), 3)

        first_tech = layer["techniques"][0]
        self.assertIn("techniqueID", first_tech)
        self.assertIn("score", first_tech)
        self.assertIn("color", first_tech)
        self.assertTrue(first_tech["enabled"])

    # =========================================================================
    # REST API ENDPOINT TESTS
    # =========================================================================

    def test_api_mitre_tactics(self):
        """GET /api/v1/mitre/tactics returns 14 tactics."""
        resp = self.client.get("/api/v1/mitre/tactics")
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertTrue(data["success"])
        self.assertEqual(data["total"], 14)
        self.assertEqual(len(data["tactics"]), 14)

    def test_api_mitre_techniques(self):
        """GET /api/v1/mitre/techniques returns list and supports filters."""
        # All
        resp = self.client.get("/api/v1/mitre/techniques")
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertTrue(data["success"])
        self.assertGreater(data["count"], 10)

        # Filter query
        resp_q = self.client.get("/api/v1/mitre/techniques?q=powershell")
        self.assertEqual(resp_q.status_code, 200)
        data_q = resp_q.get_json()
        self.assertGreaterEqual(data_q["count"], 1)
        self.assertIn("T1059.001", [t["id"] for t in data_q["techniques"]])

    def test_api_mitre_technique_detail(self):
        """GET /api/v1/mitre/technique/<id> returns technique and handles 404."""
        resp = self.client.get("/api/v1/mitre/technique/T1059.001")
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertTrue(data["success"])
        self.assertEqual(data["technique"]["id"], "T1059.001")

        # Invalid ID returns 404
        resp_bad = self.client.get("/api/v1/mitre/technique/INVALID_NOT_A_TECHNIQUE")
        self.assertEqual(resp_bad.status_code, 404)
        data_bad = resp_bad.get_json()
        self.assertFalse(data_bad["success"])

    def test_api_mitre_coverage(self):
        """GET /api/v1/mitre/coverage returns matrix coverage JSON."""
        resp = self.client.get("/api/v1/mitre/coverage")
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertEqual(data["status"], "healthy")
        self.assertIn("summary", data)
        self.assertIn("tactics", data)

    def test_api_mitre_navigator(self):
        """GET /api/v1/mitre/navigator returns Navigator JSON and attachment header."""
        resp = self.client.get("/api/v1/mitre/navigator")
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertEqual(data["domain"], "enterprise-attack")

        # Download attachment header
        resp_dl = self.client.get("/api/v1/mitre/navigator?download=true")
        self.assertEqual(resp_dl.status_code, 200)
        self.assertIn("Content-Disposition", resp_dl.headers)
        self.assertIn("mitre_attack_layer.json", resp_dl.headers["Content-Disposition"])

    def test_api_mitre_extract(self):
        """POST /api/v1/mitre/extract resolves techniques from input text."""
        payload = {"text": "Detected procdump LSASS dumping T1003.001 and lateral movement via T1021.001."}
        resp = self.client.post("/api/v1/mitre/extract", json=payload, headers=self.headers)
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertTrue(data["success"])
        self.assertEqual(data["count"], 2)
        extracted_ids = [t["id"] for t in data["techniques"]]
        self.assertIn("T1003.001", extracted_ids)
        self.assertIn("T1021.001", extracted_ids)

        # Empty payload returns 400
        resp_empty = self.client.post("/api/v1/mitre/extract", json={"text": ""}, headers=self.headers)
        self.assertEqual(resp_empty.status_code, 400)
        self.assertFalse(resp_empty.get_json()["success"])

    # =========================================================================
    # WEB VIEW ROUTE TEST
    # =========================================================================

    def test_mitre_matrix_page_renders_for_analyst(self):
        """GET /mitre-matrix renders successfully for authenticated analyst."""
        with self.client.session_transaction() as sess:
            sess["_user_id"] = str(self.user_id)
            sess["_fresh"] = True

        resp = self.client.get("/mitre-matrix")
        self.assertEqual(resp.status_code, 200)
        content = resp.get_data(as_text=True)
        self.assertIn("Enterprise MITRE ATT&amp;CK", content)
        self.assertIn("Kill Chain Tactics", content)
        self.assertIn("TA0043", content)
        self.assertIn("TA0040", content)


if __name__ == "__main__":
    unittest.main()
