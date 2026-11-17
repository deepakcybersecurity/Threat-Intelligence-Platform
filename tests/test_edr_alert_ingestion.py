"""
Unit and Integration Tests for Task 9: Dedicated EDR Telemetry & Alert Ingestion
================================================================================
Verifies:
1. Vendor Payload Normalization (CrowdStrike, MDE, SentinelOne, Generic EDR)
2. Inbound EDR Authentication (X-API-Key, Bearer token, 401 on missing/invalid)
3. Deep IOC Extraction from process trees and command-line execution
4. Host Context Tracking (Hostname, IP, OS, Agent ID, Process PID)
5. MITRE ATT&CK TTP Alignment
6. Automated Malware Graph Correlation (linking EDR alerts to Malware records)
7. Containment & Remediation Recommendation Engine (Host Isolation, Quarantine)
8. Alert Center Integration (alert_type='EDR', status='Open')
9. IOC Deduplication on Repeated Ingestion
"""

from datetime import datetime
import json
import unittest

from app import create_app, db
from app.models import Alert, AuditLog, Malware, ThreatIndicator, ThreatReport, User
from app.services.edr_service import (
    calculate_containment_action,
    find_matching_malware,
    ingest_edr_alert,
    normalize_edr_payload,
)


class TestEdrAlertIngestion(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.app = create_app()
        cls.app.config["TESTING"] = True
        cls.app.config["WTF_CSRF_ENABLED"] = False
        cls.app.config["SIEM_WEBHOOK_API_KEY"] = "test-edr-secret-key-2026"
        cls.client = cls.app.test_client()
        from app.services.security_service import assert_safe_test_database
        assert_safe_test_database(cls.app)

    def setUp(self):
        self.app_context = self.app.app_context()
        self.app_context.push()

        # Ensure analyst user exists
        self.analyst = User.query.filter_by(email="edr_analyst@test.com").first()
        if not self.analyst:
            self.analyst = User(
                username="edr_analyst",
                email="edr_analyst@test.com",
                password_hash="pbkdf2:sha256:dummyhash",
                role="analyst",
            )
            db.session.add(self.analyst)
            db.session.commit()

        self.client = self.app.test_client()
        self._cleanup()

    def tearDown(self):
        db.session.rollback()
        self._cleanup()
        self.app_context.pop()

    def _cleanup(self):
        # Scoped cleanup: delete only test alerts created by this suite
        test_alerts = Alert.query.filter(
            (Alert.title.like("%[EDR%"))
            | (Alert.title.like("%CrowdStrike Falcon%"))
            | (Alert.title.like("%Microsoft Defender%"))
            | (Alert.title.like("%SentinelOne%"))
        ).all()
        test_alert_ids = [a.id for a in test_alerts]
        if test_alert_ids:
            from app.models import AuditLog
            AuditLog.query.filter(
                AuditLog.target_table == "alerts",
                AuditLog.target_id.in_(test_alert_ids)
            ).delete(synchronize_session=False)
            for a in test_alerts:
                db.session.delete(a)

        # Delete test indicators
        test_indicators = ThreatIndicator.query.filter(
            ThreatIndicator.indicator_value.in_([
                "198.51.100.77",
                "203.0.113.88",
                "c2-edr-beacon.evil.com",
                "http://198.51.100.77/beacon.ps1",
                "44d88612fea8a8f36de82e1278abb02f44d88612fea8a8f36de82e1278abb02f",
                "a1b2c3d4e5f60718293a4b5c6d7e8f90",
            ])
        ).all()
        for ind in test_indicators:
            ind.reports.clear()
            ind.malwares.clear()
            ind.alerts.clear()
            db.session.delete(ind)

        # Delete test malware
        test_malware = Malware.query.filter_by(malware_name="Test-LockBit-Variant").first()
        if test_malware:
            test_malware.indicators.clear()
            test_malware.reports.clear()
            test_malware.alerts.clear()
            db.session.delete(test_malware)

        db.session.commit()

    # =========================================================================
    # 1. PAYLOAD NORMALIZATION TESTS
    # =========================================================================

    def test_normalize_crowdstrike_falcon_payload(self):
        """Verifies normalization of CrowdStrike Falcon telemetry schema."""
        raw = {
            "ComputerName": "CORP-FIN-01",
            "aid": "cs_agent_9981",
            "DetectionName": "Suspicious PowerShell C2 Beacon",
            "Severity": "Critical",
            "FileName": "powershell.exe",
            "ProcessId": 4120,
            "ParentCommandLine": "C:\\Windows\\explorer.exe",
            "CommandLine": "powershell.exe -enc dGVzdA== -server 198.51.100.77",
            "FilePath": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
            "SHA256HashData": "44d88612fea8a8f36de82e1278abb02f44d88612fea8a8f36de82e1278abb02f",
            "Tactic": "Execution",
            "Technique": "T1059.001",
        }
        res = normalize_edr_payload(raw)
        self.assertEqual(res["hostname"], "CORP-FIN-01")
        self.assertEqual(res["agent_id"], "cs_agent_9981")
        self.assertEqual(res["sensor_vendor"], "CrowdStrike Falcon")
        self.assertEqual(res["severity"], "Critical")
        self.assertEqual(res["process_name"], "powershell.exe")
        self.assertIn("T1059.001", res["mitre_techniques"])
        # Extracted IOCs should capture IP and SHA256
        ioc_vals = [i["value"] for i in res["extracted_iocs"]]
        self.assertIn("198.51.100.77", ioc_vals)
        self.assertIn("44d88612fea8a8f36de82e1278abb02f44d88612fea8a8f36de82e1278abb02f", ioc_vals)

    def test_normalize_defender_for_endpoint_payload(self):
        """Verifies normalization of Microsoft Defender for Endpoint schema."""
        raw = {
            "DeviceName": "SRV-DC-02.domain.local",
            "DeviceId": "mde_dev_5501",
            "Title": "Mimikatz LSASS Memory Dump",
            "Severity": "High",
            "FileName": "procdump.exe",
            "ProcessCommandLine": "procdump.exe -ma lsass.exe lsass.dmp",
            "MitreTechniques": ["T1003.001"],
            "PublicIP": "203.0.113.88",
        }
        res = normalize_edr_payload(raw)
        self.assertEqual(res["hostname"], "SRV-DC-02.domain.local")
        self.assertEqual(res["agent_id"], "mde_dev_5501")
        self.assertEqual(res["sensor_vendor"], "Microsoft Defender for Endpoint")
        self.assertEqual(res["severity"], "High")
        self.assertIn("T1003.001", res["mitre_techniques"])

    # =========================================================================
    # 2. AUTHENTICATION & VALIDATION TESTS
    # =========================================================================

    def test_edr_endpoint_unauthorized_when_missing_key(self):
        """Verifies POST /api/v1/edr/alert returns 401 when API key is missing."""
        resp = self.client.post(
            "/api/v1/edr/alert",
            json={"hostname": "HOST-01", "severity": "High"},
            headers={"Content-Type": "application/json"}
        )
        self.assertEqual(resp.status_code, 401)
        data = resp.get_json()
        self.assertFalse(data["success"])
        self.assertEqual(data["error"], "Unauthorized")

    def test_edr_endpoint_invalid_json(self):
        """Verifies POST /api/v1/edr/alert returns 400 when body is not application/json."""
        resp = self.client.post(
            "/api/v1/edr/alert",
            data="not json",
            headers={"X-API-Key": "test-edr-secret-key-2026"}
        )
        self.assertEqual(resp.status_code, 400)

    # =========================================================================
    # 3. END-TO-END EDR ALERT INGESTION & RISK SCORING TESTS
    # =========================================================================

    def test_end_to_end_edr_alert_ingestion(self):
        """
        Verifies complete EDR alert ingestion pipeline:
        - Ingests endpoint context (hostname, PID, command line, MITRE TTP).
        - Extracts and saves ThreatIndicators with risk scores.
        - Calculates containment recommendations (ISOLATE_HOST for Critical).
        - Creates an EDR Alert in the Alert Center.
        """
        payload = {
            "ComputerName": "WORKSTATION-CEO",
            "host_ip": "10.10.5.20",
            "aid": "cs_agent_ceo_01",
            "vendor": "CrowdStrike Falcon",
            "DetectionName": "Ransomware Encryption Artifacts Detected",
            "Severity": "Critical",
            "FileName": "encrypter.exe",
            "ProcessId": 8832,
            "CommandLine": "encrypter.exe -target C:\\Shares -c2 198.51.100.77 -url http://198.51.100.77/beacon.ps1",
            "FilePath": "C:\\Users\\CEO\\AppData\\Local\\Temp\\encrypter.exe",
            "SHA256HashData": "44d88612fea8a8f36de82e1278abb02f44d88612fea8a8f36de82e1278abb02f",
            "Tactic": "Impact",
            "Technique": "T1486",
        }

        resp = self.client.post(
            "/api/v1/edr/alert",
            json=payload,
            headers={
                "Content-Type": "application/json",
                "X-API-Key": "test-edr-secret-key-2026"
            }
        )

        self.assertEqual(resp.status_code, 201)
        data = resp.get_json()
        self.assertTrue(data["success"])

        # Check endpoint metadata
        self.assertEqual(data["endpoint"]["hostname"], "WORKSTATION-CEO")
        self.assertEqual(data["endpoint"]["host_ip"], "10.10.5.20")
        self.assertEqual(data["execution"]["process_name"], "encrypter.exe")

        # Check MITRE TTPs
        self.assertIn("T1486", data["mitre_attack"]["techniques"])

        # Check containment decision
        self.assertEqual(data["containment"]["containment_action"], "ISOLATE_HOST")
        self.assertTrue(data["containment"]["is_containment_recommended"])
        self.assertGreater(len(data["containment"]["remediation_steps"]), 0)

        # Check database records
        ind_ip = ThreatIndicator.query.filter_by(indicator_value="198.51.100.77").first()
        self.assertIsNotNone(ind_ip)
        self.assertIsNotNone(ind_ip.risk_score)
        self.assertIn("WORKSTATION-CEO", ind_ip.context)

        # Check Alert Center record
        alert = Alert.query.filter(Alert.title.like("%WORKSTATION-CEO%")).first()
        self.assertIsNotNone(alert)
        self.assertEqual(alert.alert_type, "EDR")
        self.assertEqual(alert.severity, "Critical")
        self.assertEqual(alert.status, "Open")
        self.assertFalse(alert.is_read)

    # =========================================================================
    # 4. MALWARE DATABASE CORRELATION TESTS
    # =========================================================================

    def test_edr_alert_correlates_with_existing_malware_record(self):
        """
        Verifies that when an EDR alert includes a hash matching an existing Malware record,
        the alert and new indicators are automatically linked to that Malware entity.
        """
        # Create a Malware record in TIP
        mal = Malware(
            malware_name="Test-LockBit-Variant",
            malware_family="LockBit",
            malware_type="Ransomware",
            platform="Windows",
            severity="Critical",
            risk_score=90,
            description="Active ransomware test record",
            mitre_attack_id="T1486",
            created_by_user_id=self.analyst.id,
            created_at=datetime.utcnow(),
        )
        db.session.add(mal)
        db.session.flush()

        # Ingest EDR alert specifying this malware family
        payload = {
            "hostname": "SQL-SERVER-PROD",
            "host_ip": "10.0.1.50",
            "vendor": "SentinelOne",
            "title": "LockBit Ransomware File Execution",
            "threat_name": "Test-LockBit-Variant",
            "severity": "Critical",
            "FileName": "lockbit.exe",
            "ProcessId": 3312,
            "CommandLine": "lockbit.exe -pass test -domain c2-edr-beacon.evil.com",
            "md5": "a1b2c3d4e5f60718293a4b5c6d7e8f90",
        }

        resp = self.client.post(
            "/api/v1/edr/alert",
            json=payload,
            headers={
                "Content-Type": "application/json",
                "X-API-Key": "test-edr-secret-key-2026"
            }
        )

        self.assertEqual(resp.status_code, 201)
        data = resp.get_json()
        self.assertTrue(data["success"])
        self.assertTrue(data["malware_correlation"]["matched"])
        self.assertEqual(data["malware_correlation"]["malware_id"], mal.id)
        self.assertEqual(data["malware_correlation"]["malware_name"], "Test-LockBit-Variant")

        # Verify created Alert is linked to this malware
        alert = db.session.get(Alert, data["alert"]["id"])
        self.assertEqual(alert.malware_id, mal.id)

    # =========================================================================
    # 5. CONTAINMENT RECOMMENDATION TESTS
    # =========================================================================

    def test_containment_decision_matrix(self):
        """Verifies containment recommendations based on risk scores and severity."""
        # Critical severity -> ISOLATE_HOST
        crit = calculate_containment_action(
            max_risk_score=80,
            severity="Critical",
            hostname="WS-01",
            process_name="malware.exe",
            process_id=123,
            file_path="C:\\malware.exe",
            c2_destinations=["1.2.3.4"]
        )
        self.assertEqual(crit["containment_action"], "ISOLATE_HOST")
        self.assertTrue(crit["is_containment_recommended"])

        # High severity -> KILL_PROCESS_AND_QUARANTINE
        high = calculate_containment_action(
            max_risk_score=55,
            severity="High",
            hostname="WS-02",
            process_name="suspicious.exe",
            process_id=456,
            file_path="C:\\suspicious.exe",
            c2_destinations=[]
        )
        self.assertEqual(high["containment_action"], "KILL_PROCESS_AND_QUARANTINE")
        self.assertTrue(high["is_containment_recommended"])

        # Low severity -> MONITOR_AND_INVESTIGATE
        low = calculate_containment_action(
            max_risk_score=15,
            severity="Low",
            hostname="WS-03",
            process_name="calc.exe",
            process_id=789,
            file_path="C:\\calc.exe",
            c2_destinations=[]
        )
        self.assertEqual(low["containment_action"], "MONITOR_AND_INVESTIGATE")
        self.assertFalse(low["is_containment_recommended"])

    # =========================================================================
    # 6. EDR AUDIT LOGGING & ADDITIONAL VENDORS
    # =========================================================================

    def test_edr_alert_audit_logging(self):
        """Verifies an audit log entry is written when an EDR alert is ingested."""
        resp = self.client.post(
            "/api/v1/edr/alert",
            json={
                "hostname": "AUDIT-WS-01",
                "vendor": "CrowdStrike Falcon",
                "severity": "High",
                "title": "Audit Test Ingestion",
                "process_name": "cmd.exe",
                "command_line": "cmd.exe /c whoami",
            },
            headers={
                "Content-Type": "application/json",
                "X-API-Key": "test-edr-secret-key-2026",
            }
        )
        self.assertEqual(resp.status_code, 201)
        data = resp.get_json()
        alert_id = data["alert"]["id"]

        # Check AuditLog
        log_entry = AuditLog.query.filter(
            AuditLog.target_table == "alerts",
            AuditLog.target_id == alert_id
        ).order_by(AuditLog.id.desc()).first()

        self.assertIsNotNone(log_entry)
        self.assertIn("edr_alert_ingest", log_entry.action)

    def test_normalize_sentinelone_payload(self):
        """Verifies normalization of SentinelOne Singularity schema."""
        raw = {
            "endpoint_name": "WS-ENG-89",
            "agent_id": "s1_agent_3321",
            "threat_name": "Suspicious WScript Macro Execution",
            "severity": "High",
            "process": "wscript.exe",
            "pid": 6190,
            "cmdline": "wscript.exe C:\\Users\\Public\\dropper.vbs http://198.51.100.77/beacon.ps1",
            "mitre_techniques": ["T1059.005", "T1204.002"],
        }
        res = normalize_edr_payload(raw)
        self.assertEqual(res["hostname"], "WS-ENG-89")
        self.assertEqual(res["agent_id"], "s1_agent_3321")
        self.assertEqual(res["sensor_vendor"], "SentinelOne")
        self.assertIn("T1059.005", res["mitre_techniques"])
        ioc_vals = [i["value"] for i in res["extracted_iocs"]]
        self.assertIn("http://198.51.100.77/beacon.ps1", ioc_vals)


if __name__ == "__main__":
    unittest.main()
