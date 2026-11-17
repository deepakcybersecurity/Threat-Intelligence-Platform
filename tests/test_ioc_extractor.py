"""
Unit Tests for IOC Extraction Service (Task 1)
==============================================
Verifies all required test cases specified in Task 1:
- Test 1: IPv4 address detection & validation
- Test 2: Domain name detection & validation
- Test 3: Complete URL detection & domain suppression
- Test 4: Cryptographic hash detection (MD5, SHA1, SHA256)
- Test 5: Multiple IOC detection in compound report text
- Test 6: Duplicate IOC deduplication
- Test 7: Empty and invalid input handling
- Additional tests: False positive controls (invalid IPs, file extensions, non-hex strings, punctuation)
"""

import unittest
from app.services.ioc_extractor import extract_iocs


class TestIOCExtractor(unittest.TestCase):

    def test_1_ipv4(self):
        """TEST 1: IPv4 address extraction and validation."""
        text = "Suspicious connection from 192.168.1.10"
        result = extract_iocs(text)
        expected = [{"type": "ipv4", "value": "192.168.1.10"}]
        self.assertEqual(result, expected)

    def test_2_domain(self):
        """TEST 2: Domain name extraction."""
        text = "Malicious domain evil-example.com was observed."
        result = extract_iocs(text)
        expected = [{"type": "domain", "value": "evil-example.com"}]
        self.assertEqual(result, expected)

    def test_3_url(self):
        """TEST 3: URL extraction without duplicate domain extraction."""
        text = "Payload downloaded from https://evil-example.com/payload.exe"
        result = extract_iocs(text)
        expected = [{"type": "url", "value": "https://evil-example.com/payload.exe"}]
        self.assertEqual(result, expected)
        # Ensure evil-example.com is NOT separately extracted as domain
        types = [i["type"] for i in result]
        self.assertNotIn("domain", types)

    def test_4_hashes(self):
        """TEST 4: Exact-length MD5, SHA1, and SHA256 hashes."""
        md5_sample = "44d88612fea8a8f36de82e1278abb02f"
        sha1_sample = "a9993e364706816aba3e25717850c26c9cd0d89d"
        sha256_sample = "275a5071de6e79cd437d32e6f007e7729d2b2fe2e317180bc3946ac614289cfa"

        text = f"Analyzed binary with MD5 {md5_sample}, SHA1 {sha1_sample}, and SHA256 {sha256_sample}."
        result = extract_iocs(text)

        result_map = {item["type"]: item["value"] for item in result}
        self.assertIn("md5", result_map)
        self.assertEqual(result_map["md5"], md5_sample)
        self.assertIn("sha1", result_map)
        self.assertEqual(result_map["sha1"], sha1_sample)
        self.assertIn("sha256", result_map)
        self.assertEqual(result_map["sha256"], sha256_sample)

    def test_5_multiple_iocs(self):
        """TEST 5: Multiple correctly classified IOCs in a single narrative."""
        text = "185.220.101.45 contacted evil-example.com and downloaded https://evil-example.com/a.exe."
        result = extract_iocs(text)

        values_by_type = {item["type"]: item["value"] for item in result}
        self.assertEqual(values_by_type.get("ipv4"), "185.220.101.45")
        self.assertEqual(values_by_type.get("domain"), "evil-example.com")
        self.assertEqual(values_by_type.get("url"), "https://evil-example.com/a.exe")
        self.assertEqual(len(result), 3)

    def test_6_duplicate_ioc(self):
        """TEST 6: Duplicate IOC occurrences are deduplicated."""
        text = "The IP 185.220.101.45 contacted 185.220.101.45."
        result = extract_iocs(text)
        expected = [{"type": "ipv4", "value": "185.220.101.45"}]
        self.assertEqual(result, expected)

    def test_7_empty_input(self):
        """TEST 7: Empty or non-string input returns an empty list without exception."""
        self.assertEqual(extract_iocs(""), [])
        self.assertEqual(extract_iocs("   "), [])
        self.assertEqual(extract_iocs(None), [])
        self.assertEqual(extract_iocs(12345), [])

    def test_false_positives_invalid_ipv4(self):
        """Verify that invalid IPv4 octets (>255) and non-IP dotted numbers are rejected."""
        text = "Invalid IPs: 999.999.999.999 and 256.100.0.1 and 1.2.3.4.5"
        result = extract_iocs(text)
        ip_values = [i["value"] for i in result if i["type"] == "ipv4"]
        self.assertEqual(ip_values, [])

    def test_false_positives_file_extensions(self):
        """Verify that common executable/document file extensions are not classified as domains."""
        text = "Downloaded payload.exe, document.pdf, script.py, and library.dll"
        result = extract_iocs(text)
        domain_values = [i["value"] for i in result if i["type"] == "domain"]
        self.assertEqual(domain_values, [])

    def test_false_positives_non_hex_hashes(self):
        """Verify that non-hexadecimal 32-character strings are not classified as MD5."""
        # 32 characters long, but contains non-hex letters (g, z, y, etc.)
        non_hex_string = "zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz"
        text = f"String is {non_hex_string}"
        result = extract_iocs(text)
        hash_values = [i["value"] for i in result if i["type"] in ("md5", "sha1", "sha256")]
        self.assertEqual(hash_values, [])

    def test_punctuation_stripping(self):
        """Verify that trailing periods, commas, parentheses, and quotes are correctly stripped."""
        text = "Found (10.0.0.1), [evil-threat.com], and 'https://malicious.org/drop.bin'."
        result = extract_iocs(text)
        val_set = {i["value"] for i in result}
        self.assertIn("10.0.0.1", val_set)
        self.assertIn("evil-threat.com", val_set)
        self.assertIn("https://malicious.org/drop.bin", val_set)


if __name__ == "__main__":
    unittest.main()
