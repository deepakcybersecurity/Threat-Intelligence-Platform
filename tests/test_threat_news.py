"""
Unit and Integration Tests for Task 7: Threat News Module
=========================================================
Verifies:
1. RSS 2.0 Feed Parsing (title, link, description, pubDate, categories)
2. Atom Feed Parsing (entry, alternate link, summary, updated)
3. HTML Entity Sanitization (&nbsp;, &rsquo;, &mdash; without parse errors)
4. Malformed Feed & Missing Field Handling (missing title, invalid URL, bad date)
5. NIST NVD API JSON Parsing (CVE ID, description, CVSS severity, portal link)
6. Date Parsing & UTC Normalization (RFC 2822, ISO 8601)
7. Deterministic Severity & Category Heuristics
8. ThreatNews Database Persistence
9. Duplicate Article Prevention (canonical URL & title-source uniqueness)
10. Source Failure & Timeout Resilience (partial failure does not halt other sources)
11. Search by Keyword in Title and Summary
12. Filtering by Category, Intelligence Source, and Severity
13. News Aggregation Facet Statistics
14. Authentication on Threat News Dashboard
15. Threat News Dashboard JSON API Output
16. Authorization on Refresh Endpoint (Admin/Analyst permitted, User rejected)
17. Safe Rendering of Untrusted Content (No unescaped HTML/XSS injection)
18. Optional IOC Extraction Bridge from News into ThreatIndicator
"""

from datetime import datetime
import json
import unittest
from unittest.mock import MagicMock, patch
import requests

from app import create_app, db
from app.models import User, ThreatNews, ThreatIndicator
from app.services.news_service import (
    clean_html_text,
    sanitize_xml_entities,
    parse_published_date,
    infer_severity,
    infer_category,
    parse_rss_feed,
    parse_nvd_api_response,
    fetch_news_from_source,
    fetch_and_store_threat_news,
    get_threat_news_filtered,
    get_news_stats,
    extract_news_iocs,
)


# Sample Mock Feeds
SAMPLE_RSS_20 = b"""<?xml version="1.0" encoding="UTF-8"?>
<rss version="2.0">
    <channel>
        <title>Mock Threat News</title>
        <link>https://mockthreat.example.com</link>
        <description>Cybersecurity news feed</description>
        <item>
            <title>Zero-Day Exploit in Enterprise Gateway Actively Exploited</title>
            <link>https://mockthreat.example.com/advisory-01</link>
            <description>&lt;p&gt;Attackers are leveraging an unauthenticated RCE flaw in VPN gateways. Patch immediately.&lt;/p&gt;</description>
            <pubDate>Fri, 09 Oct 2026 10:30:00 +0000</pubDate>
            <category>Zero-Day</category>
        </item>
        <item>
            <title>New Ransomware Strain Targets Healthcare Infrastructure</title>
            <link>https://mockthreat.example.com/ransomware-alert</link>
            <description>A new infostealer and ransomware campaign observed deploying payloads.</description>
            <pubDate>Thu, 08 Oct 2026 14:15:00 GMT</pubDate>
            <category>Malware</category>
        </item>
        <item>
            <title></title>
            <link>https://mockthreat.example.com/no-title</link>
            <description>This item has an empty title and should be skipped.</description>
        </item>
        <item>
            <title>Item with Invalid Link</title>
            <link>not-a-valid-url</link>
            <description>This item has an invalid URL and should be skipped.</description>
        </item>
    </channel>
</rss>
"""

SAMPLE_ATOM_FEED = b"""<?xml version="1.0" encoding="utf-8"?>
<feed xmlns="http://www.w3.org/2005/Atom">
    <title>Mock Atom Advisory Stream</title>
    <entry>
        <title>Nation-State APT Campaign Exploiting Cloud Credentials</title>
        <link rel="alternate" href="https://mockatom.example.com/apt-cloud"/>
        <summary type="html">Sophisticated threat actors compromised IAM roles using stolen refresh tokens.</summary>
        <updated>2026-10-09T18:45:00Z</updated>
        <category term="APT Campaign"/>
    </entry>
</feed>
"""

SAMPLE_XML_WITH_HTML_ENTITIES = b"""<?xml version="1.0" encoding="UTF-8"?>
<rss version="2.0">
    <channel>
        <title>Entity Test Feed</title>
        <item>
            <title>Security Alert: &ldquo;Critical&rdquo; Flaw Found &mdash; Details Inside</title>
            <link>https://mockthreat.example.com/entity-item</link>
            <description>Details regarding vendor&rsquo;s update&nbsp;and workaround&hellip;</description>
            <pubDate>Sat, 10 Oct 2026 05:00:00 +0000</pubDate>
        </item>
    </channel>
</rss>
"""

SAMPLE_NVD_JSON = {
    "totalResults": 1,
    "vulnerabilities": [
        {
            "cve": {
                "id": "CVE-2026-9999",
                "descriptions": [
                    {
                        "lang": "en",
                        "value": "Buffer overflow vulnerability in mock system daemon permits unauthenticated remote code execution.",
                    }
                ],
                "published": "2026-10-09T12:00:00.000",
                "metrics": {
                    "cvssMetricV31": [
                        {
                            "cvssData": {
                                "baseScore": 9.8,
                                "baseSeverity": "CRITICAL",
                            }
                        }
                    ]
                },
            }
        }
    ],
}

SAMPLE_BLEEPINGCOMPUTER_RSS = b"""<?xml version="1.0" encoding="utf-8"?>
<rss version="2.0" xmlns:content="http://purl.org/rss/1.0/modules/content/" xmlns:dc="http://purl.org/dc/elements/1.1/">
    <channel>
        <title>BleepingComputer</title>
        <link>https://www.bleepingcomputer.com/</link>
        <description>BleepingComputer cybersecurity news</description>
        <item>
            <title>Nippon Columbia malware incident exposes 8.6 million records</title>
            <link>https://www.bleepingcomputer.com/news/security/nippon-columbia-incident/</link>
            <description>A malware infection exposed millions of customer records including personal data.</description>
            <pubDate>Sun, 11 Oct 2026 10:23:46 -0400</pubDate>
            <category>Security</category>
        </item>
        <item>
            <title>State-Sponsored Hackers Exploit Zero-Day in VPN Appliances</title>
            <link>https://www.bleepingcomputer.com/news/security/vpn-zero-day-exploit/</link>
            <description>Nation-state actors are actively targeting unpatched gateway devices.</description>
            <pubDate>Sat, 10 Oct 2026 14:15:00 -0400</pubDate>
            <category>Zero-Day</category>
        </item>
    </channel>
</rss>
"""

SAMPLE_CISA_RSS = b"""<?xml version="1.0" encoding="UTF-8"?>
<rss version="2.0">
    <channel>
        <title>Cybersecurity Advisories | CISA</title>
        <link>https://www.cisa.gov/cybersecurity-advisories</link>
        <description>Current cybersecurity alerts and advisories from CISA</description>
        <item>
            <title>CISA Advisory AA26-284A: Advanced Persistent Threat Actors Compromise Critical Systems</title>
            <link>https://www.cisa.gov/news-events/cybersecurity-advisories/aa26-284a</link>
            <description>CISA and international partners released a joint advisory regarding state-sponsored cyber operations.</description>
            <pubDate>Wed, 07 Oct 2026 14:00:00 +0000</pubDate>
            <category>Advisory</category>
        </item>
    </channel>
</rss>
"""

SAMPLE_MALFORMED_XML = b"""<?xml version="1.0"?><rss><channel><title>Malformed Feed<item><title>Unclosed tag"""


class TestThreatNewsModule(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.app = create_app()
        cls.app.config["TESTING"] = True
        cls.app.config["WTF_CSRF_ENABLED"] = False
        cls.client = cls.app.test_client()
        from app.services.security_service import assert_safe_test_database
        assert_safe_test_database(cls.app)

    def setUp(self):
        self.app_context = self.app.app_context()
        self.app_context.push()

        # Create or find test analyst user
        self.analyst = User.query.filter_by(email="news_analyst@test.com").first()
        if not self.analyst:
            self.analyst = User(
                username="news_analyst",
                email="news_analyst@test.com",
                password_hash="pbkdf2:sha256:dummyhash",
                role="analyst",
            )
            db.session.add(self.analyst)

        # Create or find test regular user
        self.regular_user = User.query.filter_by(email="news_user@test.com").first()
        if not self.regular_user:
            self.regular_user = User(
                username="news_user",
                email="news_user@test.com",
                password_hash="pbkdf2:sha256:dummyhash",
                role="user",
            )
            db.session.add(self.regular_user)

        db.session.commit()
        self.client = self.app.test_client()
        self._cleanup()

    def tearDown(self):
        db.session.rollback()
        self._cleanup()
        self.app_context.pop()

    def _cleanup(self):
        # Scoped cleanup: Remove ONLY test news articles and test indicators created in tests
        test_articles = ThreatNews.query.filter(
            (ThreatNews.source.like("Mock%"))
            | (ThreatNews.title.like("TEST_%"))
            | (ThreatNews.title.like("Zero-Day%"))
            | (ThreatNews.title.like("New Ransomware%"))
            | (ThreatNews.title.like("Security Alert:%"))
            | (ThreatNews.title.like("Nation-State%"))
            | (ThreatNews.title.like("CVE-2026-9999%"))
            | (ThreatNews.title.like("%Nippon Columbia%"))
            | (ThreatNews.title.like("%State-Sponsored Hackers Exploit Zero-Day%"))
            | (ThreatNews.title.like("%CISA Advisory AA26-284A%"))
            | (ThreatNews.source_url.like("%nippon-columbia-incident%"))
            | (ThreatNews.source_url.like("%vpn-zero-day-exploit%"))
            | (ThreatNews.source_url.like("%aa26-284a%"))
            | (ThreatNews.source_url.like("%example.com%"))
        ).all()
        for a in test_articles:
            db.session.delete(a)

        test_indicators = ThreatIndicator.query.filter(
            ThreatIndicator.context.like("%Mock%") | ThreatIndicator.source.like("News: Mock%")
        ).all()
        for ind in test_indicators:
            ind.reports.clear()
            ind.malwares.clear()
            db.session.delete(ind)

        db.session.commit()

    def _login(self, user):
        with self.client.session_transaction() as sess:
            sess["_user_id"] = str(user.id)
            sess["_fresh"] = True

    # =========================================================================
    # 1. RSS & ATOM PARSING TESTS
    # =========================================================================

    def test_parse_rss_20_feed(self):
        """Verifies parsing of standard RSS 2.0 items, skipping invalid links and empty titles."""
        articles = parse_rss_feed(SAMPLE_RSS_20, "Mock RSS Source")
        self.assertEqual(len(articles), 2, "Expected exactly 2 valid articles parsed")

        art1 = articles[0]
        self.assertEqual(art1["title"], "Zero-Day Exploit in Enterprise Gateway Actively Exploited")
        self.assertEqual(art1["source_url"], "https://mockthreat.example.com/advisory-01")
        self.assertIn("Attackers are leveraging an unauthenticated RCE flaw", art1["summary"])
        self.assertNotIn("<p>", art1["summary"], "HTML tags must be cleaned")
        self.assertEqual(art1["severity"], "Critical")
        self.assertEqual(art1["category"], "Zero-Day")

        art2 = articles[1]
        self.assertEqual(art2["title"], "New Ransomware Strain Targets Healthcare Infrastructure")
        self.assertEqual(art2["category"], "Malware")
        self.assertEqual(art2["severity"], "High")

    def test_parse_atom_feed(self):
        """Verifies parsing of Atom feeds with namespaces and alternate link attributes."""
        articles = parse_rss_feed(SAMPLE_ATOM_FEED, "Mock Atom Source")
        self.assertEqual(len(articles), 1)
        art = articles[0]
        self.assertEqual(art["title"], "Nation-State APT Campaign Exploiting Cloud Credentials")
        self.assertEqual(art["source_url"], "https://mockatom.example.com/apt-cloud")
        self.assertEqual(art["category"], "Apt Campaign")
        self.assertEqual(art["severity"], "High")
        self.assertIsNotNone(art["published_at"])

    def test_parse_xml_with_html_entities(self):
        """Verifies that undeclared HTML entities (&rdquo;, &mdash;, &nbsp;) do not raise XML errors."""
        articles = parse_rss_feed(SAMPLE_XML_WITH_HTML_ENTITIES, "Mock Entity Source")
        self.assertEqual(len(articles), 1)
        art = articles[0]
        self.assertIn("Critical", art["title"])
        self.assertIn("workaround", art["summary"])

    def test_parse_nvd_api_response(self):
        """Verifies parsing of NIST NVD CVE JSON response."""
        articles = parse_nvd_api_response(SAMPLE_NVD_JSON, "Mock NVD")
        self.assertEqual(len(articles), 1)
        art = articles[0]
        self.assertTrue(art["title"].startswith("CVE-2026-9999"))
        self.assertEqual(art["source_url"], "https://nvd.nist.gov/vuln/detail/CVE-2026-9999")
        self.assertEqual(art["category"], "Vulnerability")
        self.assertEqual(art["severity"], "Critical")

    # =========================================================================
    # 2. UTILITY & NORMALIZATION TESTS
    # =========================================================================

    def test_clean_html_text(self):
        """Verifies HTML tag stripping, script elimination, and whitespace normalization."""
        raw = "<p>Malware <script>alert(1)</script> detected at <b>evil.com</b>.&nbsp;Action needed.</p>"
        cleaned = clean_html_text(raw)
        self.assertNotIn("<script>", cleaned)
        self.assertNotIn("alert(1)", cleaned)
        self.assertNotIn("<p>", cleaned)
        self.assertIn("Malware detected at evil.com. Action needed.", cleaned)

    def test_date_parsing_rfc_and_iso(self):
        """Verifies parsing of RFC 2822 and ISO 8601 dates to UTC datetime."""
        d1 = parse_published_date("Fri, 09 Oct 2026 14:30:00 +0000")
        self.assertIsNotNone(d1)
        self.assertEqual(d1.year, 2026)
        self.assertEqual(d1.month, 10)
        self.assertEqual(d1.day, 9)

        d2 = parse_published_date("2026-10-09T18:45:00Z")
        self.assertIsNotNone(d2)
        self.assertEqual(d2.hour, 18)
        self.assertEqual(d2.minute, 45)

        d_invalid = parse_published_date("not-a-valid-date-string")
        self.assertIsNone(d_invalid)

    def test_severity_heuristics(self):
        """Verifies deterministic keyword-based severity assignments."""
        self.assertEqual(infer_severity("Zero-Day in Chrome", "Actively exploited in the wild"), "Critical")
        self.assertEqual(infer_severity("Privilege Escalation in Linux Kernel", "Remote code execution flaw"), "High")
        self.assertEqual(infer_severity("Phishing Campaign impersonating IT", "Users targeted with fake login"), "Medium")
        self.assertEqual(infer_severity("General Security Bulletin", "Quarterly overview"), "Low")

    # =========================================================================
    # 3. DATABASE PERSISTENCE & DEDUPLICATION TESTS
    # =========================================================================

    @patch("app.services.news_service.requests.get")
    def test_fetch_and_store_threat_news_persistence_and_deduplication(self, mock_get):
        """Verifies that articles are saved to DB and second fetch skips duplicates."""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.content = SAMPLE_RSS_20
        mock_get.return_value = mock_response

        mock_sources = [
            {
                "id": "mock_source_1",
                "name": "Mock News Feed",
                "type": "rss",
                "url": "https://mockthreat.example.com/feed.xml",
                "enabled": True,
                "default_category": "Advisory",
                "default_severity": "Low",
            }
        ]

        # 1. First fetch
        res1 = fetch_and_store_threat_news(sources=mock_sources)
        self.assertTrue(res1["success"])
        self.assertEqual(res1["new_articles"], 2)
        self.assertEqual(res1["skipped_duplicates"], 0)

        # Confirm persisted in DB
        db_records = ThreatNews.query.filter_by(source="Mock News Feed").all()
        self.assertEqual(len(db_records), 2)

        # 2. Second fetch with identical content (deduplication check)
        res2 = fetch_and_store_threat_news(sources=mock_sources)
        self.assertTrue(res2["success"])
        self.assertEqual(res2["new_articles"], 0, "No duplicate articles should be added")
        self.assertEqual(res2["skipped_duplicates"], 2, "Both items should be counted as skipped")

        # Confirm DB still has exactly 2 records
        db_records_after = ThreatNews.query.filter_by(source="Mock News Feed").all()
        self.assertEqual(len(db_records_after), 2)

    @patch("app.services.news_service.requests.get")
    def test_source_failure_resilience(self, mock_get):
        """Verifies that failure in one source does not prevent other sources from importing."""
        def side_effect(url, **kwargs):
            if "broken" in url:
                raise requests.exceptions.ConnectionError("Connection timed out to broken feed")
            resp = MagicMock()
            resp.status_code = 200
            resp.content = SAMPLE_ATOM_FEED
            return resp

        mock_get.side_effect = side_effect

        mock_sources = [
            {
                "id": "broken_source",
                "name": "Mock Broken Source",
                "type": "rss",
                "url": "https://broken.example.com/feed.xml",
                "enabled": True,
            },
            {
                "id": "working_source",
                "name": "Mock Working Atom Source",
                "type": "rss",
                "url": "https://working.example.com/atom.xml",
                "enabled": True,
            },
        ]

        res = fetch_and_store_threat_news(sources=mock_sources)
        self.assertTrue(res["success"])
        self.assertEqual(res["new_articles"], 1)
        self.assertEqual(len(res["errors"]), 1)
        self.assertEqual(res["errors"][0]["source"], "Mock Broken Source")

    # =========================================================================
    # 4. FILTERING & STATS TESTS
    # =========================================================================

    def test_search_and_filtering(self):
        """Verifies title/summary search, category filtering, and severity filtering."""
        # Insert test articles
        a1 = ThreatNews(
            title="TEST_APT29 Spearfishing Campaign Discovered",
            source="Mock Source A",
            source_url="https://mock.com/1",
            summary="Targeted spear-phishing emails containing malicious macros.",
            category="APT Campaign",
            severity="High",
            published_at=datetime(2026, 10, 8, 12, 0, 0),
        )
        a2 = ThreatNews(
            title="TEST_Critical Zero-Day in Web Server",
            source="Mock Source B",
            source_url="https://mock.com/2",
            summary="Emergency patch released for remote exploit flaw.",
            category="Vulnerability",
            severity="Critical",
            published_at=datetime(2026, 10, 9, 12, 0, 0),
        )
        db.session.add_all([a1, a2])
        db.session.commit()

        # Search by keyword
        res_search = get_threat_news_filtered(query_text="Spearfishing").items
        self.assertEqual(len(res_search), 1)
        self.assertEqual(res_search[0].title, a1.title)

        # Filter by category
        res_cat = get_threat_news_filtered(category="Vulnerability").items
        self.assertIn(a2.id, [x.id for x in res_cat])

        # Filter by severity
        res_sev = get_threat_news_filtered(severity="Critical").items
        self.assertIn(a2.id, [x.id for x in res_sev])

        # Filter by source
        res_src = get_threat_news_filtered(source="Mock Source A").items
        self.assertIn(a1.id, [x.id for x in res_src])

    def test_get_news_stats(self):
        """Verifies summary statistics computation."""
        a = ThreatNews(
            title="TEST_Stats_Article",
            source="Mock Stats Source",
            source_url="https://mock.com/stats",
            summary="Summary text",
            category="Advisory",
            severity="Medium",
            published_at=datetime(2026, 10, 10, 1, 0, 0),
        )
        db.session.add(a)
        db.session.commit()

        stats = get_news_stats()
        self.assertGreaterEqual(stats["total"], 1)
        self.assertIn("Advisory", stats["categories"])
        self.assertIn("Mock Stats Source", stats["sources"])

    # =========================================================================
    # 5. DASHBOARD ROUTES & AUTHORIZATION TESTS
    # =========================================================================

    def test_threat_news_dashboard_route_auth_required(self):
        """Verifies that unauthenticated requests to /threat-news are redirected to login."""
        unauth_client = self.app.test_client()
        resp = unauth_client.get("/threat-news")
        self.assertEqual(resp.status_code, 302)
        self.assertIn("/login", resp.headers["Location"])

    def test_threat_news_dashboard_authenticated(self):
        """Verifies that authenticated analyst can view Threat News dashboard."""
        self._login(self.analyst)
        resp = self.client.get("/threat-news")
        self.assertEqual(resp.status_code, 200)
        html = resp.get_data(as_text=True)
        self.assertIn("Cybersecurity Threat News", html)
        self.assertIn("Fetch Latest News", html)

    def test_threat_news_json_format(self):
        """Verifies that format=json parameter returns structured JSON payload."""
        self._login(self.analyst)
        resp = self.client.get("/threat-news?format=json")
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertTrue(data.get("success"))
        self.assertIn("articles", data)
        self.assertIn("stats", data)

    def test_refresh_route_regular_user_forbidden(self):
        """Verifies that regular users are blocked from refreshing news."""
        self._login(self.regular_user)
        resp_user = self.client.post("/threat-news/refresh", follow_redirects=True)
        self.assertEqual(resp_user.status_code, 200)
        self.assertIn("Unauthorized", resp_user.get_data(as_text=True))

    def test_refresh_route_analyst_authorized(self):
        """Verifies that analysts can refresh news and receive success flash message."""
        self._login(self.analyst)
        with patch("app.dashboard.routes.fetch_and_store_threat_news") as mock_fetch:
            mock_fetch.return_value = {
                "success": True,
                "new_articles": 5,
                "skipped_duplicates": 10,
                "errors": [],
            }
            resp_analyst = self.client.post("/threat-news/refresh", follow_redirects=True)
            self.assertEqual(resp_analyst.status_code, 200)
            self.assertIn("Threat news updated", resp_analyst.get_data(as_text=True))

    def test_safe_rendering_of_untrusted_html(self):
        """Verifies that article text with XSS payloads is escaped in template rendering."""
        xss_article = ThreatNews(
            title="TEST_XSS <script>alert('xss-title')</script>",
            source="Mock Untrusted",
            source_url="https://mock.com/xss",
            summary="Attack summary containing <img src=x onerror=alert('xss-body')> and plain text.",
            category="Malware",
            severity="High",
            published_at=datetime.utcnow(),
        )
        db.session.add(xss_article)
        db.session.commit()

        self._login(self.analyst)
        resp = self.client.get("/threat-news")
        html = resp.get_data(as_text=True)

        # Unescaped executable script tags must NOT appear
        self.assertNotIn("<script>alert('xss-title')</script>", html)
        self.assertNotIn("<img src=x onerror=alert('xss-body')>", html)

    # =========================================================================
    # 6. OPTIONAL IOC EXTRACTION BRIDGE TESTS (Section 7)
    # =========================================================================

    def test_extract_news_iocs_bridge(self):
        """Verifies Section 7 integration: extracting IOCs from ThreatNews into ThreatIndicator."""
        ioc_article = ThreatNews(
            title="TEST_C2 Infrastructure and Malware Hash Detected",
            source="Mock Intelligence Stream",
            source_url="https://mock.com/ioc-article",
            summary=(
                "Advisory reports active command and control server at 198.51.100.77. "
                "The malicious payload connects to bad-malware-domain.org with MD5 "
                "0123456789abcdef0123456789abcdef."
            ),
            category="Malware",
            severity="High",
            published_at=datetime.utcnow(),
        )
        db.session.add(ioc_article)
        db.session.commit()

        # Run extraction
        res = extract_news_iocs(ioc_article.id, self.analyst.id)
        self.assertTrue(res["success"])
        self.assertEqual(res["total_extracted"], 3)  # IP, domain, MD5
        self.assertEqual(res["created"], 3)

        # Verify indicators persisted in ThreatIndicator
        ind_ip = ThreatIndicator.query.filter_by(indicator_value="198.51.100.77").first()
        self.assertIsNotNone(ind_ip)
        self.assertEqual(ind_ip.indicator_type, "ipv4")
        self.assertEqual(ind_ip.source, "News: Mock Intelligence Stream")
        self.assertEqual(ind_ip.severity, "High")

        ind_domain = ThreatIndicator.query.filter_by(indicator_value="bad-malware-domain.org").first()
        self.assertIsNotNone(ind_domain)
        self.assertEqual(ind_domain.indicator_type, "domain")

        ind_hash = ThreatIndicator.query.filter_by(indicator_value="0123456789abcdef0123456789abcdef").first()
        self.assertIsNotNone(ind_hash)
        self.assertEqual(ind_hash.indicator_type, "md5")

        # Second extraction reuses indicators instead of duplicating
        res2 = extract_news_iocs(ioc_article.id, self.analyst.id)
        self.assertTrue(res2["success"])
        self.assertEqual(res2["created"], 0)
        self.assertEqual(res2["reused"], 3)

    # =========================================================================
    # 7. CISA & BLEEPINGCOMPUTER SOURCE TESTS (REQUIREMENT 6)
    # =========================================================================

    def test_news_sources_registry_configuration(self):
        """Verifies that BleepingComputer is enabled and CISA is documented as disabled due to WAF 403."""
        from app.services.news_service import NEWS_SOURCES
        bc = next((s for s in NEWS_SOURCES if s["id"] == "bleepingcomputer"), None)
        self.assertIsNotNone(bc, "BleepingComputer must be configured in NEWS_SOURCES")
        self.assertTrue(bc.get("enabled"), "BleepingComputer should be enabled")
        self.assertEqual(bc.get("url"), "https://www.bleepingcomputer.com/feed/")

        cisa = next((s for s in NEWS_SOURCES if s["id"] == "cisa"), None)
        self.assertIsNotNone(cisa, "CISA must be configured in NEWS_SOURCES")
        self.assertFalse(cisa.get("enabled"), "CISA must remain disabled because upstream WAF returns HTTP 403")
        self.assertEqual(cisa.get("url"), "https://www.cisa.gov/cybersecurity-advisories/all.xml")

    @patch("app.services.news_service.requests.get")
    def test_bleepingcomputer_feed_parsing_and_persistence(self, mock_get):
        """Verifies successful RSS parsing and DB persistence for BleepingComputer."""
        resp = MagicMock()
        resp.status_code = 200
        resp.content = SAMPLE_BLEEPINGCOMPUTER_RSS
        mock_get.return_value = resp

        bc_source = [
            {
                "id": "bleepingcomputer",
                "name": "BleepingComputer",
                "type": "rss",
                "url": "https://www.bleepingcomputer.com/feed/",
                "enabled": True,
                "default_category": "Data Breach",
                "default_severity": "High",
            }
        ]

        res = fetch_and_store_threat_news(sources=bc_source)
        self.assertTrue(res["success"])
        self.assertEqual(res["new_articles"], 2)
        self.assertEqual(res["skipped_duplicates"], 0)

        # Verify DB records
        articles = ThreatNews.query.filter_by(source="BleepingComputer").order_by(ThreatNews.id.asc()).all()
        self.assertEqual(len(articles), 2)

        # Article 1: malware incident -> High severity, Security category
        art1 = articles[0]
        self.assertEqual(art1.title, "Nippon Columbia malware incident exposes 8.6 million records")
        self.assertEqual(art1.source_url, "https://www.bleepingcomputer.com/news/security/nippon-columbia-incident/")
        self.assertEqual(art1.category, "Security")
        self.assertEqual(art1.severity, "High")
        self.assertIn("malware infection exposed millions", art1.summary)

        # Article 2: Zero-Day -> Critical severity, Zero-Day category
        art2 = articles[1]
        self.assertEqual(art2.title, "State-Sponsored Hackers Exploit Zero-Day in VPN Appliances")
        self.assertEqual(art2.category, "Zero-Day")
        self.assertEqual(art2.severity, "Critical")

    @patch("app.services.news_service.requests.get")
    def test_bleepingcomputer_duplicate_articles_prevented(self, mock_get):
        """Verifies duplicate article prevention on consecutive BleepingComputer fetches."""
        resp = MagicMock()
        resp.status_code = 200
        resp.content = SAMPLE_BLEEPINGCOMPUTER_RSS
        mock_get.return_value = resp

        bc_source = [
            {
                "id": "bleepingcomputer",
                "name": "BleepingComputer",
                "type": "rss",
                "url": "https://www.bleepingcomputer.com/feed/",
                "enabled": True,
                "default_category": "Data Breach",
                "default_severity": "High",
            }
        ]

        # First run creates 2
        res1 = fetch_and_store_threat_news(sources=bc_source)
        self.assertEqual(res1["new_articles"], 2)

        # Second run skips duplicates
        res2 = fetch_and_store_threat_news(sources=bc_source)
        self.assertEqual(res2["new_articles"], 0)
        self.assertEqual(res2["skipped_duplicates"], 2)

        # DB count remains 2
        count = ThreatNews.query.filter_by(source="BleepingComputer").count()
        self.assertEqual(count, 2)

    @patch("app.services.news_service.requests.get")
    def test_cisa_feed_parsing_when_accessible(self, mock_get):
        """Verifies parsing and persistence of CISA feed when valid RSS is provided."""
        resp = MagicMock()
        resp.status_code = 200
        resp.content = SAMPLE_CISA_RSS
        mock_get.return_value = resp

        cisa_source = [
            {
                "id": "cisa",
                "name": "CISA Cybersecurity Advisories",
                "type": "rss",
                "url": "https://www.cisa.gov/cybersecurity-advisories/all.xml",
                "enabled": True,
                "default_category": "Advisory",
                "default_severity": "High",
            }
        ]

        res = fetch_and_store_threat_news(sources=cisa_source)
        self.assertTrue(res["success"])
        self.assertEqual(res["new_articles"], 1)

        record = ThreatNews.query.filter_by(source="CISA Cybersecurity Advisories").first()
        self.assertIsNotNone(record)
        self.assertIn("AA26-284A", record.title)
        self.assertEqual(record.category, "Advisory")
        self.assertEqual(record.severity, "High")

    @patch("app.services.news_service.requests.get")
    def test_cisa_http_403_access_denied_handling_and_pipeline_resilience(self, mock_get):
        """
        Verifies that HTTP 403 Access Denied from CISA upstream WAF is caught,
        logged cleanly, reported in errors, and does not stop other working feeds.
        """
        def side_effect(url, **kwargs):
            if "cisa.gov" in url:
                mock_403_resp = MagicMock()
                mock_403_resp.status_code = 403
                mock_403_resp.content = b"<HTML><HEAD><TITLE>Access Denied</TITLE></HEAD></HTML>"
                err = requests.exceptions.HTTPError("403 Client Error: Forbidden for url: " + url)
                err.response = mock_403_resp
                raise err
            else:
                resp = MagicMock()
                resp.status_code = 200
                resp.content = SAMPLE_BLEEPINGCOMPUTER_RSS
                return resp

        mock_get.side_effect = side_effect

        sources = [
            {
                "id": "cisa",
                "name": "CISA Cybersecurity Advisories",
                "type": "rss",
                "url": "https://www.cisa.gov/cybersecurity-advisories/all.xml",
                "enabled": True,  # Test failure handling when enabled
            },
            {
                "id": "bleepingcomputer",
                "name": "BleepingComputer",
                "type": "rss",
                "url": "https://www.bleepingcomputer.com/feed/",
                "enabled": True,
            },
        ]

        res = fetch_and_store_threat_news(sources=sources)
        self.assertTrue(res["success"])
        self.assertEqual(res["new_articles"], 2, "BleepingComputer articles should still import")
        self.assertEqual(len(res["errors"]), 1)
        self.assertEqual(res["errors"][0]["source"], "CISA Cybersecurity Advisories")
        self.assertIn("403", res["errors"][0]["error"])

    @patch("app.services.news_service.requests.get")
    def test_cisa_and_bleepingcomputer_malformed_xml_handling(self, mock_get):
        """Verifies graceful error handling when feeds return malformed XML."""
        resp = MagicMock()
        resp.status_code = 200
        resp.content = SAMPLE_MALFORMED_XML
        mock_get.return_value = resp

        sources = [
            {
                "id": "cisa",
                "name": "CISA Cybersecurity Advisories",
                "type": "rss",
                "url": "https://www.cisa.gov/cybersecurity-advisories/all.xml",
                "enabled": True,
            },
            {
                "id": "bleepingcomputer",
                "name": "BleepingComputer",
                "type": "rss",
                "url": "https://www.bleepingcomputer.com/feed/",
                "enabled": True,
            },
        ]

        res = fetch_and_store_threat_news(sources=sources)
        self.assertTrue(res["success"])
        self.assertEqual(res["new_articles"], 0)
        self.assertEqual(len(res["errors"]), 2)
        for err in res["errors"]:
            self.assertIn("ParseError", err["error"])

    @patch("app.services.news_service.requests.get")
    def test_cisa_and_bleepingcomputer_network_timeout_handling(self, mock_get):
        """Verifies graceful handling when network requests time out."""
        mock_get.side_effect = requests.exceptions.Timeout("Connection timed out to feed server")

        sources = [
            {
                "id": "bleepingcomputer",
                "name": "BleepingComputer",
                "type": "rss",
                "url": "https://www.bleepingcomputer.com/feed/",
                "enabled": True,
            }
        ]

        res = fetch_and_store_threat_news(sources=sources)
        self.assertTrue(res["success"])
        self.assertEqual(res["new_articles"], 0)
        self.assertEqual(len(res["errors"]), 1)
        self.assertEqual(res["errors"][0]["source"], "BleepingComputer")
        self.assertIn("Timeout", res["errors"][0]["error"])


if __name__ == "__main__":
    unittest.main()
