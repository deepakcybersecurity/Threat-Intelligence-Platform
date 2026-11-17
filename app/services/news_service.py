"""
Threat News Aggregation & Ingestion Service
===========================================
Fetches, normalizes, deduplicates, and persists cybersecurity news,
vulnerability advisories, and threat intelligence alerts from public RSS
feeds and REST APIs.

Features:
- Multi-source configurable registry (The Hacker News, SANS ISC, Krebs on Security,
  Dark Reading, NIST NVD, CISA Advisories).
- Robust XML / RSS 2.0 / Atom feed parsing using standard library xml.etree.ElementTree.
- Entity decoding and clean HTML tag stripping.
- RFC 2822 and ISO 8601 date parsing with UTC normalization.
- Deterministic severity and category classification heuristics.
- Duplicate prevention using canonical URLs and title-source uniqueness.
- Transactional persistence and granular import telemetry.
- Full text search, multi-factor filtering, and pagination support.
- Optional IOC extraction bridge integrating with ThreatIndicator and Alert pipelines.
"""

from datetime import datetime, timezone
import email.utils
import html
import html.entities
import logging
import re
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

import requests
from sqlalchemy import func, or_

from app import db
from app.models import ThreatNews, ThreatIndicator
from app.services.ioc_extractor import extract_iocs

logger = logging.getLogger(__name__)

# Default network timeout for news fetching
DEFAULT_TIMEOUT = 10

# Request headers identifying the platform cleanly
DEFAULT_HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/120.0.0.0 Safari/537.36 (ThreatIntelPlatform/1.0)"
    ),
    "Accept": "application/rss+xml, application/xml, text/xml, application/json, */*",
}

# Configurable news sources registry
NEWS_SOURCES = [
    {
        "id": "thehackernews",
        "name": "The Hacker News",
        "type": "rss",
        "url": "https://thehackernews.com/rss.xml",
        "enabled": True,
        "default_category": "Cyber Attack",
        "default_severity": "Medium",
    },
    {
        "id": "sans_isc",
        "name": "SANS Internet Storm Center",
        "type": "rss",
        "url": "https://isc.sans.edu/rssfeed.xml",
        "enabled": True,
        "default_category": "Threat Analysis",
        "default_severity": "Medium",
    },
    {
        "id": "krebs",
        "name": "Krebs on Security",
        "type": "rss",
        "url": "https://krebsonsecurity.com/feed/",
        "enabled": True,
        "default_category": "Investigation",
        "default_severity": "Medium",
    },
    {
        "id": "dark_reading",
        "name": "Dark Reading",
        "type": "rss",
        "url": "https://darkreading.com/rss.xml",
        "enabled": True,
        "default_category": "Industry News",
        "default_severity": "Low",
    },
    {
        "id": "nvd",
        "name": "NIST NVD Vulnerabilities",
        "type": "json_api",
        "url": "https://services.nvd.nist.gov/rest/json/cves/2.0?resultsPerPage=15",
        "enabled": True,
        "default_category": "Vulnerability",
        "default_severity": "Medium",
    },
    {
        "id": "cisa",
        "name": "CISA Cybersecurity Advisories",
        "type": "rss",
        "url": "https://www.cisa.gov/cybersecurity-advisories/all.xml",
        # Kept disabled: government Akamai WAF returns HTTP 403 Access Denied to programmatic requests; preserved for proxy or future access
        "enabled": False,
        "default_category": "Advisory",
        "default_severity": "High",
    },
    {
        "id": "bleepingcomputer",
        "name": "BleepingComputer",
        "type": "rss",
        "url": "https://www.bleepingcomputer.com/feed/",
        # Enabled: verified accessible via HTTPS request (HTTP 200, valid RSS 2.0 XML)
        "enabled": True,
        "default_category": "Data Breach",
        "default_severity": "High",
    },
]


def clean_html_text(raw_html: Optional[str]) -> str:
    """
    Remove HTML tags, decode HTML entities, and normalize whitespace.
    Ensures safe plain text for storage and template rendering.
    """
    if not raw_html:
        return ""

    # Remove script and style elements entirely
    text = re.sub(r"<(script|style)[^>]*>.*?</\1>", " ", raw_html, flags=re.DOTALL | re.IGNORECASE)
    # Remove all HTML tags
    text = re.sub(r"<[^>]+>", " ", text)
    # Decode HTML entities (&amp;, &quot;, &#x27;, etc.)
    text = html.unescape(text)
    # Normalize space before punctuation marks that resulted from tag stripping
    text = re.sub(r"\s+([.,;:!?])", r"\1", text)
    # Normalize excessive whitespace, tabs, and newlines
    text = re.sub(r"\s+", " ", text).strip()
    return text


def sanitize_xml_entities(xml_str: str) -> str:
    """
    Replace undeclared HTML entities in raw XML with their numerical or standard equivalents.
    Prevents ElementTree.ParseError: undefined entity on feeds containing &nbsp;, &rsquo;, etc.
    """
    standard_entities = {"amp", "lt", "gt", "apos", "quot"}

    def _replace_entity(match: re.Match) -> str:
        name = match.group(1)
        if name in standard_entities:
            return f"&{name};"
        cp = html.entities.name2codepoint.get(name)
        if cp:
            return f"&#{cp};"
        return f"&amp;{name};"

    return re.sub(r"&([a-zA-Z0-9]+);", _replace_entity, xml_str)


def parse_published_date(date_str: Optional[str]) -> Optional[datetime]:
    """
    Parse RFC 2822, RFC 822, or ISO 8601 date string into a naive UTC datetime.
    """
    if not date_str:
        return None

    date_str = date_str.strip()
    # 1. Try RFC 2822 / 822 (standard RSS pubDate)
    try:
        dt = email.utils.parsedate_to_datetime(date_str)
        if dt is not None:
            if dt.tzinfo is not None:
                dt = dt.astimezone(timezone.utc).replace(tzinfo=None)
            return dt
    except Exception:
        pass

    # 2. Try ISO 8601 (Atom updated / published)
    try:
        iso_str = date_str.replace("Z", "+00:00")
        dt = datetime.fromisoformat(iso_str)
        if dt.tzinfo is not None:
            dt = dt.astimezone(timezone.utc).replace(tzinfo=None)
        return dt
    except Exception:
        pass

    # 3. Fallback: try common format patterns
    for fmt in (
        "%Y-%m-%d %H:%M:%S",
        "%Y-%m-%dT%H:%M:%S",
        "%d %b %Y %H:%M:%S",
        "%Y-%m-%d",
    ):
        try:
            return datetime.strptime(date_str[:19], fmt)
        except Exception:
            continue

    return None


def infer_severity(title: str, summary: str, default_severity: str = "Low") -> str:
    """
    Deterministic rule-based severity categorization based on security indicators
    and threat terminology in the article.
    """
    combined = f"{title} {summary}".lower()

    # Critical indicators
    if any(
        kw in combined
        for kw in (
            "zero-day",
            "0-day",
            "actively exploited",
            "critical vulnerability",
            "unauthenticated remote code execution",
            "emergency directive",
            "severe rce",
            "widespread ransomware",
        )
    ):
        return "Critical"

    # High severity indicators
    if any(
        kw in combined
        for kw in (
            "remote code execution",
            "rce",
            "privilege escalation",
            "supply chain attack",
            "state-sponsored",
            "nation-state",
            "apt",
            "ransomware",
            "malware campaign",
            "backdoor",
            "rootkit",
            "trojan",
            "cve-",
        )
    ):
        return "High"

    # Medium severity indicators
    if any(
        kw in combined
        for kw in (
            "phishing",
            "data breach",
            "information disclosure",
            "credential theft",
            "security update",
            "patch tuesday",
            "cross-site scripting",
            "xss",
            "sql injection",
            "denial of service",
            "dos",
            "vulnerability",
        )
    ):
        return "Medium"

    return default_severity if default_severity in ("Low", "Medium", "High", "Critical") else "Low"


def infer_category(
    title: str,
    summary: str,
    source_category: Optional[str] = None,
    default_category: str = "General",
) -> str:
    """
    Determine the threat news category from feed metadata or text heuristics.
    """
    if source_category:
        cleaned = clean_html_text(source_category).title()
        if len(cleaned) >= 3 and len(cleaned) <= 50:
            return cleaned

    combined = f"{title} {summary}".lower()

    if any(kw in combined for kw in ("cve-", "vulnerability", "flaw", "patch", "zero-day", "0-day", "exploit")):
        return "Vulnerability"
    if any(kw in combined for kw in ("ransomware", "malware", "trojan", "infostealer", "botnet", "spyware", "loader")):
        return "Malware"
    if any(kw in combined for kw in ("phishing", "social engineering", "credential harvesting", "spoof")):
        return "Phishing"
    if any(kw in combined for kw in ("apt", "state-sponsored", "nation-state", "espionage", "campaign")):
        return "APT Campaign"
    if any(kw in combined for kw in ("breach", "data leak", "exfiltration", "stolen records", "compromise")):
        return "Data Breach"
    if any(kw in combined for kw in ("advisory", "directive", "alert", "guidance", "bulletin", "warning")):
        return "Advisory"
    if any(kw in combined for kw in ("cloud", "aws", "azure", "kubernetes", "container", "iam")):
        return "Cloud Security"

    return default_category or "General"


def is_valid_url(url: Optional[str]) -> bool:
    """Validate that URL has a valid scheme and netloc."""
    if not url or not isinstance(url, str):
        return False
    try:
        parsed = urlparse(url.strip())
        return parsed.scheme.lower() in ("http", "https") and bool(parsed.netloc)
    except Exception:
        return False


def parse_rss_feed(
    xml_data: bytes,
    source_name: str,
    default_category: str = "General",
    default_severity: str = "Low",
) -> List[Dict[str, Any]]:
    """
    Parse an RSS 2.0 or Atom feed using xml.etree.ElementTree with robust entity handling.
    Returns a list of normalized article dictionaries.
    """
    articles: List[Dict[str, Any]] = []

    # Decode bytes with safe fallback
    try:
        text = xml_data.decode("utf-8")
    except UnicodeDecodeError:
        try:
            text = xml_data.decode("latin-1")
        except UnicodeDecodeError:
            text = xml_data.decode("utf-8", errors="replace")

    # Sanitize entities
    sanitized_text = sanitize_xml_entities(text)

    import xml.etree.ElementTree as ET

    try:
        root = ET.fromstring(sanitized_text.encode("utf-8"))
    except ET.ParseError as e:
        logger.warning(f"Initial XML parse error for {source_name}: {e}. Trying relaxed strip.")
        # Attempt recovery by removing unparseable control characters
        cleaned_text = re.sub(r"[\x00-\x08\x0B\x0C\x0E-\x1F]", "", sanitized_text)
        root = ET.fromstring(cleaned_text.encode("utf-8"))

    # Determine if RSS 2.0 (<channel><item>) or Atom (<feed><entry>)
    # Find all items (RSS) or entries (Atom)
    items = root.findall(".//item")
    is_atom = False
    if not items:
        # Atom namespaces often prefix elements, search with local tag matching
        items = [elem for elem in root.iter() if elem.tag.endswith("entry")]
        is_atom = True

    for item in items:
        try:
            # Title
            title_elem = item.find("title") if not is_atom else next((e for e in item if e.tag.endswith("title")), None)
            title = clean_html_text(title_elem.text if title_elem is not None else "")
            if not title:
                continue
            # Limit title to 255 chars per DB schema
            title = title[:255]

            # Link / Source URL
            link = ""
            if not is_atom:
                link_elem = item.find("link")
                link = (link_elem.text or "").strip() if link_elem is not None else ""
            else:
                # Atom <link href="...">
                for child in item:
                    if child.tag.endswith("link"):
                        href = child.get("href")
                        rel = child.get("rel", "alternate")
                        if href and rel in ("alternate", ""):
                            link = href.strip()
                            break

            if not is_valid_url(link):
                continue
            link = link[:500]

            # Summary / Description
            raw_summary = ""
            if not is_atom:
                # Try description or content:encoded
                desc_elem = item.find("description")
                if desc_elem is not None and desc_elem.text:
                    raw_summary = desc_elem.text
                if not raw_summary:
                    content_elem = next((e for e in item if e.tag.endswith("encoded")), None)
                    if content_elem is not None and content_elem.text:
                        raw_summary = content_elem.text
            else:
                summary_elem = next((e for e in item if e.tag.endswith("summary")), None)
                if summary_elem is not None and summary_elem.text:
                    raw_summary = summary_elem.text
                else:
                    content_elem = next((e for e in item if e.tag.endswith("content")), None)
                    if content_elem is not None and content_elem.text:
                        raw_summary = content_elem.text

            summary = clean_html_text(raw_summary)
            # Truncate summary if excessively long (e.g., 2000 chars)
            if len(summary) > 2000:
                summary = summary[:1997] + "..."

            # Published Date
            raw_date = ""
            if not is_atom:
                date_elem = item.find("pubDate")
                if date_elem is not None:
                    raw_date = date_elem.text
            else:
                date_elem = next((e for e in item if e.tag.endswith("published") or e.tag.endswith("updated")), None)
                if date_elem is not None:
                    raw_date = date_elem.text

            published_at = parse_published_date(raw_date) or datetime.utcnow()

            # Category
            category_tag = ""
            cat_elem = item.find("category") if not is_atom else next((e for e in item if e.tag.endswith("category")), None)
            if cat_elem is not None:
                category_tag = cat_elem.text or cat_elem.get("term", "") or ""

            category = infer_category(title, summary, category_tag, default_category)
            severity = infer_severity(title, summary, default_severity)

            articles.append({
                "title": title,
                "source": source_name,
                "source_url": link,
                "summary": summary or None,
                "category": category,
                "severity": severity,
                "published_at": published_at,
            })
        except Exception as e:
            logger.debug(f"Error parsing item in {source_name}: {e}")
            continue

    return articles


def parse_nvd_api_response(
    data: Dict[str, Any],
    source_name: str = "NIST NVD Vulnerabilities",
    default_category: str = "Vulnerability",
) -> List[Dict[str, Any]]:
    """
    Parse JSON response from the official NIST NVD API (v2.0).
    Extracts CVE ID, vulnerability description, publication date, CVSS severity, and NVD portal URL.
    """
    articles: List[Dict[str, Any]] = []

    vulnerabilities = data.get("vulnerabilities", [])
    if not isinstance(vulnerabilities, list):
        return articles

    for entry in vulnerabilities:
        cve = entry.get("cve", {})
        cve_id = cve.get("id", "").strip()
        if not cve_id:
            continue

        # Extract primary English description
        descriptions = cve.get("descriptions", [])
        desc_text = ""
        for d in descriptions:
            if d.get("lang") == "en":
                desc_text = d.get("value", "")
                break
        if not desc_text and descriptions:
            desc_text = descriptions[0].get("value", "")

        summary = clean_html_text(desc_text)
        if len(summary) > 2000:
            summary = summary[:1997] + "..."

        title = f"{cve_id}: {summary[:160]}..." if len(summary) > 160 else f"{cve_id}: {summary}"
        title = title[:255]

        source_url = f"https://nvd.nist.gov/vuln/detail/{cve_id}"

        # Published date
        published_str = cve.get("published")
        published_at = parse_published_date(published_str) or datetime.utcnow()

        # Severity mapping from CVSS metrics
        metrics = cve.get("metrics", {})
        base_severity = "MEDIUM"
        # Check cvssMetricV31, cvssMetricV30, cvssMetricV2
        for cvss_key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            metric_list = metrics.get(cvss_key, [])
            if metric_list and isinstance(metric_list, list):
                cvss_data = metric_list[0].get("cvssData", {})
                bs = cvss_data.get("baseSeverity") or metric_list[0].get("baseSeverity")
                if bs:
                    base_severity = str(bs).upper()
                    break

        severity_map = {
            "CRITICAL": "Critical",
            "HIGH": "High",
            "MEDIUM": "Medium",
            "LOW": "Low",
        }
        severity = severity_map.get(base_severity, "Medium")

        articles.append({
            "title": title,
            "source": source_name,
            "source_url": source_url,
            "summary": summary or None,
            "category": default_category,
            "severity": severity,
            "published_at": published_at,
        })

    return articles


def fetch_news_from_source(
    source_cfg: Dict[str, Any],
    timeout: int = DEFAULT_TIMEOUT,
) -> List[Dict[str, Any]]:
    """
    Fetch articles from a single configured source definition.
    Handles network errors, timeouts, and status checks safely.
    """
    if not source_cfg.get("enabled", True):
        logger.info(f"Source {source_cfg.get('name')} is disabled, skipping.")
        return []

    url = source_cfg.get("url")
    source_name = source_cfg.get("name", "Unknown Source")
    source_type = source_cfg.get("type", "rss")
    default_category = source_cfg.get("default_category", "General")
    default_severity = source_cfg.get("default_severity", "Low")

    if not url:
        raise ValueError(f"No URL specified for source {source_name}")

    response = requests.get(
        url,
        headers=DEFAULT_HEADERS,
        timeout=timeout,
    )
    response.raise_for_status()

    if source_type == "json_api":
        data = response.json()
        return parse_nvd_api_response(data, source_name, default_category)
    else:
        return parse_rss_feed(
            response.content,
            source_name,
            default_category,
            default_severity,
        )


def fetch_and_store_threat_news(
    sources: Optional[List[Dict[str, Any]]] = None,
    timeout: int = DEFAULT_TIMEOUT,
) -> Dict[str, Any]:
    """
    Orchestrate fetching news across all enabled sources, deduplicate against existing
    database records, and persist new articles.

    Returns:
        Structured telemetry dict with import counts, source status, and errors.
    """
    if sources is None:
        sources = NEWS_SOURCES

    source_results: List[Dict[str, Any]] = []
    errors: List[Dict[str, str]] = []
    total_fetched = 0
    new_articles_count = 0
    skipped_duplicates_count = 0

    # Cache existing URLs and (source, title) pairs to minimize DB lookups
    existing_urls = {
        row[0] for row in db.session.query(ThreatNews.source_url).filter(ThreatNews.source_url.isnot(None)).all()
    }
    existing_titles = {
        (row[0].strip().lower(), row[1].strip().lower())
        for row in db.session.query(ThreatNews.source, ThreatNews.title).all()
    }

    new_records: List[ThreatNews] = []
    in_memory_seen_urls = set(existing_urls)
    in_memory_seen_titles = set(existing_titles)

    for source_cfg in sources:
        if not source_cfg.get("enabled", True):
            continue

        src_name = source_cfg.get("name", "Unknown Source")
        src_fetched = 0
        src_new = 0
        src_skipped = 0

        try:
            articles = fetch_news_from_source(source_cfg, timeout=timeout)
            src_fetched = len(articles)
            total_fetched += src_fetched

            for art in articles:
                url = art.get("source_url", "").strip()
                title = art.get("title", "").strip()
                title_key = (src_name.strip().lower(), title.lower())

                # Deduplication check
                if (url and url in in_memory_seen_urls) or (title_key in in_memory_seen_titles):
                    src_skipped += 1
                    skipped_duplicates_count += 1
                    continue

                # Create model record
                record = ThreatNews(
                    title=title,
                    source=src_name,
                    source_url=url or None,
                    summary=art.get("summary"),
                    category=art.get("category", "General"),
                    severity=art.get("severity", "Low"),
                    published_at=art.get("published_at") or datetime.utcnow(),
                    created_at=datetime.utcnow(),
                )
                new_records.append(record)

                if url:
                    in_memory_seen_urls.add(url)
                in_memory_seen_titles.add(title_key)
                src_new += 1
                new_articles_count += 1

            source_results.append({
                "source": src_name,
                "status": "success",
                "fetched": src_fetched,
                "new": src_new,
                "skipped": src_skipped,
            })
        except requests.exceptions.HTTPError as e:
            status_code = getattr(getattr(e, "response", None), "status_code", None)
            if status_code == 403:
                err_msg = f"HTTP 403 Forbidden: Access denied by upstream server/WAF for '{src_name}' ({source_cfg.get('url')})"
                logger.error(err_msg)
            else:
                err_msg = f"HTTPError {status_code}: {str(e)}"
                logger.error(f"HTTP error fetching source '{src_name}': {err_msg}")
            errors.append({
                "source": src_name,
                "error": err_msg,
            })
            source_results.append({
                "source": src_name,
                "status": "failed",
                "error": err_msg,
                "fetched": 0,
                "new": 0,
                "skipped": 0,
            })
        except Exception as e:
            err_msg = f"{type(e).__name__}: {str(e)}"
            logger.error(f"Error fetching source '{src_name}': {err_msg}")
            errors.append({
                "source": src_name,
                "error": err_msg,
            })
            source_results.append({
                "source": src_name,
                "status": "failed",
                "error": err_msg,
                "fetched": 0,
                "new": 0,
                "skipped": 0,
            })

    # Commit all newly created records in one atomic transaction
    if new_records:
        try:
            db.session.add_all(new_records)
            db.session.commit()
            logger.info(f"Persisted {len(new_records)} new threat news articles.")
        except Exception as e:
            db.session.rollback()
            logger.error(f"Failed to commit new threat news records: {e}")
            raise

    return {
        "success": True,
        "total_fetched": total_fetched,
        "new_articles": new_articles_count,
        "skipped_duplicates": skipped_duplicates_count,
        "sources_processed": len(sources),
        "source_results": source_results,
        "errors": errors,
    }


def get_threat_news_filtered(
    query_text: Optional[str] = None,
    category: Optional[str] = None,
    source: Optional[str] = None,
    severity: Optional[str] = None,
    page: int = 1,
    per_page: int = 12,
):
    """
    Query, filter, and paginate ThreatNews articles.
    """
    q = ThreatNews.query

    if query_text:
        term = f"%{query_text.strip()}%"
        q = q.filter(
            or_(
                ThreatNews.title.ilike(term),
                ThreatNews.summary.ilike(term),
            )
        )

    if category and category.lower() != "all":
        q = q.filter(func.lower(ThreatNews.category) == category.strip().lower())

    if source and source.lower() != "all":
        q = q.filter(func.lower(ThreatNews.source) == source.strip().lower())

    if severity and severity.lower() != "all":
        q = q.filter(ThreatNews.severity == severity.strip().capitalize())

    # Order newest publication first, then by primary key ID desc
    q = q.order_by(
        ThreatNews.published_at.desc(),
        ThreatNews.id.desc(),
    )

    return q.paginate(page=page, per_page=per_page, error_out=False)


def get_news_stats() -> Dict[str, Any]:
    """
    Calculate summary statistics and facet distributions for the Threat News dashboard.
    """
    total_articles = ThreatNews.query.count()

    # Severity distribution
    severity_counts = {
        "Critical": ThreatNews.query.filter_by(severity="Critical").count(),
        "High": ThreatNews.query.filter_by(severity="High").count(),
        "Medium": ThreatNews.query.filter_by(severity="Medium").count(),
        "Low": ThreatNews.query.filter_by(severity="Low").count(),
    }

    # Distinct categories with article count
    cat_rows = (
        db.session.query(ThreatNews.category, func.count(ThreatNews.id))
        .group_by(ThreatNews.category)
        .all()
    )
    categories = sorted([row[0] for row in cat_rows if row[0]])

    # Distinct sources with article count
    src_rows = (
        db.session.query(ThreatNews.source, func.count(ThreatNews.id))
        .group_by(ThreatNews.source)
        .all()
    )
    sources = sorted([row[0] for row in src_rows if row[0]])

    # Latest published date
    latest_article = ThreatNews.query.order_by(ThreatNews.published_at.desc()).first()
    latest_date = latest_article.published_at if latest_article else None

    return {
        "total": total_articles,
        "severities": severity_counts,
        "categories": categories,
        "sources": sources,
        "latest_published_at": latest_date,
    }


def extract_news_iocs(news_id: int, user_id: int) -> Dict[str, Any]:
    """
    Task 7 Section 7 Bridge: Extract Indicators of Compromise (IPv4, Domains, Hashes, URLs)
    from a ThreatNews article summary and persist/link them to ThreatIndicator.
    """
    article = ThreatNews.query.get(news_id)
    if not article:
        return {"success": False, "error": f"Article #{news_id} not found."}

    text_to_extract = f"{article.title}\n{article.summary or ''}"
    iocs = extract_iocs(text_to_extract)

    if not iocs:
        return {
            "success": True,
            "news_id": news_id,
            "article_title": article.title,
            "total_extracted": 0,
            "created": 0,
            "reused": 0,
            "indicators": [],
        }

    created_count = 0
    reused_count = 0
    indicator_records: List[Dict[str, Any]] = []

    # Map article severity to ThreatIndicator severity
    indicator_severity = article.severity or "Medium"

    for ioc in iocs:
        val = ioc["value"]
        ioc_type = ioc["type"]

        # Case-insensitive lookup to reuse existing indicators
        existing = ThreatIndicator.query.filter(
            func.lower(ThreatIndicator.indicator_value) == val.lower()
        ).first()

        if existing:
            indicator = existing
            indicator.last_seen_at = datetime.utcnow()
            indicator.updated_at = datetime.utcnow()
            reused_count += 1
        else:
            indicator = ThreatIndicator(
                indicator_value=val,
                indicator_type=ioc_type,
                confidence_score=50,
                severity=indicator_severity,
                status="Active",
                source=f"News: {article.source}",
                first_seen_at=datetime.utcnow(),
                last_seen_at=datetime.utcnow(),
                added_by_user_id=user_id,
                tlp_marking="CLEAR",
                context=f"Article: {article.title}",
            )
            db.session.add(indicator)
            db.session.flush()
            created_count += 1

        indicator_records.append({
            "id": indicator.id,
            "value": indicator.indicator_value,
            "type": indicator.indicator_type,
            "severity": indicator.severity,
            "is_new": existing is None,
        })

    db.session.commit()

    return {
        "success": True,
        "news_id": news_id,
        "article_title": article.title,
        "total_extracted": len(iocs),
        "created": created_count,
        "reused": reused_count,
        "indicators": indicator_records,
    }
