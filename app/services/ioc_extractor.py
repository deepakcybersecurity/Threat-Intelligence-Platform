"""
IOC (Indicator of Compromise) Extraction Service
================================================
Extracts, normalizes, and validates common Indicators of Compromise (IOCs)
from unstructured security and threat-report text.

Supported IOC Types:
- ipv4: Validated IPv4 addresses (0.0.0.0 - 255.255.255.255)
- domain: Fully Qualified Domain Names (FQDNs) with valid TLDs
- url: Complete HTTP and HTTPS URLs (hostnames within URLs are not duplicated as domains)
- md5: 32-character hexadecimal hashes
- sha1: 40-character hexadecimal hashes
- sha256: 64-character hexadecimal hashes

Design & Security Principles:
- Pure data processing: strictly zero execution, eval, or shell operations.
- Zero external dependencies: utilizes standard Python libraries (re, ipaddress, urllib.parse).
- High precision: false positive control via octet bounds, file extension exclusion,
  strict hexadecimal boundary lookarounds, and punctuation stripping.
- Deduplication: avoids duplicate IOC values in the returned results.
"""

import ipaddress
import re
from typing import Dict, List, Set
from urllib.parse import urlparse


# Punctuation characters to strip from IOC boundaries
TRAILING_PUNCTUATION = ".,;:!?'\"`)>]}\\"
LEADING_PUNCTUATION = "('\"<[{"

# Common file extensions that must NOT be treated as domain TLDs
EXCLUDED_EXTENSIONS = {
    "exe", "dll", "sys", "bin", "doc", "docx", "pdf", "zip", "rar", "tar",
    "gz", "7z", "png", "jpg", "jpeg", "gif", "sh", "bat", "ps1", "py",
    "c", "cpp", "h", "json", "xml", "txt", "csv", "log", "dat", "tmp",
    "iso", "apk", "jar", "vbs", "js", "html", "htm", "css", "php", "asp",
    "aspx", "bak", "cfg", "ini", "conf", "msi", "scr", "cmd", "vbe", "wsf"
}

# Recognized global top-level domains and country code TLDs
VALID_TLDS = {
    "com", "org", "net", "edu", "gov", "mil", "int", "io", "co", "ru", "in",
    "uk", "de", "cn", "xyz", "info", "biz", "me", "cc", "tv", "top", "online",
    "site", "club", "app", "dev", "cloud", "pro", "ai", "security", "tech",
    "agency", "global", "network", "live", "world", "link", "vip", "shop",
    "store", "space", "host", "digital", "zone", "ca", "fr", "au", "jp", "br",
    "nl", "kr", "it", "es", "ch", "se", "no", "fi", "be", "at", "dk", "pl",
    "za", "tw", "hk", "sg", "nz", "mx", "ar", "cl", "tr", "ua", "cz", "ro",
    "gr", "hu", "pt", "il", "ie", "th", "vn", "my", "ph", "id", "pk", "bd",
    "ng", "ke", "eg", "su", "onion", "to", "ms", "ly", "is", "gg", "fm"
}

# Compiled regex patterns
URL_REGEX = re.compile(
    r'https?://[^\s<>"\'{}|\\^`\[\]]+',
    re.IGNORECASE
)

# IPv4 regex bounded by non-digit/non-dot characters
IPV4_REGEX = re.compile(
    r'(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?!\.\d|\d)'
)

# Domain regex: 1+ labels followed by recognized TLD
DOMAIN_REGEX = re.compile(
    r'(?<![a-zA-Z0-9_-])(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,24}(?![a-zA-Z0-9_-])',
    re.IGNORECASE
)

# Exact-length hexadecimal hash patterns with strict boundary lookarounds
# (prevents matching subsets of longer hashes like SHA256 as MD5 or SHA1)
SHA256_REGEX = re.compile(r'(?<![a-fA-F0-9])[a-fA-F0-9]{64}(?![a-fA-F0-9])')
SHA1_REGEX = re.compile(r'(?<![a-fA-F0-9])[a-fA-F0-9]{40}(?![a-fA-F0-9])')
MD5_REGEX = re.compile(r'(?<![a-fA-F0-9])[a-fA-F0-9]{32}(?![a-fA-F0-9])')


def _is_valid_ipv4(candidate: str) -> bool:
    """Validate that candidate string is a strictly valid IPv4 address."""
    try:
        addr = ipaddress.IPv4Address(candidate)
        return str(addr) == candidate
    except (ValueError, ipaddress.AddressValueError):
        return False


def _is_valid_domain(candidate: str) -> bool:
    """Validate domain structure, labels, and ensure TLD is valid and not a file extension."""
    if not candidate or len(candidate) > 253:
        return False

    parts = candidate.split(".")
    if len(parts) < 2:
        return False

    tld = parts[-1].lower()
    if tld in EXCLUDED_EXTENSIONS or tld not in VALID_TLDS:
        return False

    for part in parts:
        if not part or len(part) > 63:
            return False
        if part.startswith("-") or part.endswith("-"):
            return False
        if not re.match(r"^[a-zA-Z0-9-]+$", part):
            return False

    # Ensure not all-numeric labels (which would be an IP)
    if all(p.isdigit() for p in parts):
        return False

    return True


def extract_iocs(text: str) -> List[Dict[str, str]]:
    """
    Extract structured Indicators of Compromise (IOCs) from input text.

    Supported types:
        - "ipv4"
        - "domain"
        - "url"
        - "md5"
        - "sha1"
        - "sha256"

    Returns:
        List of dicts: [{"type": "<ioc_type>", "value": "<normalized_value>"}, ...]
    """
    if not text or not isinstance(text, str):
        return []

    indicators: List[Dict[str, str]] = []
    seen_values: Set[str] = set()

    # -------------------------------------------------------------------------
    # 1. URLs Extraction
    # -------------------------------------------------------------------------
    # URLs are extracted first. In accordance with Section 6, hostnames that are
    # part of complete URLs are not extracted as separate domain IOCs.
    # We mask URLs in the text during subsequent domain and IP scanning.
    raw_urls = URL_REGEX.findall(text)
    masked_text = text

    for raw_url in raw_urls:
        cleaned_url = raw_url.rstrip(TRAILING_PUNCTUATION).lstrip(LEADING_PUNCTUATION)
        try:
            parsed = urlparse(cleaned_url)
            if parsed.scheme.lower() in ("http", "https") and parsed.netloc:
                norm_url = cleaned_url
                norm_key = norm_url.lower()
                if norm_key not in seen_values:
                    seen_values.add(norm_key)
                    indicators.append({"type": "url", "value": norm_url})
        except Exception:
            continue

    # Mask detected URLs with whitespace so embedded hostnames and IPs within URLs
    # are not duplicated as standalone domains or IPs
    masked_text = URL_REGEX.sub(lambda m: " " * len(m.group(0)), text)

    # -------------------------------------------------------------------------
    # 2. IPv4 Addresses Extraction
    # -------------------------------------------------------------------------
    raw_ips = IPV4_REGEX.findall(masked_text)
    for raw_ip in raw_ips:
        cleaned_ip = raw_ip.strip(TRAILING_PUNCTUATION + LEADING_PUNCTUATION)
        if _is_valid_ipv4(cleaned_ip):
            norm_key = cleaned_ip
            if norm_key not in seen_values:
                seen_values.add(norm_key)
                indicators.append({"type": "ipv4", "value": cleaned_ip})

    # -------------------------------------------------------------------------
    # 3. Domain Names Extraction
    # -------------------------------------------------------------------------
    raw_domains = DOMAIN_REGEX.findall(masked_text)
    for raw_domain in raw_domains:
        cleaned_domain = raw_domain.rstrip(TRAILING_PUNCTUATION).lstrip(LEADING_PUNCTUATION + "@")
        cleaned_domain_lower = cleaned_domain.lower()
        if _is_valid_domain(cleaned_domain_lower):
            if cleaned_domain_lower not in seen_values:
                seen_values.add(cleaned_domain_lower)
                indicators.append({"type": "domain", "value": cleaned_domain_lower})

    # -------------------------------------------------------------------------
    # 4. Cryptographic Hashes Extraction (SHA256, SHA1, MD5)
    # -------------------------------------------------------------------------
    # SHA256 (64 hex characters)
    for match in SHA256_REGEX.findall(text):
        h_val = match.lower()
        if set(h_val) != {"0"} and h_val not in seen_values:
            seen_values.add(h_val)
            indicators.append({"type": "sha256", "value": h_val})

    # SHA1 (40 hex characters)
    for match in SHA1_REGEX.findall(text):
        h_val = match.lower()
        if set(h_val) != {"0"} and h_val not in seen_values:
            seen_values.add(h_val)
            indicators.append({"type": "sha1", "value": h_val})

    # MD5 (32 hex characters)
    for match in MD5_REGEX.findall(text):
        h_val = match.lower()
        if set(h_val) != {"0"} and h_val not in seen_values:
            seen_values.add(h_val)
            indicators.append({"type": "md5", "value": h_val})

    return indicators
