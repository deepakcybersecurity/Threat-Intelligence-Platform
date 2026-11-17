"""
Automated IOC Blocklist Export Service (Task 11)
================================================
Generates multi-vendor threat intelligence blocklists for perimeter firewalls,
web proxies, DNS sinkholes, and intrusion detection systems (IDS/IPS).

Supported Vendor Standards:
1. Plaintext Dynamic Lists: Palo Alto Networks EDL, Fortinet Threat Feed, pfSense pfBlockerNG
2. DNS Sinkhole / Hosts file: Pi-hole, AdGuard Home, dnsmasq, unbound
3. BIND9 / PowerDNS Response Policy Zone (DNS RPZ)
4. Suricata & Snort IDS/IPS Signature Rules
5. Web Proxy URL Blacklists: Squid, Zscaler, BlueCoat / Symantec
6. EDR Custom IOC Hashes: CrowdStrike Falcon IOC, Defender Indicator List
7. CSV Export for SIEM Correlation (Splunk, Sentinel, QRadar)
8. HTTP Caching with ETag & If-None-Match validation (304 Not Modified)
"""

from datetime import datetime, timezone
import hashlib
import json
import logging
from typing import Any, Dict, List, Optional, Tuple

from sqlalchemy import or_, func

from app import db
from app.models import ThreatIndicator

logger = logging.getLogger(__name__)


def fetch_blocklist_indicators(
    indicator_types: Optional[List[str]] = None,
    min_risk: int = 50,
    severity: Optional[str] = None,
    limit: int = 5000,
) -> List[ThreatIndicator]:
    """
    Query active threat indicators meeting the risk and severity criteria.
    Only includes indicators marked 'Active' with risk_score >= min_risk
    or severity in ('Critical', 'High').
    """
    query = ThreatIndicator.query.filter(
        ThreatIndicator.status == "Active",
        or_(
            ThreatIndicator.risk_score >= min_risk,
            ThreatIndicator.severity.in_(["Critical", "High"])
        )
    )

    if indicator_types:
        norm_types = [t.strip().lower() for t in indicator_types]
        query = query.filter(func.lower(ThreatIndicator.indicator_type).in_(norm_types))

    if severity and severity.lower() != "all":
        query = query.filter(ThreatIndicator.severity == severity.strip().capitalize())

    return query.order_by(
        ThreatIndicator.risk_score.desc(),
        func.coalesce(ThreatIndicator.last_seen_at, ThreatIndicator.created_at).desc()
    ).limit(limit).all()


def compute_feed_etag(content: str) -> str:
    """Generate MD5 hash checksum for HTTP ETag headers."""
    return hashlib.md5(content.encode("utf-8")).hexdigest()


def generate_plain_blocklist(
    indicators: List[ThreatIndicator],
    include_header: bool = False
) -> str:
    """Generate plaintext list (one item per line) for Palo Alto / Fortinet / pfSense."""
    lines: List[str] = []
    if include_header:
        now_str = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
        lines.append(f"# ThreatIntel Platform Automated Blocklist Feed")
        lines.append(f"# Generated: {now_str}")
        lines.append(f"# Total Indicators: {len(indicators)}")
        lines.append("")

    for ind in indicators:
        val = ind.indicator_value.strip()
        if val and not val.startswith("#"):
            lines.append(val)

    return "\n".join(lines) + "\n"


def generate_hosts_sinkhole_blocklist(
    indicators: List[ThreatIndicator],
    sinkhole_ip: str = "0.0.0.0"
) -> str:
    """
    Generate DNS Sinkhole hosts file format:
    0.0.0.0 malicious-domain.com
    Directly consumable by Pi-hole, AdGuard Home, dnsmasq, and local hosts files.
    """
    now_str = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    lines: List[str] = [
        "# ThreatIntel Platform DNS Sinkhole Feed",
        f"# Generated: {now_str}",
        f"# Total Domains: {len(indicators)}",
        "# Format: <SINKHOLE_IP> <DOMAIN>",
        "",
    ]
    seen_domains = set()
    for ind in indicators:
        dom = ind.indicator_value.strip().lower()
        # Strip protocol or path if accidentally present
        if dom.startswith("http://") or dom.startswith("https://"):
            dom = dom.split("/")[2] if len(dom.split("/")) > 2 else dom
        if dom and dom not in seen_domains:
            seen_domains.add(dom)
            lines.append(f"{sinkhole_ip} {dom}")

    return "\n".join(lines) + "\n"


def generate_dns_rpz_blocklist(
    indicators: List[ThreatIndicator],
    zone_name: str = "rpz.tip.local"
) -> str:
    """
    Generate BIND9 / PowerDNS Response Policy Zone (RPZ) zone format:
    malicious-domain.com CNAME .
    *.malicious-domain.com CNAME .
    """
    now = datetime.now(timezone.utc)
    serial = now.strftime("%Y%m%d01")
    now_str = now.strftime("%Y-%m-%d %H:%M:%S UTC")

    lines: List[str] = [
        f"; ThreatIntel Platform DNS RPZ Policy Zone Feed: {zone_name}",
        f"; Generated: {now_str}",
        f"; Total Rules: {len(indicators)}",
        "$TTL 300",
        f"@ IN SOA localhost. root.localhost. (",
        f"    {serial} ; serial",
        "    3600       ; refresh",
        "    600        ; retry",
        "    604800     ; expire",
        "    300        ; minimum",
        ")",
        "  IN NS localhost.",
        "",
    ]

    seen_domains = set()
    for ind in indicators:
        dom = ind.indicator_value.strip().lower()
        if dom.startswith("http://") or dom.startswith("https://"):
            dom = dom.split("/")[2] if len(dom.split("/")) > 2 else dom
        if dom and dom not in seen_domains:
            seen_domains.add(dom)
            lines.append(f"{dom} CNAME .")
            lines.append(f"*.{dom} CNAME .")

    return "\n".join(lines) + "\n"


def generate_suricata_snort_rules(
    indicators: List[ThreatIndicator],
    base_sid: int = 1900000
) -> str:
    """
    Generate Snort / Suricata IDS/IPS alert rules for IP addresses and Domains.
    """
    now_str = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    lines: List[str] = [
        "# ThreatIntel Platform Suricata / Snort IDS Signatures",
        f"# Generated: {now_str}",
        f"# Total Rules: {len(indicators)}",
        "",
    ]

    sid = base_sid
    for ind in indicators:
        val = ind.indicator_value.strip()
        itype = ind.indicator_type.strip().lower()
        sev = ind.severity or "High"
        risk = ind.risk_score or 50

        if itype in ("ipv4", "ip"):
            # Inbound connection to malicious IP
            rule = (
                f'alert ip any any -> {val} any ('
                f'msg:"TIP Threat Block - Malicious Destination IP {val} (Risk {risk}/100)"; '
                f'reference:url,tip.local/threat-feed; '
                f'classtype:trojan-activity; '
                f'sid:{sid}; rev:1;)'
            )
            lines.append(rule)
            sid += 1
        elif itype == "domain":
            clean_dom = val.lower()
            rule = (
                f'alert dns any any -> any 53 ('
                f'msg:"TIP Threat Block - DNS Query for Malicious Domain {clean_dom}"; '
                f'dns.query; content:"{clean_dom}"; nocase; '
                f'reference:url,tip.local/threat-feed; '
                f'classtype:bad-unknown; '
                f'sid:{sid}; rev:1;)'
            )
            lines.append(rule)
            sid += 1

    return "\n".join(lines) + "\n"


def generate_csv_blocklist(indicators: List[ThreatIndicator]) -> str:
    """
    Generate RFC 4180 compliant CSV export with metadata for SIEM lookup tables.
    """
    headers = [
        "indicator_value",
        "indicator_type",
        "risk_score",
        "severity",
        "confidence_score",
        "status",
        "tlp_marking",
        "source",
        "first_seen_at",
        "last_seen_at",
        "context"
    ]
    lines: List[str] = [",".join(headers)]

    for ind in indicators:
        # Escape double quotes
        ctx = (ind.context or "").replace('"', '""').replace("\n", " ").strip()
        src = (ind.source or "").replace('"', '""').strip()
        row = [
            f'"{ind.indicator_value}"',
            f'"{ind.indicator_type}"',
            str(ind.risk_score or 0),
            f'"{ind.severity}"',
            str(ind.confidence_score or 50),
            f'"{ind.status}"',
            f'"{ind.tlp_marking}"',
            f'"{src}"',
            f'"{ind.first_seen_at.isoformat() if ind.first_seen_at else ""}"',
            f'"{ind.last_seen_at.isoformat() if ind.last_seen_at else ""}"',
            f'"{ctx}"',
        ]
        lines.append(",".join(row))

    return "\n".join(lines) + "\n"


def get_blocklist_statistics() -> Dict[str, Any]:
    """
    Compute real-time statistics for all active blocklist feeds.
    """
    active_query = ThreatIndicator.query.filter(ThreatIndicator.status == "Active")
    total_active = active_query.count()

    high_risk_count = active_query.filter(
        or_(
            ThreatIndicator.risk_score >= 50,
            ThreatIndicator.severity.in_(["Critical", "High"])
        )
    ).count()

    critical_count = active_query.filter(
        or_(
            ThreatIndicator.risk_score >= 75,
            ThreatIndicator.severity == "Critical"
        )
    ).count()

    # Breakdown by indicator type
    type_counts: Dict[str, int] = {}
    rows = db.session.query(
        ThreatIndicator.indicator_type,
        func.count(ThreatIndicator.id)
    ).filter(
        ThreatIndicator.status == "Active",
        or_(
            ThreatIndicator.risk_score >= 50,
            ThreatIndicator.severity.in_(["Critical", "High"])
        )
    ).group_by(ThreatIndicator.indicator_type).all()

    for itype, cnt in rows:
        type_counts[str(itype).lower()] = cnt

    return {
        "status": "healthy",
        "total_active_indicators": total_active,
        "high_risk_blocked_total": high_risk_count,
        "critical_risk_blocked_total": critical_count,
        "type_breakdown": type_counts,
        "last_evaluated": datetime.now(timezone.utc).isoformat(),
        "formats_available": [
            "plain", "ip", "domains", "urls", "hashes", "hosts", "rpz", "suricata", "csv", "json"
        ]
    }
