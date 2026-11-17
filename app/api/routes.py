"""
REST API Endpoints for Threat Intelligence Platform
===================================================
Includes Task 8: SIEM & EDR Webhook Ingestion, Real-Time IOC Lookup,
and Firewall/EDR Sensor Blocklist Feeds.
"""

from datetime import datetime
import json
import logging
from flask import Blueprint, jsonify, request, Response

from app import db, limiter
from . import api_bp
from app.services.siem_edr_service import (
    authenticate_api_request,
    verify_webhook_signature,
    ingest_siem_edr_alert,
    lookup_ioc,
    get_blocklist_data,
)

logger = logging.getLogger(__name__)
from app.services.edr_service import ingest_edr_alert
from app.services.stix_service import (
    export_stix_bundle,
    get_taxii_collections_manifest,
    build_stix_bundle,
    indicator_to_stix,
)
from app.services.blocklist_service import (
    fetch_blocklist_indicators,
    generate_plain_blocklist,
    generate_hosts_sinkhole_blocklist,
    generate_dns_rpz_blocklist,
    generate_suricata_snort_rules,
    generate_csv_blocklist,
    get_blocklist_statistics,
    compute_feed_etag,
)
from app.services.mitre_service import (
    get_all_tactics,
    get_tactic,
    get_technique,
    search_techniques,
    extract_mitre_techniques_from_text,
    get_mitre_matrix_coverage,
    generate_attack_navigator_layer,
)
from app.services.ioc_expiry_service import (
    evaluate_and_expire_iocs,
    reactivate_indicator,
    bulk_reactivate_indicators,
    get_expiry_statistics,
    get_expiring_soon_indicators,
    DEFAULT_TTL_POLICIES,
)
from app.services.api_crud_service import (
    list_indicators as crud_list_indicators,
    get_indicator as crud_get_indicator,
    create_indicator as crud_create_indicator,
    update_indicator as crud_update_indicator,
    delete_indicator as crud_delete_indicator,
    list_alerts as crud_list_alerts,
    get_alert as crud_get_alert,
    update_alert_status as crud_update_alert_status,
    list_reports as crud_list_reports,
    get_report as crud_get_report,
    list_malware as crud_list_malware,
    get_malware as crud_get_malware,
    list_audit_logs as crud_list_audit_logs,
    list_users as crud_list_users,
    get_openapi_schema,
)
from app.models import ThreatIndicator


def make_cached_feed_response(content: str, mimetype: str, filename: str = None) -> Response:
    """Helper to return HTTP response with ETag, 304 validation, and caching headers."""
    etag = compute_feed_etag(content)
    if_none_match = request.headers.get("If-None-Match")
    if if_none_match and if_none_match.strip('"') == etag:
        return Response(status=304)

    headers = {
        "ETag": f'"{etag}"',
        "Cache-Control": "public, max-age=300",
        "Access-Control-Allow-Origin": "*",
    }
    if filename:
        headers["Content-Disposition"] = f"inline; filename={filename}"

    return Response(content, mimetype=mimetype, headers=headers)


@api_bp.route("/api/status", methods=["GET"])
def api_status():
    """Healthcheck endpoint for platform API."""
    return jsonify({
        "status": "operational",
        "version": "1.0",
        "endpoints": {
            "webhook_ingest": "/api/v1/webhook/alert",
            "edr_alert_ingest": "/api/v1/edr/alert",
            "ioc_lookup": "/api/v1/ioc/lookup",
            "blocklist_json": "/api/v1/feed/blocklist",
            "blocklist_plain": "/api/v1/feed/blocklist/plain",
            "blocklist_ip": "/api/v1/blocklist/ip",
            "blocklist_domains": "/api/v1/blocklist/domains",
            "blocklist_urls": "/api/v1/blocklist/urls",
            "blocklist_hashes": "/api/v1/blocklist/hashes",
            "blocklist_hosts": "/api/v1/blocklist/hosts",
            "blocklist_rpz": "/api/v1/blocklist/rpz",
            "blocklist_suricata": "/api/v1/blocklist/suricata",
            "blocklist_csv": "/api/v1/blocklist/csv",
            "blocklist_stats": "/api/v1/blocklist/stats",
            "stix_bundle": "/api/v1/stix/bundle",
            "stix_download": "/api/v1/stix/download",
            "taxii_collections": "/api/v1/taxii/collections",
            "mitre_tactics": "/api/v1/mitre/tactics",
            "mitre_techniques": "/api/v1/mitre/techniques",
            "mitre_coverage": "/api/v1/mitre/coverage",
            "mitre_navigator": "/api/v1/mitre/navigator",
            "mitre_extract": "/api/v1/mitre/extract",
            "ioc_expire": "/api/v1/ioc/expire",
            "ioc_expiry_stats": "/api/v1/ioc/expiry/stats",
            "ioc_expiring_soon": "/api/v1/ioc/expiry/expiring-soon",
            "ioc_reactivate": "/api/v1/ioc/reactivate/<id>",
            "ioc_bulk_reactivate": "/api/v1/ioc/bulk-reactivate",
            "v2_indicators": "/api/v2/indicators",
            "v2_alerts": "/api/v2/alerts",
            "v2_reports": "/api/v2/reports",
            "v2_malware": "/api/v2/malware",
            "v2_audit_logs": "/api/v2/audit-logs",
            "v2_users": "/api/v2/users",
            "v2_docs": "/api/v2/docs",
        }
    })


@api_bp.route("/api/v1/webhook/alert", methods=["POST"])
@limiter.limit("120 per minute", methods=["POST"])
def webhook_alert_ingest():
    """
    Inbound Webhook receiver for SIEM & EDR alerts (Splunk, Microsoft Sentinel, CrowdStrike, Defender).
    Authenticates via X-API-Key or Authorization Bearer header.
    Automatically extracts IOCs, calculates deterministic risk scores, and triggers alerts in Alert Center.
    """
    is_auth, auth_msg, actor_info = authenticate_api_request(request)
    if not is_auth:
        return jsonify({
            "success": False,
            "error": "Unauthorized",
            "message": auth_msg
        }), 401

    is_sig_valid, sig_msg = verify_webhook_signature(request)
    if not is_sig_valid:
        return jsonify({
            "success": False,
            "error": "InvalidSignature",
            "message": sig_msg
        }), 401

    if not request.is_json:
        return jsonify({
            "success": False,
            "error": "InvalidContentType",
            "message": "Content-Type must be application/json."
        }), 400

    payload = request.get_json(silent=True)
    if not payload or not isinstance(payload, dict):
        return jsonify({
            "success": False,
            "error": "EmptyPayload",
            "message": "Request body must contain a valid JSON object."
        }), 400

    try:
        result = ingest_siem_edr_alert(payload, actor_info=actor_info)
        return jsonify(result), 201
    except Exception as e:
        logger.error("SIEM webhook ingestion failed: %s", e, exc_info=True)
        return jsonify({
            "success": False,
            "error": "IngestionError",
            "message": "An error occurred while processing the SIEM webhook alert."
        }), 500


@api_bp.route("/api/v1/edr/alert", methods=["POST"])
@limiter.limit("120 per minute", methods=["POST"])
def edr_alert_ingest():
    """
    Dedicated EDR telemetry & alert ingestion endpoint (Task 9).
    Receives alerts from CrowdStrike Falcon, Microsoft Defender for Endpoint,
    SentinelOne, and Carbon Black.
    Processes endpoint context, process tree, file hashes, MITRE ATT&CK TTPs,
    correlates with Malware database, and computes containment recommendations.
    """
    is_auth, auth_msg, actor_info = authenticate_api_request(request)
    if not is_auth:
        return jsonify({
            "success": False,
            "error": "Unauthorized",
            "message": auth_msg
        }), 401

    is_sig_valid, sig_msg = verify_webhook_signature(request)
    if not is_sig_valid:
        return jsonify({
            "success": False,
            "error": "InvalidSignature",
            "message": sig_msg
        }), 401

    if not request.is_json:
        return jsonify({
            "success": False,
            "error": "InvalidContentType",
            "message": "Content-Type must be application/json."
        }), 400

    payload = request.get_json(silent=True)
    if not payload or not isinstance(payload, dict):
        return jsonify({
            "success": False,
            "error": "EmptyPayload",
            "message": "Request body must contain a valid JSON object."
        }), 400

    try:
        result = ingest_edr_alert(payload, actor_info=actor_info)
        return jsonify(result), 201
    except Exception as e:
        logger.error("EDR alert ingestion failed: %s", e, exc_info=True)
        return jsonify({
            "success": False,
            "error": "EDRIngestionError",
            "message": "An error occurred while processing the EDR alert telemetry."
        }), 500


@api_bp.route("/api/v1/ioc/lookup", methods=["GET", "POST"])
@limiter.limit("100 per minute")
def api_ioc_lookup():
    """
    Bi-directional Real-Time IOC Lookup for SIEM & EDR.
    Allows SOC analysts or automated playbooks to check indicator reputation,
    relational threat reports, malware families, and receive actionable recommendations.
    """
    is_auth, auth_msg, _ = authenticate_api_request(request)
    if not is_auth:
        return jsonify({
            "success": False,
            "error": "Unauthorized",
            "message": auth_msg
        }), 401

    if request.method == "POST":
        data = request.get_json(silent=True) or {}
        # Batch lookup support
        if "indicators" in data and isinstance(data["indicators"], list):
            results = []
            for item in data["indicators"][:50]:  # limit batch size
                val = item if isinstance(item, str) else item.get("value", "")
                t = None if isinstance(item, str) else item.get("type")
                results.append(lookup_ioc(val, t))
            return jsonify({
                "success": True,
                "count": len(results),
                "results": results
            }), 200

        indicator_val = data.get("indicator") or data.get("value")
        indicator_type = data.get("type")
    else:
        indicator_val = request.args.get("indicator") or request.args.get("value")
        indicator_type = request.args.get("type")

    if not indicator_val:
        return jsonify({
            "success": False,
            "error": "MissingParameter",
            "message": "Parameter 'indicator' or 'value' is required."
        }), 400

    res = lookup_ioc(indicator_val, indicator_type)
    return jsonify({
        "success": True,
        **res
    }), 200


@api_bp.route("/api/v1/feed/blocklist", methods=["GET"])
@limiter.limit("60 per minute")
def api_blocklist_feed():
    """
    Automated JSON blocklist feed for SIEM threat intel lists, EDR sensor feeds, and Firewalls.
    Supports filtering by indicator type (?type=ipv4) and minimum risk score (?min_risk=50).
    """
    ind_type = request.args.get("type")
    min_risk = request.args.get("min_risk", 50, type=int)
    limit = request.args.get("limit", 1000, type=int)

    items = get_blocklist_data(indicator_type=ind_type, min_risk=min_risk, limit=limit)
    return jsonify({
        "success": True,
        "feed_name": "ThreatIntelPlatform-ActiveBlocklist",
        "filter": {
            "type": ind_type or "all",
            "min_risk": min_risk,
            "limit": limit
        },
        "total": len(items),
        "indicators": items
    }), 200


@api_bp.route("/api/v1/feed/blocklist/plain", methods=["GET"])
@limiter.limit("60 per minute")
def api_blocklist_plain():
    """
    Plain-text feed (one indicator per line) for Firewall dynamic blocklists
    (Palo Alto External Dynamic List, Fortinet Threat Feed, pfSense, Snort, Suricata).
    """
    ind_type = request.args.get("type")
    min_risk = request.args.get("min_risk", 50, type=int)
    limit = request.args.get("limit", 2000, type=int)

    items = get_blocklist_data(indicator_type=ind_type, min_risk=min_risk, limit=limit)
    lines = [item["value"] for item in items]
    content = "\n".join(lines) + "\n"

    return Response(content, mimetype="text/plain", headers={
        "Content-Disposition": "inline; filename=blocklist.txt"
    })


# ===========================================================================
# STIX 2.1 & TAXII 2.1 THREAT INTEL SHARING (Task 10)
# ===========================================================================

@api_bp.route("/api/v1/stix/bundle", methods=["GET"])
@limiter.limit("30 per minute")
def api_stix_bundle():
    """
    Export Indicators, Malwares, and Threat Reports in OASIS STIX 2.1 JSON Bundle format.
    Allows interoperability with threat intelligence platforms (OpenCTI, MISP, Anomali, ThreatConnect).
    Query Parameters:
      - ?type= (ipv4, domain, url, hash)
      - ?min_risk= (e.g. 50 or 75)
      - ?severity= (Critical, High, Medium, Low)
      - ?status= (Active, Inactive, Expired)
      - ?report_id= (Export indicators & malwares for a specific report)
      - ?malware_id= (Export indicators for a specific malware)
      - ?limit= (Default 500)
    """
    ind_type = request.args.get("type")
    min_risk = request.args.get("min_risk", type=int)
    severity = request.args.get("severity")
    status = request.args.get("status")
    report_id = request.args.get("report_id", type=int)
    malware_id = request.args.get("malware_id", type=int)
    limit = request.args.get("limit", 500, type=int)

    bundle = export_stix_bundle(
        indicator_type=ind_type,
        min_risk=min_risk,
        severity=severity,
        status=status,
        report_id=report_id,
        malware_id=malware_id,
        limit=min(limit, 2000),
    )

    resp_json = json.dumps(bundle, indent=2)
    return Response(
        resp_json,
        mimetype="application/vnd.oasis.stix+json; version=2.1",
        headers={
            "Content-Type": "application/vnd.oasis.stix+json; version=2.1",
            "Access-Control-Allow-Origin": "*",
        }
    )


@api_bp.route("/api/v1/stix/download", methods=["GET"])
@limiter.limit("30 per minute")
def api_stix_download():
    """
    Download complete STIX 2.1 Bundle as a JSON file attachment for manual import
    into SIEM, SOAR, or external Threat Intelligence Platforms.
    """
    ind_type = request.args.get("type")
    min_risk = request.args.get("min_risk", type=int)
    severity = request.args.get("severity")
    limit = request.args.get("limit", 1000, type=int)

    bundle = export_stix_bundle(
        indicator_type=ind_type,
        min_risk=min_risk,
        severity=severity,
        limit=min(limit, 5000),
    )

    timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    filename = f"stix_bundle_{timestamp}.json"
    content = json.dumps(bundle, indent=2)

    return Response(
        content,
        mimetype="application/vnd.oasis.stix+json; version=2.1",
        headers={
            "Content-Disposition": f"attachment; filename={filename}",
            "Content-Type": "application/vnd.oasis.stix+json; version=2.1",
        }
    )


@api_bp.route("/api/v1/stix/indicator/<int:indicator_id>", methods=["GET"])
@limiter.limit("60 per minute")
def api_stix_single_indicator(indicator_id):
    """Export an individual ThreatIndicator as a standalone STIX 2.1 Bundle."""
    ind = db.session.get(ThreatIndicator, indicator_id)
    if not ind:
        return jsonify({
            "success": False,
            "error": "NotFound",
            "message": f"ThreatIndicator #{indicator_id} not found."
        }), 404

    bundle = build_stix_bundle(
        indicators=[ind],
        malwares=ind.malwares,
        reports=ind.reports,
    )
    return Response(
        json.dumps(bundle, indent=2),
        mimetype="application/vnd.oasis.stix+json; version=2.1"
    )


@api_bp.route("/api/v1/taxii/collections", methods=["GET"])
@limiter.limit("60 per minute")
def api_taxii_collections():
    """
    TAXII 2.1 Collection Discovery endpoint for automated STIX feed pollers.
    """
    manifest = get_taxii_collections_manifest()
    return jsonify(manifest), 200


# ===========================================================================
# AUTOMATED IOC BLOCKLIST EXPORT ENGINE (Task 11)
# ===========================================================================

@api_bp.route("/api/v1/blocklist/ip", methods=["GET"])
@limiter.limit("60 per minute")
def api_blocklist_ip():
    """
    Automated IP blocklist feed for firewalls (Palo Alto EDL, Fortinet, pfSense, Check Point).
    Returns newline-delimited IPv4/IPv6 addresses.
    """
    min_risk = request.args.get("min_risk", 50, type=int)
    severity = request.args.get("severity")
    limit = request.args.get("limit", 5000, type=int)
    include_header = request.args.get("comments", "false").lower() in ("true", "1", "yes")

    inds = fetch_blocklist_indicators(
        indicator_types=["ipv4", "ip", "ipv6"],
        min_risk=min_risk,
        severity=severity,
        limit=limit,
    )
    content = generate_plain_blocklist(inds, include_header=include_header)
    return make_cached_feed_response(content, mimetype="text/plain", filename="blocklist_ip.txt")


@api_bp.route("/api/v1/blocklist/domains", methods=["GET"])
@limiter.limit("60 per minute")
def api_blocklist_domains():
    """
    Automated Domain blocklist feed for DNS firewalls, pi-hole, and web filters.
    Returns newline-delimited domain names.
    """
    min_risk = request.args.get("min_risk", 50, type=int)
    severity = request.args.get("severity")
    limit = request.args.get("limit", 5000, type=int)
    include_header = request.args.get("comments", "false").lower() in ("true", "1", "yes")

    inds = fetch_blocklist_indicators(
        indicator_types=["domain", "hostname"],
        min_risk=min_risk,
        severity=severity,
        limit=limit,
    )
    content = generate_plain_blocklist(inds, include_header=include_header)
    return make_cached_feed_response(content, mimetype="text/plain", filename="blocklist_domains.txt")


@api_bp.route("/api/v1/blocklist/urls", methods=["GET"])
@limiter.limit("60 per minute")
def api_blocklist_urls():
    """
    Automated URL blocklist feed for forward proxies (Squid, Zscaler, BlueCoat / Symantec).
    Returns newline-delimited URLs.
    """
    min_risk = request.args.get("min_risk", 50, type=int)
    severity = request.args.get("severity")
    limit = request.args.get("limit", 5000, type=int)
    include_header = request.args.get("comments", "false").lower() in ("true", "1", "yes")

    inds = fetch_blocklist_indicators(
        indicator_types=["url"],
        min_risk=min_risk,
        severity=severity,
        limit=limit,
    )
    content = generate_plain_blocklist(inds, include_header=include_header)
    return make_cached_feed_response(content, mimetype="text/plain", filename="blocklist_urls.txt")


@api_bp.route("/api/v1/blocklist/hashes", methods=["GET"])
@limiter.limit("60 per minute")
def api_blocklist_hashes():
    """
    Automated File Hash blocklist feed for EDR custom detection (CrowdStrike Falcon, Defender, SentinelOne).
    Returns newline-delimited SHA256, MD5, and SHA1 hashes.
    """
    min_risk = request.args.get("min_risk", 50, type=int)
    severity = request.args.get("severity")
    limit = request.args.get("limit", 5000, type=int)
    include_header = request.args.get("comments", "false").lower() in ("true", "1", "yes")

    inds = fetch_blocklist_indicators(
        indicator_types=["sha256", "md5", "sha1"],
        min_risk=min_risk,
        severity=severity,
        limit=limit,
    )
    content = generate_plain_blocklist(inds, include_header=include_header)
    return make_cached_feed_response(content, mimetype="text/plain", filename="blocklist_hashes.txt")


@api_bp.route("/api/v1/blocklist/hosts", methods=["GET"])
@limiter.limit("60 per minute")
def api_blocklist_hosts():
    """
    DNS Sinkhole Hosts format ('0.0.0.0 domain.com') for Pi-hole, AdGuard Home, dnsmasq, unbound.
    """
    min_risk = request.args.get("min_risk", 50, type=int)
    severity = request.args.get("severity")
    sinkhole_ip = request.args.get("ip", "0.0.0.0")
    limit = request.args.get("limit", 5000, type=int)

    inds = fetch_blocklist_indicators(
        indicator_types=["domain", "hostname"],
        min_risk=min_risk,
        severity=severity,
        limit=limit,
    )
    content = generate_hosts_sinkhole_blocklist(inds, sinkhole_ip=sinkhole_ip)
    return make_cached_feed_response(content, mimetype="text/plain", filename="hosts.txt")


@api_bp.route("/api/v1/blocklist/rpz", methods=["GET"])
@limiter.limit("60 per minute")
def api_blocklist_rpz():
    """
    BIND9 / PowerDNS Response Policy Zone (DNS RPZ) policy zone file format.
    """
    min_risk = request.args.get("min_risk", 50, type=int)
    severity = request.args.get("severity")
    zone_name = request.args.get("zone", "rpz.tip.local")
    limit = request.args.get("limit", 5000, type=int)

    inds = fetch_blocklist_indicators(
        indicator_types=["domain", "hostname"],
        min_risk=min_risk,
        severity=severity,
        limit=limit,
    )
    content = generate_dns_rpz_blocklist(inds, zone_name=zone_name)
    return make_cached_feed_response(content, mimetype="text/plain", filename="rpz.zone")


@api_bp.route("/api/v1/blocklist/suricata", methods=["GET"])
@limiter.limit("60 per minute")
def api_blocklist_suricata():
    """
    Suricata and Snort IDS/IPS signature rules for malicious IP and DNS traffic.
    """
    min_risk = request.args.get("min_risk", 50, type=int)
    severity = request.args.get("severity")
    base_sid = request.args.get("sid", 1900000, type=int)
    limit = request.args.get("limit", 5000, type=int)

    inds = fetch_blocklist_indicators(
        indicator_types=["ipv4", "ip", "domain"],
        min_risk=min_risk,
        severity=severity,
        limit=limit,
    )
    content = generate_suricata_snort_rules(inds, base_sid=base_sid)
    return make_cached_feed_response(content, mimetype="text/plain", filename="tip_blocklist.rules")


@api_bp.route("/api/v1/blocklist/csv", methods=["GET"])
@limiter.limit("60 per minute")
def api_blocklist_csv():
    """
    CSV export with full threat metadata for SIEM lookup tables (Splunk, Sentinel, QRadar).
    """
    min_risk = request.args.get("min_risk", 50, type=int)
    severity = request.args.get("severity")
    ind_type = request.args.get("type")
    types = [ind_type] if ind_type and ind_type.lower() != "all" else None
    limit = request.args.get("limit", 5000, type=int)

    inds = fetch_blocklist_indicators(
        indicator_types=types,
        min_risk=min_risk,
        severity=severity,
        limit=limit,
    )
    content = generate_csv_blocklist(inds)
    return make_cached_feed_response(content, mimetype="text/csv", filename="blocklist.csv")


@api_bp.route("/api/v1/blocklist/stats", methods=["GET"])
def api_blocklist_stats():
    """
    Real-time statistics & healthcheck for active perimeter blocklists.
    """
    stats = get_blocklist_statistics()
    return jsonify(stats), 200


# ===========================================================================
# MITRE ATT&CK MAPPING & MATRIX API (Task 12)
# ===========================================================================

@api_bp.route("/api/v1/mitre/tactics", methods=["GET"])
def api_mitre_tactics():
    """
    List all 14 Enterprise MITRE ATT&CK Tactics with metadata and technique counts.
    """
    tactics = get_all_tactics()
    return jsonify({
        "success": True,
        "total": len(tactics),
        "tactics": tactics,
    }), 200


@api_bp.route("/api/v1/mitre/techniques", methods=["GET"])
def api_mitre_techniques():
    """
    Query, filter, and search MITRE ATT&CK techniques.
    Supports ?tactic=, ?platform=, ?q=, and ?limit=.
    """
    tactic = request.args.get("tactic")
    platform = request.args.get("platform")
    q = request.args.get("q")
    limit = request.args.get("limit", 100, type=int)

    techniques = search_techniques(
        query=q,
        tactic=tactic,
        platform=platform,
        limit=min(limit, 500),
    )
    return jsonify({
        "success": True,
        "count": len(techniques),
        "techniques": techniques,
    }), 200


@api_bp.route("/api/v1/mitre/technique/<string:technique_id>", methods=["GET"])
def api_mitre_technique_detail(technique_id):
    """
    Get detailed metadata for a specific MITRE ATT&CK technique by ID (e.g. T1059.001).
    """
    technique = get_technique(technique_id)
    if not technique:
        return jsonify({
            "success": False,
            "error": "NotFound",
            "message": f"Technique ID '{technique_id}' is invalid or not found."
        }), 404

    return jsonify({
        "success": True,
        "technique": technique,
    }), 200


@api_bp.route("/api/v1/mitre/coverage", methods=["GET"])
def api_mitre_coverage():
    """
    Real-time platform MITRE ATT&CK Matrix coverage and heatmap data across all malware & alerts.
    """
    coverage = get_mitre_matrix_coverage()
    return jsonify(coverage), 200


@api_bp.route("/api/v1/mitre/navigator", methods=["GET"])
def api_mitre_navigator_export():
    """
    Export official MITRE ATT&CK Navigator Layer v4.5 JSON format.
    Pass ?download=true to download as an attachment.
    """
    layer = generate_attack_navigator_layer()
    content = json.dumps(layer, indent=2)

    download = request.args.get("download", "false").lower() in ("true", "1", "yes")
    headers = {
        "Content-Type": "application/json",
        "Access-Control-Allow-Origin": "*",
    }
    if download:
        headers["Content-Disposition"] = "attachment; filename=mitre_attack_layer.json"

    return Response(content, mimetype="application/json", headers=headers)


@api_bp.route("/api/v1/mitre/extract", methods=["POST"])
@limiter.limit("60 per minute", methods=["POST"])
def api_mitre_extract():
    """
    Extract and resolve MITRE ATT&CK techniques from arbitrary text/log payload.
    Requires authentication.
    Body: {"text": "Adversary ran powershell.exe (T1059.001) ..."}
    """
    is_auth, auth_msg, _ = authenticate_api_request(request)
    if not is_auth:
        return jsonify({
            "success": False,
            "error": "Unauthorized",
            "message": auth_msg,
            "techniques": []
        }), 401

    data = request.get_json(silent=True) or {}
    text = data.get("text") or request.form.get("text") or ""
    if not text:
        return jsonify({
            "success": False,
            "error": "BadRequest",
            "message": "Field 'text' is required.",
            "techniques": []
        }), 400

    techniques = extract_mitre_techniques_from_text(text[:50000])
    return jsonify({
        "success": True,
        "count": len(techniques),
        "techniques": techniques,
    }), 200


# =============================================================================
# Automated IOC Expiry & Lifecycle API Endpoints (Task 13)
# =============================================================================

@api_bp.route("/api/v1/ioc/expire", methods=["POST"])
@limiter.limit("30 per minute", methods=["POST"])
def api_ioc_expire():
    """
    Trigger the automated IOC expiry job on demand.
    Requires admin or analyst privileges.
    Supports query parameters or JSON payload:
    - dry_run: bool (default: false)
    - days: int (optional global TTL override)
    - type: str (optional indicator type filter)
    - custom_ttl: dict (optional mapping of type to TTL days)
    """
    is_auth, auth_msg, actor_info = authenticate_api_request(request)
    if not is_auth:
        return jsonify({"success": False, "error": "Unauthorized", "message": auth_msg}), 401

    if actor_info and actor_info.get("role") not in ("admin", "analyst"):
        return jsonify({
            "success": False,
            "error": "Forbidden",
            "message": "Analyst or admin privileges required to execute IOC expiration."
        }), 403

    data = request.get_json(silent=True) or {}

    # Check dry_run from JSON or query string
    dry_run = data.get("dry_run")
    if dry_run is None:
        dry_run = request.args.get("dry_run", "false").lower() in ("true", "1", "yes")
    else:
        dry_run = bool(dry_run)

    # Check days override
    days = data.get("days") or request.args.get("days")
    custom_policies = data.get("custom_ttl") or {}
    if days is not None:
        try:
            d_val = int(days)
            for k in DEFAULT_TTL_POLICIES:
                if k not in custom_policies:
                    custom_policies[k] = d_val
        except (ValueError, TypeError):
            pass

    filter_type = data.get("type") or request.args.get("type")

    user_id = actor_info["id"] if (actor_info and actor_info.get("id")) else None

    try:
        result = evaluate_and_expire_iocs(
            ttl_policies=custom_policies if custom_policies else None,
            dry_run=dry_run,
            user_id=user_id,
            filter_type=filter_type,
        )
        return jsonify(result), 200
    except Exception as exc:
        logger.error("IOC expiry execution failed: %s", exc, exc_info=True)
        return jsonify({
            "success": False,
            "error": "ExpiryExecutionError",
            "message": "An error occurred while executing automated IOC expiration.",
        }), 500


@api_bp.route("/api/v1/ioc/expiry/stats", methods=["GET"])
@limiter.limit("60 per minute")
def api_ioc_expiry_stats():
    """
    Get comprehensive IOC lifecycle, aging, and expiration statistics.
    """
    stats = get_expiry_statistics()
    return jsonify({
        "success": True,
        "statistics": stats,
    }), 200


@api_bp.route("/api/v1/ioc/expiry/expiring-soon", methods=["GET"])
@limiter.limit("60 per minute")
def api_ioc_expiring_soon():
    """
    Get Active indicators approaching expiration within N days.
    Query parameters:
    - days: int (default: 7)
    - limit: int (default: 50)
    """
    try:
        days = int(request.args.get("days", 7))
    except (ValueError, TypeError):
        days = 7

    try:
        limit = int(request.args.get("limit", 50))
    except (ValueError, TypeError):
        limit = 50

    expiring = get_expiring_soon_indicators(days_threshold=days, limit=limit)
    return jsonify({
        "success": True,
        "days_threshold": days,
        "count": len(expiring),
        "expiring_soon": expiring,
    }), 200


@api_bp.route("/api/v1/ioc/reactivate/<int:indicator_id>", methods=["POST"])
@limiter.limit("60 per minute", methods=["POST"])
def api_ioc_reactivate(indicator_id: int):
    """
    Reactivate a single expired indicator back to Active status.
    Requires admin or analyst privileges.
    Accepts optional JSON payload {"reason": "Analyst manual review"}.
    """
    is_auth, auth_msg, actor_info = authenticate_api_request(request)
    if not is_auth:
        return jsonify({"success": False, "error": "Unauthorized", "message": auth_msg}), 401

    if actor_info and actor_info.get("role") not in ("admin", "analyst"):
        return jsonify({
            "success": False,
            "error": "Forbidden",
            "message": "Analyst or admin privileges required to reactivate indicators."
        }), 403

    data = request.get_json(silent=True) or {}
    reason = data.get("reason") or "Manual Analyst Reactivation"

    user_id = actor_info["id"] if (actor_info and actor_info.get("id")) else None

    result = reactivate_indicator(
        indicator_id=indicator_id,
        user_id=user_id,
        reason=reason,
    )

    if not result.get("success"):
        return jsonify(result), 404

    return jsonify(result), 200


@api_bp.route("/api/v1/ioc/bulk-reactivate", methods=["POST"])
@limiter.limit("30 per minute", methods=["POST"])
def api_ioc_bulk_reactivate():
    """
    Bulk reactivate multiple expired indicators.
    Requires admin or analyst privileges.
    Payload: {"indicator_ids": [1, 2, 3], "reason": "Batch validation"}
    """
    is_auth, auth_msg, actor_info = authenticate_api_request(request)
    if not is_auth:
        return jsonify({"success": False, "error": "Unauthorized", "message": auth_msg}), 401

    if actor_info and actor_info.get("role") not in ("admin", "analyst"):
        return jsonify({
            "success": False,
            "error": "Forbidden",
            "message": "Analyst or admin privileges required for bulk reactivation."
        }), 403

    data = request.get_json(silent=True) or {}
    indicator_ids = data.get("indicator_ids")
    if not indicator_ids or not isinstance(indicator_ids, list):
        return jsonify({
            "success": False,
            "error": "BadRequest",
            "message": "Field 'indicator_ids' must be a non-empty list of indicator IDs.",
        }), 400

    reason = data.get("reason") or "Bulk Analyst Reactivation"

    user_id = actor_info["id"] if (actor_info and actor_info.get("id")) else None

    result = bulk_reactivate_indicators(
        indicator_ids=indicator_ids,
        user_id=user_id,
        reason=reason,
    )

    return jsonify(result), 200

    return jsonify(result), 200


# =============================================================================
# REST API v2 — Full CRUD Endpoints (Task 9: Phase 2)
# =============================================================================

def _resolve_api_actor(req):
    """Resolve the authenticated actor's user ID from the API request."""
    _, _, actor_info = authenticate_api_request(req)
    if actor_info and actor_info.get("id"):
        return actor_info["id"]
    return None


# ---- OpenAPI Documentation ----

@api_bp.route("/api/v2/docs", methods=["GET"])
def api_v2_docs():
    """OpenAPI 3.0 schema describing all REST API v2 endpoints."""
    return jsonify(get_openapi_schema()), 200


# ---- Indicators CRUD ----

@api_bp.route("/api/v2/indicators", methods=["GET"])
def api_v2_list_indicators():
    """List threat indicators with filtering, search, sorting, and pagination."""
    is_auth, auth_msg, _ = authenticate_api_request(request)
    if not is_auth:
        return jsonify({"success": False, "error": "Unauthorized", "message": auth_msg}), 401

    result = crud_list_indicators(
        page=request.args.get("page", 1, type=int),
        per_page=request.args.get("per_page", 20, type=int),
        indicator_type=request.args.get("type"),
        severity=request.args.get("severity"),
        status=request.args.get("status"),
        q=request.args.get("q"),
        min_risk=request.args.get("min_risk", type=int),
        sort_by=request.args.get("sort_by"),
        sort_order=request.args.get("sort_order"),
    )
    return jsonify(result), 200


@api_bp.route("/api/v2/indicators", methods=["POST"])
@limiter.limit("100 per minute", methods=["POST"])
def api_v2_create_indicator():
    """Create a new threat indicator."""
    is_auth, auth_msg, actor_info = authenticate_api_request(request)
    if not is_auth:
        return jsonify({"success": False, "error": "Unauthorized", "message": auth_msg}), 401

    if actor_info and actor_info.get("role") not in ("admin", "analyst"):
        return jsonify({
            "success": False,
            "error": "Forbidden",
            "message": "Analyst or admin privileges required to create indicators."
        }), 403

    user_id = _resolve_api_actor(request)
    if not user_id:
        # Fall back to first admin user for API key auth
        from app.models import User
        admin = User.query.filter_by(role="admin").first()
        user_id = admin.id if admin else 1

    data = request.get_json(silent=True) or {}
    if not data:
        return jsonify({"success": False, "error": "BadRequest", "message": "JSON body required."}), 400

    ind_dict, error = crud_create_indicator(data, user_id)
    if error:
        return jsonify({"success": False, "error": "ValidationError", "message": error}), 400

    return jsonify({"success": True, "indicator": ind_dict}), 201


@api_bp.route("/api/v2/indicators/<int:indicator_id>", methods=["GET"])
def api_v2_get_indicator(indicator_id):
    """Get a single threat indicator by ID."""
    is_auth, auth_msg, _ = authenticate_api_request(request)
    if not is_auth:
        return jsonify({"success": False, "error": "Unauthorized", "message": auth_msg}), 401

    data = crud_get_indicator(indicator_id)
    if data is None:
        return jsonify({"success": False, "error": "NotFound", "message": f"Indicator #{indicator_id} not found."}), 404

    return jsonify({"success": True, "indicator": data}), 200


@api_bp.route("/api/v2/indicators/<int:indicator_id>", methods=["PUT"])
def api_v2_update_indicator(indicator_id):
    """Update an existing threat indicator (partial update)."""
    is_auth, auth_msg, actor_info = authenticate_api_request(request)
    if not is_auth:
        return jsonify({"success": False, "error": "Unauthorized", "message": auth_msg}), 401

    if actor_info and actor_info.get("role") not in ("admin", "analyst"):
        return jsonify({
            "success": False,
            "error": "Forbidden",
            "message": "Analyst or admin privileges required to update indicators."
        }), 403

    user_id = _resolve_api_actor(request)
    if not user_id:
        from app.models import User
        admin = User.query.filter_by(role="admin").first()
        user_id = admin.id if admin else 1

    data = request.get_json(silent=True) or {}
    ind_dict, error = crud_update_indicator(indicator_id, data, user_id)
    if error:
        status_code = 404 if "not found" in error.lower() else 400
        return jsonify({"success": False, "error": "ValidationError", "message": error}), status_code

    return jsonify({"success": True, "indicator": ind_dict}), 200


@api_bp.route("/api/v2/indicators/<int:indicator_id>", methods=["DELETE"])
def api_v2_delete_indicator(indicator_id):
    """Delete a threat indicator and cascade-delete associated alerts."""
    is_auth, auth_msg, actor_info = authenticate_api_request(request)
    if not is_auth:
        return jsonify({"success": False, "error": "Unauthorized", "message": auth_msg}), 401

    if actor_info and actor_info.get("role") not in ("admin", "analyst"):
        return jsonify({
            "success": False,
            "error": "Forbidden",
            "message": "Analyst or admin privileges required to delete indicators."
        }), 403

    user_id = _resolve_api_actor(request)
    if not user_id:
        from app.models import User
        admin = User.query.filter_by(role="admin").first()
        user_id = admin.id if admin else 1

    success, message = crud_delete_indicator(indicator_id, user_id)
    if not success:
        return jsonify({"success": False, "error": "NotFound", "message": message}), 404

    return jsonify({"success": True, "message": message}), 200


# ---- Alerts CRUD ----

@api_bp.route("/api/v2/alerts", methods=["GET"])
def api_v2_list_alerts():
    """List alerts with filtering, search, sorting, and pagination."""
    is_auth, auth_msg, _ = authenticate_api_request(request)
    if not is_auth:
        return jsonify({"success": False, "error": "Unauthorized", "message": auth_msg}), 401

    is_read = request.args.get("is_read")
    if is_read is not None:
        is_read = is_read.lower() in ("true", "1", "yes")

    result = crud_list_alerts(
        page=request.args.get("page", 1, type=int),
        per_page=request.args.get("per_page", 20, type=int),
        severity=request.args.get("severity"),
        status=request.args.get("status"),
        alert_type=request.args.get("alert_type"),
        q=request.args.get("q"),
        is_read=is_read,
        sort_by=request.args.get("sort_by"),
        sort_order=request.args.get("sort_order"),
    )
    return jsonify(result), 200


@api_bp.route("/api/v2/alerts/<int:alert_id>", methods=["GET"])
def api_v2_get_alert(alert_id):
    """Get a single alert by ID."""
    is_auth, auth_msg, _ = authenticate_api_request(request)
    if not is_auth:
        return jsonify({"success": False, "error": "Unauthorized", "message": auth_msg}), 401

    data = crud_get_alert(alert_id)
    if data is None:
        return jsonify({"success": False, "error": "NotFound", "message": f"Alert #{alert_id} not found."}), 404

    return jsonify({"success": True, "alert": data}), 200


@api_bp.route("/api/v2/alerts/<int:alert_id>", methods=["PATCH"])
def api_v2_update_alert(alert_id):
    """Update alert status (lifecycle transition)."""
    is_auth, auth_msg, actor_info = authenticate_api_request(request)
    if not is_auth:
        return jsonify({"success": False, "error": "Unauthorized", "message": auth_msg}), 401

    if actor_info and actor_info.get("role") not in ("admin", "analyst"):
        return jsonify({
            "success": False,
            "error": "Forbidden",
            "message": "Analyst or admin privileges required to update alerts."
        }), 403

    user_id = _resolve_api_actor(request)
    if not user_id:
        from app.models import User
        admin = User.query.filter_by(role="admin").first()
        user_id = admin.id if admin else 1

    data = request.get_json(silent=True) or {}
    new_status = data.get("status")
    if not new_status:
        return jsonify({"success": False, "error": "BadRequest", "message": "Field 'status' is required."}), 400

    alert_dict, error = crud_update_alert_status(alert_id, new_status, user_id)
    if error:
        status_code = 404 if "not found" in error.lower() else 400
        return jsonify({"success": False, "error": "ValidationError", "message": error}), status_code

    return jsonify({"success": True, "alert": alert_dict}), 200


# ---- Reports (read-only) ----

@api_bp.route("/api/v2/reports", methods=["GET"])
def api_v2_list_reports():
    """List threat reports with filtering, search, sorting, and pagination."""
    is_auth, auth_msg, _ = authenticate_api_request(request)
    if not is_auth:
        return jsonify({"success": False, "error": "Unauthorized", "message": auth_msg}), 401

    result = crud_list_reports(
        page=request.args.get("page", 1, type=int),
        per_page=request.args.get("per_page", 20, type=int),
        severity=request.args.get("severity"),
        category=request.args.get("category"),
        q=request.args.get("q"),
        sort_by=request.args.get("sort_by"),
        sort_order=request.args.get("sort_order"),
    )
    return jsonify(result), 200


@api_bp.route("/api/v2/reports/<int:report_id>", methods=["GET"])
def api_v2_get_report(report_id):
    """Get a single threat report by ID with linked IOCs and malware."""
    is_auth, auth_msg, _ = authenticate_api_request(request)
    if not is_auth:
        return jsonify({"success": False, "error": "Unauthorized", "message": auth_msg}), 401

    data = crud_get_report(report_id)
    if data is None:
        return jsonify({"success": False, "error": "NotFound", "message": f"Report #{report_id} not found."}), 404

    return jsonify({"success": True, "report": data}), 200


# ---- Malware (read-only) ----

@api_bp.route("/api/v2/malware", methods=["GET"])
def api_v2_list_malware():
    """List malware entries with filtering, search, sorting, and pagination."""
    is_auth, auth_msg, _ = authenticate_api_request(request)
    if not is_auth:
        return jsonify({"success": False, "error": "Unauthorized", "message": auth_msg}), 401

    result = crud_list_malware(
        page=request.args.get("page", 1, type=int),
        per_page=request.args.get("per_page", 20, type=int),
        malware_type=request.args.get("malware_type"),
        platform=request.args.get("platform"),
        severity=request.args.get("severity"),
        q=request.args.get("q"),
        sort_by=request.args.get("sort_by"),
        sort_order=request.args.get("sort_order"),
    )
    return jsonify(result), 200


@api_bp.route("/api/v2/malware/<int:malware_id>", methods=["GET"])
def api_v2_get_malware(malware_id):
    """Get a single malware entry by ID with linked IOCs."""
    is_auth, auth_msg, _ = authenticate_api_request(request)
    if not is_auth:
        return jsonify({"success": False, "error": "Unauthorized", "message": auth_msg}), 401

    data = crud_get_malware(malware_id)
    if data is None:
        return jsonify({"success": False, "error": "NotFound", "message": f"Malware #{malware_id} not found."}), 404

    return jsonify({"success": True, "malware": data}), 200


# ---- Audit Logs (admin only) ----

@api_bp.route("/api/v2/audit-logs", methods=["GET"])
def api_v2_list_audit_logs():
    """List audit log entries with filtering, search, and pagination (admin only)."""
    is_auth, auth_msg, actor_info = authenticate_api_request(request)
    if not is_auth:
        return jsonify({"success": False, "error": "Unauthorized", "message": auth_msg}), 401

    # Admin-only check
    if actor_info and actor_info.get("role") and actor_info["role"] != "admin":
        return jsonify({"success": False, "error": "Forbidden", "message": "Admin access required."}), 403

    result = crud_list_audit_logs(
        page=request.args.get("page", 1, type=int),
        per_page=request.args.get("per_page", 20, type=int),
        user_id=request.args.get("user_id", type=int),
        action=request.args.get("action"),
        target_table=request.args.get("target_table"),
        q=request.args.get("q"),
        sort_by=request.args.get("sort_by"),
        sort_order=request.args.get("sort_order"),
    )
    return jsonify(result), 200


# ---- Users (admin only) ----

@api_bp.route("/api/v2/users", methods=["GET"])
def api_v2_list_users():
    """List users with pagination (admin only)."""
    is_auth, auth_msg, actor_info = authenticate_api_request(request)
    if not is_auth:
        return jsonify({"success": False, "error": "Unauthorized", "message": auth_msg}), 401

    # Admin-only check
    if actor_info and actor_info.get("role") and actor_info["role"] != "admin":
        return jsonify({"success": False, "error": "Forbidden", "message": "Admin access required."}), 403

    result = crud_list_users(
        page=request.args.get("page", 1, type=int),
        per_page=request.args.get("per_page", 20, type=int),
    )
    return jsonify(result), 200


