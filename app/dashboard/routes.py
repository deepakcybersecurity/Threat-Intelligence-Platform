from flask import (
    render_template,
    request,
    redirect,
    url_for,
    flash,
    current_app,
    send_from_directory,
    abort,
    jsonify
)

from flask_login import (
    login_required,
    current_user,
)

from functools import wraps

from app.services.ioc_extractor import extract_iocs
from app.services.ioc_enrichment import enrich_indicator
from app.services.ioc_correlation import correlate_indicator_by_id
from app.services.risk_scoring import (
    calculate_indicator_risk_by_id,
    save_indicator_risk,
)
from app.services.alert_service import (
    get_alerts_filtered,
    get_alert_counts,
    mark_alert_read,
    acknowledge_alert,
    resolve_alert,
    reopen_alert,
)
from app.services.news_service import (
    fetch_and_store_threat_news,
    get_threat_news_filtered,
    get_news_stats,
    extract_news_iocs,
)
from app.services.audit_service import log_action as _audit_log
from app.services.security_service import (
    sanitize_text,
    validate_password_complexity,
    validate_file_upload,
)
from werkzeug.security import generate_password_hash, check_password_hash
from app.services.mitre_service import (
    get_all_tactics,
    get_tactic,
    get_technique,
    map_threat_to_mitre,
    get_mitre_matrix_coverage,
    generate_attack_navigator_layer,
)

from werkzeug.utils import secure_filename

import os

from app import db

from app.models import (
    User,
    ThreatReport,
    Malware,
    Alert,
    ThreatIndicator,
    ThreatNews,
    IPLookupHistory
)

from . import dashboard_bp
from datetime import datetime 

from sqlalchemy import or_, func
# from app.models.threat_indicator import ThreatIndicator

import requests
from app.services.ip_reputation import check_ip_reputation 

from zoneinfo import ZoneInfo


# ── RBAC helper ──────────────────────────────────────────────────────────────

def analyst_required(f):
    """Route guard: must be logged in and have role admin or analyst."""
    @wraps(f)
    @login_required
    def decorated(*args, **kwargs):
        if current_user.role not in ("admin", "analyst"):
            abort(403)
        return f(*args, **kwargs)
    return decorated


@dashboard_bp.route("/dashboard")
@login_required
def dashboard():

    total_users = User.query.count()

    total_reports = ThreatReport.query.count()

    total_malware = Malware.query.count()

    total_indicators = ThreatIndicator.query.count()

    total_alerts = Alert.query.count()

    total_news = ThreatNews.query.count()

    return render_template(
        "dashboard.html",
        total_users=total_users,
        total_reports=total_reports,
        total_malware=total_malware,
        total_indicators=total_indicators,
        total_alerts=total_alerts,
        total_news=total_news
    )


@dashboard_bp.route("/threat-feed", methods=["GET"])
@login_required
def threat_feed():
    indicator_type = request.args.get("type", "").strip().lower()
    severity = request.args.get("severity", "").strip().capitalize()
    source = request.args.get("source", "").strip().lower()
    status = request.args.get("status", "").strip()

    query = ThreatIndicator.query

    if indicator_type and indicator_type != "all":
        if indicator_type in ("ip", "ipv4"):
            query = query.filter(func.lower(ThreatIndicator.indicator_type).in_(["ip", "ipv4"]))
        elif indicator_type == "hash":
            query = query.filter(func.lower(ThreatIndicator.indicator_type).in_(["md5", "sha1", "sha256"]))
        else:
            query = query.filter(func.lower(ThreatIndicator.indicator_type) == indicator_type)

    if severity and severity.lower() != "all":
        query = query.filter(ThreatIndicator.severity == severity)

    if status and status.lower() != "all":
        query = query.filter(func.lower(ThreatIndicator.status) == status.lower())

    if source and source != "all":
        query = query.filter(ThreatIndicator.source.ilike(f"%{source}%"))

    indicators = query.order_by(
        func.coalesce(ThreatIndicator.last_seen_at, ThreatIndicator.created_at).desc(),
        ThreatIndicator.id.desc()
    ).all()

    from app.services.ioc_expiry_service import get_expiry_statistics
    expiry_stats = get_expiry_statistics()

    return render_template(
        "threat-feed.html",
        indicators=indicators,
        expiry_stats=expiry_stats,
        current_status=status,
        current_type=indicator_type,
        current_severity=severity,
        current_source=source,
    )


@dashboard_bp.route("/threat-feed/run-expiry", methods=["POST"])
@login_required
def threat_feed_run_expiry():
    """Trigger automated IOC expiry job from web UI."""
    from app.services.ioc_expiry_service import evaluate_and_expire_iocs
    is_ajax = request.headers.get("X-Requested-With") == "XMLHttpRequest" or request.is_json
    dry_run = request.form.get("dry_run", "false").lower() in ("true", "1") if not request.is_json else bool(request.get_json(silent=True) or {}.get("dry_run", False))

    res = evaluate_and_expire_iocs(dry_run=dry_run, user_id=current_user.id)
    if is_ajax:
        return jsonify(res)

    flash(
        f"IOC Expiry Job completed: {res['expired_count']} indicators {'eligible to expire' if dry_run else 'expired'}.",
        "success" if res["expired_count"] > 0 else "info"
    )
    return redirect(url_for("dashboard.threat_feed"))


@dashboard_bp.route("/threat-indicator/<int:indicator_id>/reactivate", methods=["POST"])
@login_required
def threat_indicator_reactivate(indicator_id: int):
    """Reactivate an expired indicator from web UI."""
    from app.services.ioc_expiry_service import reactivate_indicator
    is_ajax = request.headers.get("X-Requested-With") == "XMLHttpRequest" or request.is_json
    reason = request.form.get("reason") if not request.is_json else (request.get_json(silent=True) or {}).get("reason")

    res = reactivate_indicator(
        indicator_id=indicator_id,
        user_id=current_user.id,
        reason=reason or "Web UI Reactivation by Analyst"
    )

    if is_ajax:
        return jsonify(res), (200 if res.get("success") else 404)

    if res.get("success"):
        flash(res["message"], "success")
    else:
        flash(res.get("message", "Failed to reactivate indicator"), "danger")

    return redirect(url_for("dashboard.threat_feed"))
    

# @dashboard_bp.route("/ip-checker", methods=["GET", "POST"])
# @login_required
# def ip_checker():

#     result = None
#     error = None

#     if request.method == "POST":

#         ip_address = request.form.get("ip_address", "").strip()

#         if not ip_address:
#             error = "Please enter an IP address."

#         else:
#             try:
#                 result = check_ip_reputation(ip_address)

#             except requests.exceptions.RequestException:
#                 error = "Unable to connect to AbuseIPDB."

#             except Exception as e:
#                 error = str(e)

#     return render_template(
#         "ip-checker.html",
#         result=result,
#         error=error
#     )

@dashboard_bp.route("/ip-checker", methods=["GET", "POST"])
@login_required
def ip_checker():

    result = None
    error = None

    if request.method == "POST":

        ip_address = request.form.get("ip_address", "").strip()

        if not ip_address:

            error = "Please enter an IP address."

        else:

            try:

                # Check IP reputation using AbuseIPDB
                result = check_ip_reputation(ip_address)

                # Save successful lookup in database
                lookup = IPLookupHistory(
                    user_id=current_user.id,
                    ip_address=ip_address,
                    country=result.get("countryCode"),
                    city=result.get("city"),
                    isp=result.get("isp"),
                    organization=result.get("organization")
                )

                db.session.add(lookup)
                db.session.commit()

            except requests.exceptions.RequestException:

                error = "Unable to connect to AbuseIPDB."

            except Exception as e:

                db.session.rollback()
                error = str(e)

    return render_template(
        "ip-checker.html",
        result=result,
        error=error
    )

@dashboard_bp.route("/ip-lookup-history")
@login_required
def ip_lookup_history():

    history = IPLookupHistory.query.filter_by(
        user_id=current_user.id
    ).order_by(
        IPLookupHistory.lookup_time.desc()
    ).all()

    # Convert database UTC time to India Standard Time
    for record in history:

        if record.lookup_time:

            record.display_lookup_time = record.lookup_time.replace(
                tzinfo=ZoneInfo("UTC")
            ).astimezone(
                ZoneInfo("Asia/Kolkata")
            )

    return render_template(
        "ip-lookup-history.html",
        history=history
    )

@dashboard_bp.route("/malware-info", methods=["GET"])
@login_required
def malware_info():

    query = request.args.get("query", "").strip()
    malware_type = request.args.get("malware_type", "").strip()
    platform = request.args.get("platform", "").strip()
    severity = request.args.get("severity", "").strip()

    malware_query = Malware.query

    # Search
    if query:
        malware_query = malware_query.filter(
            or_(
                Malware.malware_name.ilike(f"%{query}%"),
                Malware.malware_family.ilike(f"%{query}%"),
                Malware.malware_type.ilike(f"%{query}%"),
                Malware.platform.ilike(f"%{query}%"),
                Malware.severity.ilike(f"%{query}%"),
                Malware.mitre_attack_id.ilike(f"%{query}%"),
                Malware.cve_id.ilike(f"%{query}%")
            )
        )

    # Malware Type Filter
    if malware_type:
        malware_query = malware_query.filter(
            Malware.malware_type == malware_type
        )

    # Platform Filter
    if platform:
        malware_query = malware_query.filter(
            Malware.platform == platform
        )

    # Severity Filter
    if severity:
        malware_query = malware_query.filter(
            Malware.severity == severity
        )

    # Latest records first
    malwares = malware_query.order_by(
        Malware.created_at.desc()
    ).all()

    return render_template(
        "malware-info.html",
        malwares=malwares,
        query=query,
        malware_type=malware_type,
        platform=platform,
        severity=severity
    )

@dashboard_bp.route("/add-malware", methods=["GET", "POST"])
@analyst_required
def add_malware():

    if request.method == "POST":

        malware_name = sanitize_text(request.form.get("malware_name", "")).strip()
        malware_family = sanitize_text(request.form.get("malware_family", "")).strip()
        malware_type = request.form.get("malware_type")
        platform = request.form.get("platform")
        severity = request.form.get("severity")

        risk_score = request.form.get("risk_score", "50").strip()
        description = sanitize_text(request.form.get("description", "")).strip()

        first_seen_at = request.form.get("first_seen_at") or None
        last_seen_at = request.form.get("last_seen_at") or None

        mitre_attack_id = request.form.get(
            "mitre_attack_id", ""
        ).strip()

        cve_id = request.form.get(
            "cve_id", ""
        ).strip()


        # Basic validation
        if not malware_name:
            return render_template(
                "add-malware.html",
                error="Malware name is required."
            )


        try:

            risk_score = int(risk_score)

            if risk_score < 0 or risk_score > 100:
                raise ValueError


        except ValueError:

            return render_template(
                "add-malware.html",
                error="Risk score must be between 0 and 100."
            )


        malware = Malware(

            malware_name=malware_name,

            malware_family=malware_family or None,

            malware_type=malware_type,

            platform=platform,

            severity=severity,

            risk_score=risk_score,

            description=description or None,

            mitre_attack_id=mitre_attack_id or None,

            cve_id=cve_id or None,

            created_by_user_id=current_user.id

        )


        db.session.add(malware)
        db.session.flush()
        _audit_log(current_user.id, "add_malware", "malware_info", malware.id)
        db.session.commit()


        return redirect(
            url_for("dashboard.malware_info")
        )


    return render_template(
        "add-malware.html"
    )



@dashboard_bp.route("/malware/<int:malware_id>")
@login_required
def malware_details(malware_id):
    malware = Malware.query.get_or_404(malware_id)
    mitre_data = map_threat_to_mitre(malware)
    return render_template(
        "malware-details.html",
        malware=malware,
        mitre_data=mitre_data,
    )


@dashboard_bp.route("/malware/edit/<int:malware_id>", methods=["GET", "POST"])
@analyst_required
def edit_malware(malware_id):
    malware = Malware.query.get_or_404(malware_id)

    if request.method == "POST":
        malware_name = sanitize_text(request.form.get("malware_name", "")).strip()
        malware_family = sanitize_text(request.form.get("malware_family", "")).strip()
        malware_type = request.form.get("malware_type")
        platform = request.form.get("platform")
        severity = request.form.get("severity")
        risk_score = request.form.get("risk_score", "50").strip()
        description = sanitize_text(request.form.get("description", "")).strip()
        mitre_attack_id = request.form.get("mitre_attack_id", "").strip()
        cve_id = request.form.get("cve_id", "").strip()

        first_seen_at = request.form.get("first_seen_at")
        last_seen_at = request.form.get("last_seen_at")

        if not malware_name:
            flash("Malware name is required.", "danger")
            return render_template("edit-malware.html", malware=malware)

        try:
            risk_score = int(risk_score)
            if risk_score < 0 or risk_score > 100:
                raise ValueError
        except ValueError:
            flash("Risk score must be between 0 and 100.", "danger")
            return render_template("edit-malware.html", malware=malware)

        malware.malware_name = malware_name
        malware.malware_family = malware_family or None
        malware.malware_type = malware_type
        malware.platform = platform
        malware.severity = severity
        malware.risk_score = risk_score
        malware.description = description or None
        malware.mitre_attack_id = mitre_attack_id or None
        malware.cve_id = cve_id or None

        if first_seen_at:
            try:
                malware.first_seen_at = datetime.fromisoformat(first_seen_at)
            except ValueError:
                pass

        if last_seen_at:
            try:
                malware.last_seen_at = datetime.fromisoformat(last_seen_at)
            except ValueError:
                pass

        _audit_log(current_user.id, "edit_malware", "malware_info", malware.id)
        db.session.commit()
        flash("Malware record updated successfully.", "success")
        return redirect(url_for("dashboard.malware_details", malware_id=malware.id))

    return render_template(
        "edit-malware.html",
        malware=malware
    )



@dashboard_bp.route("/malware/delete/<int:malware_id>", methods=["POST"])
@analyst_required
def delete_malware(malware_id):
    malware = Malware.query.get_or_404(malware_id)
    malware_name = malware.malware_name
    try:
        _audit_log(current_user.id, f"delete_malware:{malware_name}", "malware_info", malware_id)
        db.session.delete(malware)
        db.session.commit()
        flash("Malware record deleted successfully.", "success")
    except Exception as e:
        db.session.rollback()
        flash(f"Error deleting malware: {str(e)}", "danger")

    return redirect(url_for("dashboard.malware_info"))



@dashboard_bp.route("/threat-reports")
@login_required
def threat_reports():

    reports = ThreatReport.query.order_by(
        ThreatReport.created_at.desc()
    ).all()

    return render_template(
        "threat-reports.html",
        reports=reports
    )


@dashboard_bp.route("/threat-report-upload", methods=["GET", "POST"])
@login_required
def threat_report_upload():

    if request.method == "POST":

        title = sanitize_text(request.form.get("title", "")).strip()
        description = sanitize_text(request.form.get("summary") or request.form.get("description") or "").strip()
        category = sanitize_text(request.form.get("category", "")).strip()
        severity = request.form.get("severity", "").strip()
        tlp_level = request.form.get("tlp_level", "").strip()
        target_sector = sanitize_text(request.form.get("sectors", "")).strip()

        if not title:
            flash("Report title is required.", "danger")
            return render_template("threat-report-upload.html")

        uploaded_file = request.files.get("report_file")
        filename = None

        if uploaded_file and uploaded_file.filename:
            is_valid_file, file_err = validate_file_upload(uploaded_file.filename)
            if not is_valid_file:
                flash(file_err, "danger")
                return render_template("threat-report-upload.html")

            filename = secure_filename(uploaded_file.filename)
            save_path = os.path.join(
                current_app.config["UPLOAD_FOLDER"],
                filename
            )
            try:
                uploaded_file.save(save_path)
            except Exception as e:
                flash(f"Failed to save attachment file: {str(e)}", "danger")
                return render_template("threat-report-upload.html")

        try:
            # 1. Create ThreatReport
            report = ThreatReport(
                user_id=current_user.id,
                title=title,
                description=description,
                category=category,
                severity=severity,
                tlp_level=tlp_level,
                target_sector=target_sector,
                attachment=filename
            )
            db.session.add(report)
            db.session.flush()

            # 2. Extract IOCs from report text (primarily description/summary content)
            text_to_extract = f"{description}\n{title}" if title else description
            iocs = extract_iocs(text_to_extract)

            # Map report severity to ThreatIndicator severity_enum ('Low', 'Medium', 'High', 'Critical')
            indicator_severity = (severity or "Medium").capitalize()
            if indicator_severity not in ("Low", "Medium", "High", "Critical"):
                indicator_severity = "Medium"

            # Map report tlp_level to ThreatIndicator tlp_enum ('RED', 'AMBER', 'GREEN', 'WHITE', 'CLEAR')
            indicator_tlp = (tlp_level or "WHITE").upper()
            if indicator_tlp not in ("RED", "AMBER", "GREEN", "WHITE", "CLEAR"):
                indicator_tlp = "WHITE"

            # 3. For each extracted IOC: find or create ThreatIndicator and link to report
            for ioc in iocs:
                existing_indicator = ThreatIndicator.query.filter(
                    func.lower(ThreatIndicator.indicator_value) == ioc["value"].lower()
                ).first()

                if existing_indicator:
                    indicator = existing_indicator
                    indicator.last_seen_at = datetime.utcnow()
                    indicator.updated_at = datetime.utcnow()
                    if indicator.status == "Expired":
                        indicator.status = "Active"
                        _audit_log(current_user.id, "ioc_auto_revive_report", "threat_indicators", indicator.id)
                else:
                    indicator = ThreatIndicator(
                        indicator_value=ioc["value"],
                        indicator_type=ioc["type"],
                        confidence_score=50,
                        severity=indicator_severity,
                        status="Active",
                        source="Threat Report",
                        first_seen_at=datetime.utcnow(),
                        last_seen_at=datetime.utcnow(),
                        added_by_user_id=current_user.id,
                        tlp_marking=indicator_tlp,
                        context=title
                    )
                    db.session.add(indicator)
                    db.session.flush()

                # Link indicator to current ThreatReport (prevent duplicate associations)
                if indicator not in report.indicators:
                    report.indicators.append(indicator)

            _audit_log(current_user.id, "upload_threat_report", "threat_reports", report.id)
            db.session.commit()

            flash(
                "Threat report uploaded successfully.",
                "success"
            )
            return redirect(url_for("dashboard.threat_reports"))


        except Exception as e:
            db.session.rollback()
            if filename:
                save_path = os.path.join(current_app.config["UPLOAD_FOLDER"], filename)
                if os.path.exists(save_path):
                    try:
                        os.remove(save_path)
                    except OSError:
                        pass
            flash(
                f"Error processing threat report: {str(e)}",
                "danger"
            )
            return render_template("threat-report-upload.html")

    return render_template("threat-report-upload.html")


@dashboard_bp.route("/threat-report/<int:report_id>")
@login_required
def view_report(report_id):

    report = ThreatReport.query.get_or_404(report_id)

    return render_template(
        "view-report.html",
        report=report
    )

@dashboard_bp.route("/threat-report/edit/<int:report_id>", methods=["GET", "POST"])
@login_required
def edit_report(report_id):

    report = ThreatReport.query.get_or_404(report_id)

    if request.method == "POST":

        report.title = request.form.get("title")
        report.description = request.form.get("summary")
        report.category = request.form.get("category")
        report.severity = request.form.get("severity")
        report.tlp_level = request.form.get("tlp_level")
        report.target_sector = request.form.get("sectors")
        report.status = request.form.get("status")

        uploaded_file = request.files.get("report_file")

        if uploaded_file and uploaded_file.filename:
            is_valid_file, file_err = validate_file_upload(uploaded_file.filename)
            if not is_valid_file:
                flash(file_err, "danger")
                return redirect(url_for("dashboard.edit_report", report_id=report.id))

            filename = secure_filename(uploaded_file.filename)

            save_path = os.path.join(
                current_app.config["UPLOAD_FOLDER"],
                filename
            )

            uploaded_file.save(save_path)

            report.attachment = filename

        db.session.commit()

        flash(
            "Threat Report updated successfully.",
            "success"
        )

        return redirect(
            url_for(
                "dashboard.view_report",
                report_id=report.id
            )
        )

    return render_template(
        "edit-report.html",
        report=report
    )


@dashboard_bp.route("/threat-report/delete/<int:report_id>", methods=["POST"])
@login_required
def delete_report(report_id):

    report = ThreatReport.query.get_or_404(report_id)

    try:

        # Delete attachment if it exists
        if report.attachment:

            file_path = os.path.join(
                current_app.config["UPLOAD_FOLDER"],
                report.attachment
            )

            if os.path.exists(file_path):

                os.remove(file_path)

        # Delete report from database
        db.session.delete(report)
        db.session.commit()

        flash(
            "Threat Report deleted successfully.",
            "success"
        )

    except Exception as e:

        db.session.rollback()

        flash(
            f"Error deleting report: {str(e)}",
            "danger"
        )

    return redirect(
        url_for("dashboard.threat_reports")
    )

@dashboard_bp.route("/threat-report/download/<int:report_id>")
@login_required
def download_attachment(report_id):

    report = ThreatReport.query.get_or_404(report_id)

    # Check if attachment exists in database
    if not report.attachment:

        flash(
            "No attachment is available for this report.",
            "warning"
        )

        return redirect(
            url_for(
                "dashboard.view_report",
                report_id=report.id
            )
        )

    upload_folder = current_app.config["UPLOAD_FOLDER"]

    file_path = os.path.join(
        upload_folder,
        report.attachment
    )

    # Check if file exists on disk
    if not os.path.exists(file_path):

        flash(
            "Attachment file not found on the server.",
            "danger"
        )

        return redirect(
            url_for(
                "dashboard.view_report",
                report_id=report.id
            )
        )

    return send_from_directory(
        upload_folder,
        report.attachment,
        as_attachment=True
    )


# from app.models import ThreatReport

@dashboard_bp.route("/search-threats", methods=["GET"])
@login_required
def search_threats():

    query = request.args.get("query", "").strip()

    if query:
        reports = ThreatReport.query.filter(
            or_(
                ThreatReport.title.ilike(f"%{query}%"),
                ThreatReport.description.ilike(f"%{query}%"),
                ThreatReport.category.ilike(f"%{query}%"),
                ThreatReport.severity.ilike(f"%{query}%"),
                ThreatReport.status.ilike(f"%{query}%"),
                ThreatReport.tlp_level.ilike(f"%{query}%"),
                ThreatReport.target_sector.ilike(f"%{query}%")
            )
        ).order_by(
            ThreatReport.created_at.desc()
        ).all()
    else:
        reports = ThreatReport.query.order_by(
            ThreatReport.created_at.desc()
        ).all()

    return render_template(
        "search-threats.html",
        reports=reports,
        query=query
    )


@dashboard_bp.route("/alerts", methods=["GET"])
@login_required
def alerts():
    query_text = request.args.get("query", "").strip()
    severity = request.args.get("severity", "all").strip()
    status = request.args.get("status", "all").strip()
    alert_type = request.args.get("alert_type", "all").strip()

    alert_list = get_alerts_filtered(
        query_text=query_text,
        severity=severity,
        status=status,
        alert_type=alert_type
    )
    counts = get_alert_counts()

    if request.headers.get("Accept") == "application/json" or request.args.get("format") == "json":
        return jsonify({
            "success": True,
            "total": len(alert_list),
            "counts": counts,
            "alerts": [
                {
                    "id": a.id,
                    "title": a.title,
                    "description": a.description,
                    "severity": a.severity,
                    "status": a.status,
                    "alert_type": a.alert_type,
                    "is_read": a.is_read,
                    "indicator_id": a.indicator_id,
                    "indicator_value": a.indicator.indicator_value if a.indicator else None,
                    "malware_id": a.malware_id,
                    "created_at": a.created_at.strftime("%Y-%m-%d %H:%M:%S") if a.created_at else None,
                }
                for a in alert_list
            ]
        })

    return render_template(
        "alerts.html",
        alerts=alert_list,
        counts=counts,
        query=query_text,
        current_severity=severity,
        current_status=status,
        current_type=alert_type
    )


@dashboard_bp.route("/alert/<int:alert_id>", methods=["GET"])
@login_required
def alert_details(alert_id):
    alert = Alert.query.get_or_404(alert_id)
    if not alert.is_read:
        mark_alert_read(alert.id, current_user)

    indicator_risk = None
    if alert.indicator_id:
        try:
            indicator_risk = calculate_indicator_risk_by_id(alert.indicator_id)
        except Exception:
            pass

    if request.headers.get("Accept") == "application/json" or request.args.get("format") == "json":
        return jsonify({
            "success": True,
            "alert": {
                "id": alert.id,
                "title": alert.title,
                "description": alert.description,
                "severity": alert.severity,
                "status": alert.status,
                "alert_type": alert.alert_type,
                "is_read": alert.is_read,
                "indicator_id": alert.indicator_id,
                "indicator_value": alert.indicator.indicator_value if alert.indicator else None,
                "malware_id": alert.malware_id,
                "malware_name": alert.malware.malware_name if alert.malware else None,
                "created_at": alert.created_at.strftime("%Y-%m-%d %H:%M:%S") if alert.created_at else None,
                "updated_at": alert.updated_at.strftime("%Y-%m-%d %H:%M:%S") if alert.updated_at else None,
            },
            "indicator_risk": indicator_risk
        })

    return render_template(
        "alert-details.html",
        alert=alert,
        indicator_risk=indicator_risk
    )


@dashboard_bp.route("/alert/<int:alert_id>/read", methods=["POST"])
@login_required
def alert_mark_read_route(alert_id):
    alert = Alert.query.get_or_404(alert_id)
    mark_alert_read(alert.id, current_user)
    if request.is_json or request.headers.get("X-Requested-With") == "XMLHttpRequest":
        return jsonify({"success": True, "alert_id": alert.id, "is_read": True})
    flash("Alert marked as read.", "info")
    return redirect(request.referrer or url_for("dashboard.alerts"))


@dashboard_bp.route("/alert/<int:alert_id>/acknowledge", methods=["POST"])
@login_required
def alert_acknowledge_route(alert_id):
    alert = Alert.query.get_or_404(alert_id)
    try:
        acknowledge_alert(alert.id, current_user)
        if request.is_json or request.headers.get("X-Requested-With") == "XMLHttpRequest":
            return jsonify({"success": True, "alert_id": alert.id, "status": alert.status})
        flash(f"Alert #{alert.id} acknowledged (In Progress).", "success")
    except ValueError as e:
        if request.is_json or request.headers.get("X-Requested-With") == "XMLHttpRequest":
            return jsonify({"success": False, "error": str(e)}), 400
        flash(str(e), "warning")
    return redirect(request.referrer or url_for("dashboard.alerts"))


@dashboard_bp.route("/alert/<int:alert_id>/resolve", methods=["POST"])
@login_required
def alert_resolve_route(alert_id):
    alert = Alert.query.get_or_404(alert_id)
    try:
        resolve_alert(alert.id, current_user)
        if request.is_json or request.headers.get("X-Requested-With") == "XMLHttpRequest":
            return jsonify({"success": True, "alert_id": alert.id, "status": alert.status})
        flash(f"Alert #{alert.id} marked as Resolved.", "success")
    except ValueError as e:
        if request.is_json or request.headers.get("X-Requested-With") == "XMLHttpRequest":
            return jsonify({"success": False, "error": str(e)}), 400
        flash(str(e), "warning")
    return redirect(request.referrer or url_for("dashboard.alerts"))


@dashboard_bp.route("/alert/<int:alert_id>/reopen", methods=["POST"])
@login_required
def alert_reopen_route(alert_id):
    alert = Alert.query.get_or_404(alert_id)
    try:
        reopen_alert(alert.id, current_user)
        if request.is_json or request.headers.get("X-Requested-With") == "XMLHttpRequest":
            return jsonify({"success": True, "alert_id": alert.id, "status": alert.status})
        flash(f"Alert #{alert.id} reopened.", "info")
    except ValueError as e:
        if request.is_json or request.headers.get("X-Requested-With") == "XMLHttpRequest":
            return jsonify({"success": False, "error": str(e)}), 400
        flash(str(e), "warning")
    return redirect(request.referrer or url_for("dashboard.alerts"))


@dashboard_bp.route("/profile", methods=["GET", "POST"])
@login_required
def profile():
    from app.services.mfa_service import (
        init_mfa_setup,
        confirm_and_enable_mfa,
        disable_mfa_for_user,
        count_remaining_backup_codes,
    )
    from app.services.api_key_service import (
        generate_user_api_key,
        revoke_user_api_key,
        get_user_api_key_info,
    )
    from flask import session as _sess

    mfa_setup_data = None

    if request.method == "POST":
        action = request.form.get("action", "").strip()

        if action == "change_password":
            current_password = request.form.get("current_password", "")
            new_password = request.form.get("new_password", "")
            confirm_password = request.form.get("confirm_password", "")

            # 1. Require current password
            if not current_password:
                flash("Current password is required.", "danger")
                return redirect(url_for("dashboard.profile"))

            # 2. Verify current password
            if not check_password_hash(current_user.password_hash, current_password):
                flash("Current password is incorrect.", "danger")
                return redirect(url_for("dashboard.profile"))

            # 3. Require new password
            if not new_password:
                flash("New password is required.", "danger")
                return redirect(url_for("dashboard.profile"))

            # 4. Verify password confirmation
            if new_password != confirm_password:
                flash("New password and confirmation do not match.", "danger")
                return redirect(url_for("dashboard.profile"))

            # 5. Prevent reusing existing password
            if current_password == new_password:
                flash("New password cannot be the same as your current password.", "warning")
                return redirect(url_for("dashboard.profile"))

            # 6. Validate password complexity against platform policy
            is_valid_pw, pw_err = validate_password_complexity(new_password)
            if not is_valid_pw:
                flash(pw_err, "danger")
                return redirect(url_for("dashboard.profile"))

            # 7. Securely update password hash
            current_user.password_hash = generate_password_hash(new_password)
            # G-6: Rotate session token to invalidate other devices, update current session
            import secrets
            fresh_token = secrets.token_hex(16)
            current_user.session_token = fresh_token
            _sess["_session_token"] = fresh_token

            # 8. Record audit log without sensitive secrets
            _audit_log(
                user_id=current_user.id,
                action="self_service_password_change",
                target_table="users",
                target_id=current_user.id,
            )

            try:
                db.session.commit()
                flash("Your password has been successfully updated.", "success")
            except Exception as exc:
                db.session.rollback()
                flash("A database error occurred while updating your password.", "danger")

            return redirect(url_for("dashboard.profile"))

        elif action == "update_contact":
            # Profile cannot modify role, account status, or other privileged fields (G-2 Rule 5)
            flash("Corporate directory details are managed via Enterprise IdP.", "info")
            return redirect(url_for("dashboard.profile"))

        # ── Phase 3: MFA / TOTP Setup & Enrollment ────────────────────
        elif action == "setup_mfa":
            ok, msg, setup_data = init_mfa_setup(current_user.id)
            if ok and setup_data:
                _sess["mfa_setup_secret"] = setup_data["secret"]
                _sess["mfa_setup_backup_codes"] = setup_data["backup_codes"]
                mfa_setup_data = setup_data
            else:
                flash(msg, "danger")

        elif action == "enable_mfa":
            secret = _sess.get("mfa_setup_secret")
            backup_codes = _sess.get("mfa_setup_backup_codes")
            code = request.form.get("totp_code", "").strip()

            if not secret or not backup_codes:
                flash("MFA setup session has expired. Please initiate setup again.", "warning")
                return redirect(url_for("dashboard.profile"))

            ok, msg = confirm_and_enable_mfa(current_user.id, secret, code, backup_codes)
            if ok:
                _sess.pop("mfa_setup_secret", None)
                _sess.pop("mfa_setup_backup_codes", None)
                flash(f"{msg} Save your emergency recovery backup codes in a safe place.", "success")
                return redirect(url_for("dashboard.profile"))
            else:
                flash(msg, "danger")
                from app.services.mfa_service import get_totp_uri, generate_qr_code_svg
                uri = get_totp_uri(secret, current_user.username, current_user.email)
                qr_svg = generate_qr_code_svg(uri)
                mfa_setup_data = {
                    "secret": secret,
                    "uri": uri,
                    "qr_svg": qr_svg,
                    "backup_codes": backup_codes,
                }

        elif action == "cancel_mfa_setup":
            _sess.pop("mfa_setup_secret", None)
            _sess.pop("mfa_setup_backup_codes", None)
            flash("MFA enrollment setup cancelled.", "info")
            return redirect(url_for("dashboard.profile"))

        elif action == "disable_mfa":
            current_password = request.form.get("current_password", "")
            ok, msg = disable_mfa_for_user(current_user.id, current_password=current_password)
            flash(msg, "success" if ok else "danger")
            return redirect(url_for("dashboard.profile"))

        # ── Phase 3: User API Key Generation & Revocation ─────────────
        elif action == "generate_api_key":
            label = request.form.get("api_key_label", "Personal API Key")
            ok, msg, raw_token = generate_user_api_key(current_user.id, label=label)
            if ok and raw_token:
                _sess["newly_generated_api_key"] = raw_token
                flash(msg, "success")
            else:
                flash(msg, "danger")
            return redirect(url_for("dashboard.profile"))

        elif action == "revoke_api_key":
            ok, msg = revoke_user_api_key(current_user.id)
            flash(msg, "success" if ok else "danger")
            return redirect(url_for("dashboard.profile"))

        else:
            flash("Invalid action requested.", "warning")
            return redirect(url_for("dashboard.profile"))

    # GET
    api_key_info = get_user_api_key_info(current_user.id)
    remaining_backup_codes = count_remaining_backup_codes(current_user)
    newly_generated_api_key = _sess.pop("newly_generated_api_key", None)

    return render_template(
        "profile.html",
        api_key_info=api_key_info,
        remaining_backup_codes=remaining_backup_codes,
        newly_generated_api_key=newly_generated_api_key,
        mfa_setup=mfa_setup_data,
    )


@dashboard_bp.route("/threat-indicator/<int:indicator_id>/enrich", methods=["POST"])
@login_required
def enrich_indicator_route(indicator_id):
    indicator = ThreatIndicator.query.get_or_404(indicator_id)
    result = enrich_indicator(indicator)
    return jsonify(result)


@dashboard_bp.route("/threat-indicator/<int:indicator_id>/correlations", methods=["GET"])
@login_required
def indicator_correlations_route(indicator_id):
    indicator = ThreatIndicator.query.get_or_404(indicator_id)
    result = correlate_indicator_by_id(indicator.id)
    return jsonify(result)


@dashboard_bp.route("/threat-indicator/<int:indicator_id>/risk-score", methods=["GET", "POST"])
@login_required
def indicator_risk_score_route(indicator_id):
    indicator = ThreatIndicator.query.get_or_404(indicator_id)
    if request.method == "POST":
        result = save_indicator_risk(indicator.id)
    else:
        result = calculate_indicator_risk_by_id(indicator.id)
    return jsonify(result)


@dashboard_bp.route("/threat-news", methods=["GET"])
@login_required
def threat_news():
    query_text = request.args.get("query", "").strip()
    category = request.args.get("category", "all").strip()
    source = request.args.get("source", "all").strip()
    severity = request.args.get("severity", "all").strip()
    page = request.args.get("page", 1, type=int)

    pagination = get_threat_news_filtered(
        query_text=query_text,
        category=category,
        source=source,
        severity=severity,
        page=page,
        per_page=12,
    )
    stats = get_news_stats()

    if request.is_json or request.args.get("format") == "json" or request.headers.get("Accept") == "application/json":
        return jsonify({
            "success": True,
            "total": pagination.total,
            "page": pagination.page,
            "pages": pagination.pages,
            "stats": stats,
            "articles": [
                {
                    "id": a.id,
                    "title": a.title,
                    "source": a.source,
                    "source_url": a.source_url,
                    "summary": a.summary,
                    "category": a.category,
                    "severity": a.severity,
                    "published_at": a.published_at.strftime("%Y-%m-%d %H:%M:%S") if a.published_at else None,
                    "created_at": a.created_at.strftime("%Y-%m-%d %H:%M:%S") if a.created_at else None,
                }
                for a in pagination.items
            ],
        })

    return render_template(
        "threat-news.html",
        articles=pagination.items,
        pagination=pagination,
        stats=stats,
        query=query_text,
        current_category=category,
        current_source=source,
        current_severity=severity,
        categories=stats.get("categories", []),
        sources=stats.get("sources", []),
    )


@dashboard_bp.route("/threat-news/refresh", methods=["POST"])
@login_required
def refresh_threat_news():
    # Only admin and analyst can refresh news
    if current_user.role not in ("admin", "analyst"):
        msg = "Unauthorized: Admin or Analyst privileges are required to refresh threat news."
        if request.is_json or request.headers.get("X-Requested-With") == "XMLHttpRequest":
            return jsonify({"success": False, "error": msg}), 403
        flash(msg, "danger")
        return redirect(url_for("dashboard.threat_news"))

    try:
        result = fetch_and_store_threat_news()
        new_count = result.get("new_articles", 0)
        skipped_count = result.get("skipped_duplicates", 0)
        errors = result.get("errors", [])

        if request.is_json or request.headers.get("X-Requested-With") == "XMLHttpRequest":
            return jsonify({
                "success": True,
                "result": result,
                "message": f"Threat news refresh completed: {new_count} new articles imported, {skipped_count} duplicates skipped."
            })

        flash(
            f"Threat news updated: {new_count} new articles imported, {skipped_count} existing duplicates skipped.",
            "success"
        )
        if errors:
            failed_sources = ", ".join(e["source"] for e in errors)
            flash(f"Note: Some sources could not be reached ({failed_sources}). Check network or feed status.", "warning")

    except Exception as e:
        err_msg = f"Failed to refresh threat news: {str(e)}"
        if request.is_json or request.headers.get("X-Requested-With") == "XMLHttpRequest":
            return jsonify({"success": False, "error": err_msg}), 500
        flash(err_msg, "danger")

    return redirect(url_for("dashboard.threat_news"))


@dashboard_bp.route("/threat-news/<int:news_id>/extract-iocs", methods=["POST"])
@login_required
def extract_news_iocs_route(news_id):
    if current_user.role not in ("admin", "analyst"):
        return jsonify({"success": False, "error": "Unauthorized: Analyst privileges required."}), 403

    result = extract_news_iocs(news_id, current_user.id)
    return jsonify(result)


@dashboard_bp.route("/siem-edr-integration", methods=["GET"])
@login_required
def siem_edr_integration():
    """Renders the SIEM & EDR Integration Portal and Webhook Guide."""
    if current_user.role not in ("admin", "analyst"):
        abort(403)

    raw_key = current_app.config.get("SIEM_WEBHOOK_API_KEY", "")
    if current_user.role == "admin" and raw_key and raw_key != "tip-siem-edr-default-secret-key-2026":
        masked_key = f"{raw_key[:8]}••••••••{raw_key[-4:]}" if len(raw_key) > 12 else "••••••••"
    elif current_user.role == "admin":
        masked_key = "DEFAULT_OR_UNSET"
    else:
        masked_key = current_user.masked_api_key or "NO_PERSONAL_KEY_PROVISIONED"

    host_url = request.host_url.rstrip("/")
    return render_template(
        "siem-edr-integration.html",
        api_key=masked_key,
        host_url=host_url,
        has_personal_key=bool(current_user.api_key),
    )


@dashboard_bp.route("/mitre-matrix", methods=["GET"])
@login_required
def mitre_matrix():
    """Renders the Enterprise MITRE ATT&CK Matrix Explorer & Heatmap Navigator."""
    from app.services.mitre_service import MITRE_TECHNIQUES

    coverage = get_mitre_matrix_coverage()

    def get_catalog_techniques_for_tactic(tactic_id):
        return [
            (tid, tech) for tid, tech in MITRE_TECHNIQUES.items()
            if tactic_id in tech.get("tactics", [])
        ]

    def is_technique_in_list(tech_id, tech_list):
        return any(t.get("id") == tech_id for t in tech_list)

    return render_template(
        "mitre-matrix.html",
        coverage=coverage,
        tactics=coverage["tactics"],
        summary=coverage["summary"],
        get_catalog_techniques_for_tactic=get_catalog_techniques_for_tactic,
        is_technique_in_list=is_technique_in_list,
    )



