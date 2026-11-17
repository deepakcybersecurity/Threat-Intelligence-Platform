"""
Admin Blueprint Routes — Task 8: Admin / RBAC & Remediation G-5, G-7, G-8, G-10
Enforces: @login_required + admin-only role check on every route.
"""

from datetime import datetime
from functools import wraps
from flask import render_template, request, redirect, url_for, flash, abort, Response
from flask_login import login_required, current_user

from . import admin_bp
from app import db
from app.services.admin_service import (
    get_all_users,
    update_user_role,
    suspend_user,
    activate_user,
    delete_user,
    provision_user,
    reset_user_password,
    generate_password_reset_token,
    unlock_user,
    revoke_user_sessions,
    get_analyst_activity_metrics,
    bulk_suspend_users,
    bulk_activate_users,
    bulk_update_user_roles,
    bulk_revoke_user_sessions,
)
from app.services.audit_service import (
    get_recent_audit_logs,
    filter_audit_logs,
    export_audit_logs_csv_data,
    get_audit_tables_and_actions,
    log_action,
)
from app.services.security_service import sanitize_text


# ---------------------------------------------------------------------------
# RBAC decorator: admin-only
# ---------------------------------------------------------------------------

def admin_required(f):
    """Decorator: user must be logged in AND have role == 'admin'."""
    @wraps(f)
    @login_required
    def decorated(*args, **kwargs):
        if current_user.role != "admin":
            abort(403)
        return f(*args, **kwargs)
    return decorated


# ---------------------------------------------------------------------------
# Admin Panel — GET + POST
# ---------------------------------------------------------------------------

@admin_bp.route("/admin", methods=["GET", "POST"])
@admin_required
def admin():
    """
    GET  : Render admin panel with real users, audit logs, and analyst metrics.
    POST : Handle user management actions (single & bulk actions).
    """
    if request.method == "POST":
        action = request.form.get("action", "").strip()

        # ── Role Update ──────────────────────────────────────────────
        if action == "update_role":
            user_id = request.form.get("user_id", type=int)
            new_role = request.form.get("new_role", "").strip()
            ok, msg = update_user_role(current_user.id, user_id, new_role)
            flash(msg, "success" if ok else "danger")

        # ── Suspend User ─────────────────────────────────────────────
        elif action == "suspend":
            user_id = request.form.get("user_id", type=int)
            ok, msg = suspend_user(current_user.id, user_id)
            flash(msg, "success" if ok else "danger")

        # ── Activate User ────────────────────────────────────────────
        elif action == "activate":
            user_id = request.form.get("user_id", type=int)
            ok, msg = activate_user(current_user.id, user_id)
            flash(msg, "success" if ok else "danger")

        # ── Delete User ──────────────────────────────────────────────
        elif action == "delete":
            user_id = request.form.get("user_id", type=int)
            ok, msg = delete_user(current_user.id, user_id)
            flash(msg, "success" if ok else "danger")

        # ── Provision New User ───────────────────────────────────────
        elif action == "provision":
            username = sanitize_text(request.form.get("username", "")).strip()
            email = request.form.get("email", "").strip()
            password = request.form.get("password", "")
            role = request.form.get("role", "user").strip()
            ok, msg = provision_user(current_user.id, username, email, password, role)
            flash(msg, "success" if ok else "danger")

        # ── Reset User Password (Admin-Initiated G-1) ────────────────
        elif action == "reset_password":
            user_id = request.form.get("user_id", type=int)
            new_password = request.form.get("new_password", "").strip() or None
            ok, msg, _ = reset_user_password(current_user.id, user_id, new_password)
            flash(msg, "success" if ok else "danger")

        # ── Generate One-Time Password Reset Link (G-1) ──────────────
        elif action == "generate_reset_token":
            user_id = request.form.get("user_id", type=int)
            ok, msg, token = generate_password_reset_token(current_user.id, user_id)
            if ok and token:
                reset_url = url_for("auth.reset_password_token", token=token, _external=True)
                flash(f"{msg} Reset Link: {reset_url}", "success")
            else:
                flash(msg, "danger")

        # ── Unlock User Account (G-4) ────────────────────────────────
        elif action == "unlock_user":
            user_id = request.form.get("user_id", type=int)
            ok, msg = unlock_user(current_user.id, user_id)
            flash(msg, "success" if ok else "danger")

        # ── Revoke User Active Sessions (G-6) ────────────────────────
        elif action == "revoke_sessions":
            user_id = request.form.get("user_id", type=int)
            ok, msg = revoke_user_sessions(current_user.id, user_id)
            flash(msg, "success" if ok else "danger")

        # ── Reset / Disable User MFA (Phase 3) ───────────────────────
        elif action == "reset_mfa":
            user_id = request.form.get("user_id", type=int)
            from app.services.mfa_service import disable_mfa_for_user
            ok, msg = disable_mfa_for_user(user_id, is_admin_override=True, actor_id=current_user.id)
            flash(msg, "success" if ok else "danger")

        # ── Bulk User Actions (G-10) ────────────────────────────────
        elif action == "bulk_action":
            bulk_type = request.form.get("bulk_type", "").strip()
            user_ids = request.form.getlist("selected_user_ids", type=int)
            if not user_ids:
                flash("No users selected for bulk action.", "warning")
            elif bulk_type == "bulk_suspend":
                ok, msg, _ = bulk_suspend_users(current_user.id, user_ids)
                flash(msg, "success" if ok else "danger")
            elif bulk_type == "bulk_activate":
                ok, msg, _ = bulk_activate_users(current_user.id, user_ids)
                flash(msg, "success" if ok else "danger")
            elif bulk_type == "bulk_change_role":
                new_role = request.form.get("bulk_role", "").strip()
                ok, msg, _ = bulk_update_user_roles(current_user.id, user_ids, new_role)
                flash(msg, "success" if ok else "danger")
            elif bulk_type == "bulk_revoke_sessions":
                ok, msg, _ = bulk_revoke_user_sessions(current_user.id, user_ids)
                flash(msg, "success" if ok else "danger")
            else:
                flash(f"Unknown bulk action: {bulk_type}", "warning")

        else:
            flash(f"Unknown action: {action}", "warning")

        return redirect(url_for("admin.admin"))

    # ── GET: Audit Log Filtering, Pagination, and Analyst Metrics ────
    audit_q = request.args.get("q", "").strip() or None
    audit_user_id = request.args.get("user_id", type=int)
    audit_action = request.args.get("action_filter", "").strip() or None
    audit_target_table = request.args.get("target_table", "").strip() or None
    audit_date_from = request.args.get("date_from", "").strip() or None
    audit_date_to = request.args.get("date_to", "").strip() or None
    audit_page = request.args.get("page", 1, type=int)
    audit_per_page = request.args.get("per_page", 25, type=int)

    # G-5: Filtered and Paginated Audit Logs
    audit_pagination = filter_audit_logs(
        q=audit_q,
        user_id=audit_user_id,
        action=audit_action,
        target_table=audit_target_table,
        date_from=audit_date_from,
        date_to=audit_date_to,
        page=audit_page,
        per_page=audit_per_page,
    )

    # G-8: Analyst Activity & Contribution Metrics
    analyst_metrics = get_analyst_activity_metrics()

    users = get_all_users()
    audit_tables, audit_actions = get_audit_tables_and_actions()

    return render_template(
        "admin-panel.html",
        users=users,
        audit_logs=audit_pagination["items"],
        audit_pagination=audit_pagination,
        analyst_metrics=analyst_metrics,
        audit_tables=audit_tables,
        audit_actions=audit_actions,
    )


# ---------------------------------------------------------------------------
# G-7: Audit Log CSV Export Endpoint
# ---------------------------------------------------------------------------

@admin_bp.route("/admin/audit-logs/export-csv", methods=["GET"])
@admin_bp.route("/admin/export-audit-csv", methods=["GET"])
@admin_required
def export_audit_logs_csv():
    """
    Export audit trail logs as RFC 4180 CSV attachment (G-7).
    Respects active search, user, action, target table, and date range filters.
    """
    audit_q = request.args.get("q", "").strip() or None
    audit_user_id = request.args.get("user_id", type=int)
    audit_action = request.args.get("action_filter", "").strip() or None
    audit_target_table = request.args.get("target_table", "").strip() or None
    audit_date_from = request.args.get("date_from", "").strip() or None
    audit_date_to = request.args.get("date_to", "").strip() or None

    csv_data = export_audit_logs_csv_data(
        q=audit_q,
        user_id=audit_user_id,
        action=audit_action,
        target_table=audit_target_table,
        date_from=audit_date_from,
        date_to=audit_date_to,
    )

    # Record compliance export event in audit log
    log_action(
        user_id=current_user.id,
        action="export_audit_logs_csv",
        target_table="audit_logs",
    )
    try:
        db.session.commit()
    except Exception:
        db.session.rollback()

    filename = f"audit_logs_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.csv"
    return Response(
        csv_data,
        mimetype="text/csv",
        headers={
            "Content-Disposition": f'attachment; filename="{filename}"',
            "Cache-Control": "no-cache, no-store, must-revalidate",
        },
    )
