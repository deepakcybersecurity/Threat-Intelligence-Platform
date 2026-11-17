"""
Admin Service — Task 8: Admin / RBAC
Handles user provisioning, role updates, suspend/activate, and deletion.
All write functions log to the audit trail automatically.
"""

import logging
from typing import Any
from werkzeug.security import generate_password_hash
from app import db
from app.models.user import User
from app.models.threat_indicator import ThreatIndicator
from app.models.threat_report import ThreatReport
from app.models.malware import Malware
from app.models.alert import Alert
from app.models.audit_log import AuditLog
from app.services.audit_service import log_action
from app.services.security_service import validate_password_complexity
import secrets
import string
from flask import current_app
from itsdangerous import URLSafeTimedSerializer, SignatureExpired, BadSignature

logger = logging.getLogger(__name__)

VALID_ROLES = ("admin", "analyst", "user")


# ---------------------------------------------------------------------------
# Read helpers
# ---------------------------------------------------------------------------

def get_all_users() -> list[User]:
    """Return all users ordered by ID."""
    return User.query.order_by(User.id).all()


def get_user_by_id(user_id: int) -> User | None:
    return db.session.get(User, user_id)


# ---------------------------------------------------------------------------
# Write operations (each logs to audit trail)
# ---------------------------------------------------------------------------

def update_user_role(actor_id: int, target_user_id: int, new_role: str) -> tuple[bool, str]:
    """
    Change a user's role.
    Returns (success: bool, message: str).
    """
    if new_role not in VALID_ROLES:
        return False, f"Invalid role '{new_role}'. Must be one of: {VALID_ROLES}"

    user = get_user_by_id(target_user_id)
    if not user:
        return False, f"User {target_user_id} not found."

    old_role = user.role
    user.role = new_role
    log_action(
        user_id=actor_id,
        action=f"update_role:{old_role}->{new_role}",
        target_table="users",
        target_id=target_user_id,
    )
    try:
        db.session.commit()
        return True, f"Role updated to '{new_role}' for user {user.username}."
    except Exception as exc:
        db.session.rollback()
        logger.error("update_user_role failed: %s", exc, exc_info=True)
        return False, "Database error while updating role."


def suspend_user(actor_id: int, target_user_id: int) -> tuple[bool, str]:
    """Deactivate a user account."""
    user = get_user_by_id(target_user_id)
    if not user:
        return False, f"User {target_user_id} not found."

    if actor_id == target_user_id:
        return False, "You cannot suspend your own account."

    user.is_active = False
    # G-6: Rotate session token to immediately terminate all active sessions for suspended user
    user.session_token = secrets.token_hex(16)
    log_action(
        user_id=actor_id,
        action="suspend_user",
        target_table="users",
        target_id=target_user_id,
    )
    try:
        db.session.commit()
        return True, f"User {user.username} suspended."
    except Exception as exc:
        db.session.rollback()
        logger.error("suspend_user failed: %s", exc, exc_info=True)
        return False, "Database error while suspending user."


def activate_user(actor_id: int, target_user_id: int) -> tuple[bool, str]:
    """Re-activate a suspended user account."""
    user = get_user_by_id(target_user_id)
    if not user:
        return False, f"User {target_user_id} not found."

    user.is_active = True
    # G-4: Clear any lockout state upon activation
    user.failed_login_count = 0
    user.locked_until = None
    log_action(
        user_id=actor_id,
        action="activate_user",
        target_table="users",
        target_id=target_user_id,
    )
    try:
        db.session.commit()
        return True, f"User {user.username} re-activated."
    except Exception as exc:
        db.session.rollback()
        logger.error("activate_user failed: %s", exc, exc_info=True)
        return False, "Database error while activating user."


def delete_user(actor_id: int, target_user_id: int) -> tuple[bool, str]:
    """
    Delete a user. Refuses to delete self or last admin.
    """
    if actor_id == target_user_id:
        return False, "You cannot delete your own account."

    user = get_user_by_id(target_user_id)
    if not user:
        return False, f"User {target_user_id} not found."

    # Guard: don't remove the last admin
    if user.role == "admin":
        admin_count = User.query.filter_by(role="admin").count()
        if admin_count <= 1:
            return False, "Cannot delete the last admin account."

    log_action(
        user_id=actor_id,
        action=f"delete_user:{user.username}",
        target_table="users",
        target_id=target_user_id,
    )
    try:
        db.session.delete(user)
        db.session.commit()
        return True, f"User {user.username} deleted."
    except Exception as exc:
        db.session.rollback()
        logger.error("delete_user failed: %s", exc, exc_info=True)
        return False, "Database error while deleting user."


def provision_user(
    actor_id: int,
    username: str,
    email: str,
    password: str,
    role: str = "user",
) -> tuple[bool, str]:
    """
    Create a new user account (admin provisioning path).
    Returns (success, message).
    """
    if role not in VALID_ROLES:
        return False, f"Invalid role '{role}'."

    username = username.strip()
    email = email.strip().lower()

    if not username or not email or not password:
        return False, "Username, email, and password are required."

    if User.query.filter_by(username=username).first():
        return False, f"Username '{username}' already exists."

    if User.query.filter_by(email=email).first():
        return False, f"Email '{email}' already registered."

    is_valid_pw, pw_err = validate_password_complexity(password)
    if not is_valid_pw:
        return False, pw_err

    new_user = User(
        username=username,
        email=email,
        password_hash=generate_password_hash(password),
        role=role,
        is_active=True,
    )
    db.session.add(new_user)
    db.session.flush()  # assign new_user.id before logging

    log_action(
        user_id=actor_id,
        action=f"provision_user:{role}",
        target_table="users",
        target_id=new_user.id,
    )
    try:
        db.session.commit()
        return True, f"User '{username}' created with role '{role}'."
    except Exception as exc:
        db.session.rollback()
        logger.error("provision_user failed: %s", exc, exc_info=True)
        return False, "Database error while creating user."


# ---------------------------------------------------------------------------
# G-1: Administrator-Initiated Password Reset & Reset Token Workflows
# ---------------------------------------------------------------------------

def generate_temporary_password(length: int = 16) -> str:
    """Generate a cryptographically secure temporary password meeting complexity requirements."""
    specials = "!@#$%=+?*~_-"
    pwd = [
        secrets.choice(string.ascii_uppercase),
        secrets.choice(string.ascii_lowercase),
        secrets.choice(string.digits),
        secrets.choice(specials),
    ]
    charset = string.ascii_letters + string.digits + specials
    pwd += [secrets.choice(charset) for _ in range(max(length - 4, 8))]
    secrets.SystemRandom().shuffle(pwd)
    return "".join(pwd)


def reset_user_password(
    actor_id: int,
    target_user_id: int,
    new_password: str | None = None,
) -> tuple[bool, str, str | None]:
    """
    Admin-initiated password reset for a target user account.
    Returns (success: bool, message: str, temporary_password: str | None).
    Never logs or exposes plaintext passwords in audit trails.
    """
    actor = get_user_by_id(actor_id)
    if not actor or actor.role != "admin":
        return False, "Unauthorized: Admin privileges required to reset passwords.", None

    target_user = get_user_by_id(target_user_id)
    if not target_user:
        return False, f"User {target_user_id} not found.", None

    temp_password = None
    if new_password and new_password.strip():
        pwd_to_set = new_password.strip()
        is_valid_pw, pw_err = validate_password_complexity(pwd_to_set)
        if not is_valid_pw:
            return False, pw_err, None
    else:
        temp_password = generate_temporary_password(16)
        pwd_to_set = temp_password

    # Update hash
    target_user.password_hash = generate_password_hash(pwd_to_set)
    # G-4: Clear any lockout state upon password reset
    target_user.failed_login_count = 0
    target_user.locked_until = None
    # G-6: Rotate session token to immediately terminate existing sessions
    target_user.session_token = secrets.token_hex(16)

    # Log action to audit trail without recording secrets
    log_action(
        user_id=actor_id,
        action=f"admin_reset_password:{target_user.username}",
        target_table="users",
        target_id=target_user.id,
    )

    try:
        db.session.commit()
        if temp_password:
            return True, f"Password reset for '{target_user.username}'. Temporary password: {temp_password}", temp_password
        return True, f"Password successfully reset for '{target_user.username}'.", None
    except Exception as exc:
        db.session.rollback()
        logger.error("reset_user_password failed: %s", exc, exc_info=True)
        return False, "Database error while resetting password.", None


def generate_password_reset_token(
    actor_id: int,
    target_user_id: int,
    max_age: int = 3600,
) -> tuple[bool, str, str | None]:
    """
    Generate a cryptographically signed reset token for a user.
    Token is signed with current_app.config['SECRET_KEY'] and includes a hash-fingerprint
    so that once the password changes, the token is automatically invalidated.
    """
    actor = get_user_by_id(actor_id)
    if not actor or actor.role != "admin":
        return False, "Unauthorized: Admin privileges required.", None

    target_user = get_user_by_id(target_user_id)
    if not target_user:
        return False, f"User {target_user_id} not found.", None

    s = URLSafeTimedSerializer(current_app.config["SECRET_KEY"])
    fingerprint = target_user.password_hash[-10:]
    token = s.dumps({"user_id": target_user.id, "fp": fingerprint}, salt="pwd-reset-salt")

    log_action(
        user_id=actor_id,
        action=f"generate_reset_token:{target_user.username}",
        target_table="users",
        target_id=target_user.id,
    )
    try:
        db.session.commit()
        return True, f"Password reset token generated for '{target_user.username}'.", token
    except Exception as exc:
        db.session.rollback()
        logger.error("generate_password_reset_token failed: %s", exc, exc_info=True)
        return False, "Database error while logging token generation.", None


def reset_password_with_token(token: str, new_password: str) -> tuple[bool, str]:
    """
    Consume a signed reset token and update password.
    """
    s = URLSafeTimedSerializer(current_app.config["SECRET_KEY"])
    try:
        data = s.loads(token, salt="pwd-reset-salt", max_age=3600)
    except SignatureExpired:
        return False, "The password reset link has expired. Please request a new one."
    except (BadSignature, Exception):
        return False, "Invalid or corrupted password reset link."

    user_id = data.get("user_id")
    expected_fp = data.get("fp")
    user = get_user_by_id(user_id)
    if not user:
        return False, "User account no longer exists."

    # Invalidate if password has already been changed since token was issued
    if user.password_hash[-10:] != expected_fp:
        return False, "This password reset link has already been used."

    is_valid_pw, pw_err = validate_password_complexity(new_password)
    if not is_valid_pw:
        return False, pw_err

    user.password_hash = generate_password_hash(new_password)
    # G-4: Clear lockout state on successful token reset
    user.failed_login_count = 0
    user.locked_until = None
    # G-6: Rotate session token to immediately terminate existing sessions
    user.session_token = secrets.token_hex(16)
    log_action(
        user_id=user.id,
        action=f"token_reset_password:{user.username}",
        target_table="users",
        target_id=user.id,
    )
    try:
        db.session.commit()
        return True, "Your password has been successfully reset. Please log in with your new password."
    except Exception as exc:
        db.session.rollback()
        logger.error("reset_password_with_token failed: %s", exc, exc_info=True)
        return False, "Database error while resetting password."


# ---------------------------------------------------------------------------
# G-4: Unlock User & G-6: Revoke User Sessions Workflows
# ---------------------------------------------------------------------------

def unlock_user(actor_id: int, target_user_id: int) -> tuple[bool, str]:
    """
    Admin-initiated manual unlock for a locked user account.
    Returns (success: bool, message: str).
    """
    actor = get_user_by_id(actor_id)
    if not actor or actor.role != "admin":
        return False, "Unauthorized: Admin privileges required to unlock user accounts."

    target_user = get_user_by_id(target_user_id)
    if not target_user:
        return False, f"User {target_user_id} not found."

    target_user.failed_login_count = 0
    target_user.locked_until = None

    log_action(
        user_id=actor_id,
        action=f"unlock_user:{target_user.username}",
        target_table="users",
        target_id=target_user.id,
    )
    try:
        db.session.commit()
        return True, f"User '{target_user.username}' has been successfully unlocked."
    except Exception as exc:
        db.session.rollback()
        logger.error("unlock_user failed: %s", exc, exc_info=True)
        return False, "Database error while unlocking user account."


def revoke_user_sessions(actor_id: int, target_user_id: int) -> tuple[bool, str]:
    """
    Admin-initiated force-logout / revocation of all active browser sessions for a target user.
    Returns (success: bool, message: str).
    """
    actor = get_user_by_id(actor_id)
    if not actor or actor.role != "admin":
        return False, "Unauthorized: Admin privileges required to revoke user sessions."

    target_user = get_user_by_id(target_user_id)
    if not target_user:
        return False, f"User {target_user_id} not found."

    # Rotate session token to immediately terminate active sessions
    target_user.session_token = secrets.token_hex(16)

    log_action(
        user_id=actor_id,
        action=f"revoke_sessions:{target_user.username}",
        target_table="users",
        target_id=target_user.id,
    )
    try:
        db.session.commit()
        return True, f"All active sessions for user '{target_user.username}' have been revoked."
    except Exception as exc:
        db.session.rollback()
        logger.error("revoke_user_sessions failed: %s", exc, exc_info=True)
        return False, "Database error while revoking user sessions."


# ---------------------------------------------------------------------------
# G-8: Analyst Activity & Contribution Metrics
# ---------------------------------------------------------------------------

def get_analyst_activity_metrics() -> dict[str, Any]:
    """
    Compute operational contributions and metrics for all analysts/users (G-8).
    Tracks indicators created, threat reports submitted, malware cataloged,
    and alerts handled.
    """
    users = User.query.order_by(User.id).all()
    user_metrics = []

    total_indicators_all = ThreatIndicator.query.count()
    total_reports_all = ThreatReport.query.count()
    total_malware_all = Malware.query.count()
    total_alerts_resolved_all = Alert.query.filter_by(status="Resolved").count()
    total_audit_events_all = AuditLog.query.count()

    for u in users:
        ioc_count = ThreatIndicator.query.filter_by(added_by_user_id=u.id).count()
        rep_count = ThreatReport.query.filter_by(user_id=u.id).count()
        mal_count = Malware.query.filter_by(created_by_user_id=u.id).count()
        alert_count = Alert.query.filter_by(user_id=u.id).count()
        audit_count = AuditLog.query.filter_by(user_id=u.id).count()

        total_contrib = ioc_count + rep_count + mal_count + alert_count

        last_active = u.last_login
        latest_audit = (
            AuditLog.query.filter_by(user_id=u.id)
            .order_by(AuditLog.created_at.desc())
            .first()
        )
        if latest_audit and (not last_active or latest_audit.created_at > last_active):
            last_active = latest_audit.created_at

        user_metrics.append({
            "user_id": u.id,
            "username": u.username,
            "email": u.email,
            "role": u.role,
            "is_active": u.is_active,
            "is_locked": u.is_locked,
            "indicators_count": ioc_count,
            "reports_count": rep_count,
            "malware_count": mal_count,
            "alerts_count": alert_count,
            "audit_count": audit_count,
            "total_contributions": total_contrib,
            "last_active": last_active,
        })

    user_metrics.sort(key=lambda m: (m["total_contributions"], m["audit_count"]), reverse=True)

    top_analyst = None
    analysts_only = [m for m in user_metrics if m["role"] in ("analyst", "admin")]
    if analysts_only and analysts_only[0]["total_contributions"] > 0:
        top_analyst = analysts_only[0]
    elif user_metrics and user_metrics[0]["total_contributions"] > 0:
        top_analyst = user_metrics[0]

    return {
        "users": user_metrics,
        "summary": {
            "total_indicators": total_indicators_all,
            "total_reports": total_reports_all,
            "total_malware": total_malware_all,
            "total_alerts_resolved": total_alerts_resolved_all,
            "total_audit_events": total_audit_events_all,
            "active_analysts_count": len([m for m in user_metrics if m["role"] == "analyst" and m["is_active"]]),
            "top_contributor": top_analyst,
        },
    }


# ---------------------------------------------------------------------------
# G-10: Bulk User Actions (Suspend, Activate, Role Change, Session Revocation)
# ---------------------------------------------------------------------------

def bulk_suspend_users(actor_id: int, user_ids: list[int]) -> tuple[bool, str, int]:
    """
    Bulk suspend selected user accounts.
    Skips actor's own account and terminates sessions for suspended users.
    Returns (success: bool, message: str, count: int).
    """
    actor = get_user_by_id(actor_id)
    if not actor or actor.role != "admin":
        return False, "Unauthorized: Admin privileges required.", 0

    if not user_ids:
        return False, "No users selected.", 0

    count = 0
    skipped_self = False
    for uid in set(user_ids):
        if uid == actor_id:
            skipped_self = True
            continue
        user = get_user_by_id(uid)
        if not user or not user.is_active:
            continue

        user.is_active = False
        user.session_token = secrets.token_hex(16)  # G-6 terminate sessions
        log_action(
            user_id=actor_id,
            action=f"bulk_suspend_user:{user.username}",
            target_table="users",
            target_id=user.id,
        )
        count += 1

    try:
        db.session.commit()
        msg = f"Successfully suspended {count} user(s)."
        if skipped_self:
            msg += " (Your own account was skipped)."
        return True, msg, count
    except Exception as exc:
        db.session.rollback()
        logger.error("bulk_suspend_users failed: %s", exc, exc_info=True)
        return False, "Database error during bulk suspension.", 0


def bulk_activate_users(actor_id: int, user_ids: list[int]) -> tuple[bool, str, int]:
    """
    Bulk activate selected user accounts and clear lockout states.
    Returns (success: bool, message: str, count: int).
    """
    actor = get_user_by_id(actor_id)
    if not actor or actor.role != "admin":
        return False, "Unauthorized: Admin privileges required.", 0

    if not user_ids:
        return False, "No users selected.", 0

    count = 0
    for uid in set(user_ids):
        user = get_user_by_id(uid)
        if not user or user.is_active:
            continue

        user.is_active = True
        user.failed_login_count = 0  # G-4 clear lockout
        user.locked_until = None
        log_action(
            user_id=actor_id,
            action=f"bulk_activate_user:{user.username}",
            target_table="users",
            target_id=user.id,
        )
        count += 1

    try:
        db.session.commit()
        return True, f"Successfully activated {count} user(s).", count
    except Exception as exc:
        db.session.rollback()
        logger.error("bulk_activate_users failed: %s", exc, exc_info=True)
        return False, "Database error during bulk activation.", 0


def bulk_update_user_roles(actor_id: int, user_ids: list[int], new_role: str) -> tuple[bool, str, int]:
    """
    Bulk update role for selected user accounts.
    Guards against removing the last administrator account.
    Returns (success: bool, message: str, count: int).
    """
    actor = get_user_by_id(actor_id)
    if not actor or actor.role != "admin":
        return False, "Unauthorized: Admin privileges required.", 0

    if not user_ids:
        return False, "No users selected.", 0

    if new_role not in VALID_ROLES:
        return False, f"Invalid role '{new_role}'. Must be one of: {list(VALID_ROLES)}", 0

    # Guard: Check last admin constraint if new_role is not admin
    if new_role != "admin":
        total_admins = User.query.filter_by(role="admin").count()
        selected_admins = User.query.filter(User.id.in_(user_ids), User.role == "admin").count()
        if selected_admins >= total_admins:
            return False, "Cannot demote all administrators. At least one admin must remain.", 0

    count = 0
    for uid in set(user_ids):
        user = get_user_by_id(uid)
        if not user or user.role == new_role:
            continue

        old_role = user.role
        user.role = new_role
        log_action(
            user_id=actor_id,
            action=f"bulk_update_role:{old_role}->{new_role}",
            target_table="users",
            target_id=user.id,
        )
        count += 1

    try:
        db.session.commit()
        return True, f"Updated {count} user(s) to role '{new_role}'.", count
    except Exception as exc:
        db.session.rollback()
        logger.error("bulk_update_user_roles failed: %s", exc, exc_info=True)
        return False, "Database error during bulk role update.", 0


def bulk_revoke_user_sessions(actor_id: int, user_ids: list[int]) -> tuple[bool, str, int]:
    """
    Bulk terminate active browser sessions for selected users by rotating session tokens.
    Returns (success: bool, message: str, count: int).
    """
    actor = get_user_by_id(actor_id)
    if not actor or actor.role != "admin":
        return False, "Unauthorized: Admin privileges required.", 0

    if not user_ids:
        return False, "No users selected.", 0

    count = 0
    for uid in set(user_ids):
        user = get_user_by_id(uid)
        if not user:
            continue

        user.session_token = secrets.token_hex(16)  # G-6 rotate session token
        log_action(
            user_id=actor_id,
            action=f"bulk_revoke_sessions:{user.username}",
            target_table="users",
            target_id=user.id,
        )
        count += 1

    try:
        db.session.commit()
        return True, f"Revoked active sessions for {count} user(s).", count
    except Exception as exc:
        db.session.rollback()
        logger.error("bulk_revoke_user_sessions failed: %s", exc, exc_info=True)
        return False, "Database error during bulk session revocation.", 0

