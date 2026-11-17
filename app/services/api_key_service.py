"""
API Key Service — Phase 3: Advanced Identity & Authentication
Provides secure analyst-level API key generation, rotation, revocation,
and verification for machine-to-machine REST API integrations.
"""

from datetime import datetime, timezone
import logging
import secrets

from app import db
from app.models.user import User
from app.services.audit_service import log_action

logger = logging.getLogger(__name__)


def generate_user_api_key(user_id: int, label: str = "Personal API Key") -> tuple[bool, str, str | None]:
    """
    Generate or rotate a cryptographically secure personal API key for a user.
    Never persists or logs plaintext keys in audit logs.
    Returns (success: bool, message: str, raw_api_key: str | None).
    """
    user = db.session.get(User, user_id)
    if not user:
        return False, "User not found.", None

    if not user.is_active:
        return False, "Cannot generate API key for a suspended or deactivated account.", None

    clean_label = (label or "Personal API Key").strip()[:100]
    token = f"tip_live_{secrets.token_urlsafe(32)}"

    old_action = "rotate_api_key" if user.api_key else "create_api_key"
    user.api_key = token
    user.api_key_created_at = datetime.now(timezone.utc)
    user.api_key_label = clean_label

    # Audit log records the event without recording the secret token
    log_action(
        user_id=user.id,
        action=f"{old_action}:{clean_label}",
        target_table="users",
        target_id=user.id,
    )

    try:
        db.session.commit()
        return True, "API key generated successfully. Copy your key now as it will not be shown in full again.", token
    except Exception as exc:
        db.session.rollback()
        logger.error("generate_user_api_key failed: %s", exc, exc_info=True)
        return False, "Database error while generating API key.", None


def revoke_user_api_key(user_id: int, actor_id: int | None = None) -> tuple[bool, str]:
    """
    Revoke an active personal API key immediately invalidating programmatic access.
    Returns (success: bool, message: str).
    """
    user = db.session.get(User, user_id)
    if not user:
        return False, "User not found."

    if not user.api_key:
        return False, "No active API key found on this account."

    label = user.api_key_label or "Personal API Key"
    user.api_key = None
    user.api_key_created_at = None
    user.api_key_label = None

    effective_actor = actor_id or user.id
    log_action(
        user_id=effective_actor,
        action=f"revoke_api_key:{label}",
        target_table="users",
        target_id=user.id,
    )

    try:
        db.session.commit()
        return True, "API key has been revoked. All programmatic requests using this key will now be rejected."
    except Exception as exc:
        db.session.rollback()
        logger.error("revoke_user_api_key failed: %s", exc, exc_info=True)
        return False, "Database error while revoking API key."


def get_user_api_key_info(user_id: int) -> dict:
    """Return non-sensitive metadata regarding the user's current API key."""
    user = db.session.get(User, user_id)
    if not user or not user.api_key:
        return {
            "has_key": False,
            "masked_key": "",
            "created_at": None,
            "label": None,
        }

    return {
        "has_key": True,
        "masked_key": user.masked_api_key,
        "created_at": user.api_key_created_at,
        "label": user.api_key_label,
    }
