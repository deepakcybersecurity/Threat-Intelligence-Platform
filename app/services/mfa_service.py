"""
MFA / TOTP Service — Phase 3: Advanced Identity & Authentication
Provides RFC 6238 TOTP authenticator setup, inline SVG QR code generation,
verification, backup recovery code management, and administrative resets.
"""

import json
import logging
import secrets
import string
import pyotp
import qrcode
from qrcode.image.svg import SvgPathImage
from werkzeug.security import generate_password_hash, check_password_hash

from app import db
from app.models.user import User
from app.services.audit_service import log_action

logger = logging.getLogger(__name__)


def generate_mfa_secret() -> str:
    """Generate a high-entropy Base32 secret string for RFC 6238 TOTP."""
    return pyotp.random_base32()


def get_totp_uri(secret: str, username: str, email: str, issuer: str = "ThreatIntel Platform") -> str:
    """Generate Key URI for Google Authenticator / Microsoft Authenticator / 1Password."""
    totp = pyotp.TOTP(secret)
    account_name = email or username
    return totp.provisioning_uri(name=account_name, issuer_name=issuer)


def generate_qr_code_svg(uri: str) -> str:
    """Generate a clean, standalone inline SVG QR code vector string."""
    qr = qrcode.QRCode(
        version=None,
        error_correction=qrcode.constants.ERROR_CORRECT_M,
        box_size=8,
        border=2,
        image_factory=SvgPathImage,
    )
    qr.add_data(uri)
    qr.make(fit=True)
    img = qr.make_image()
    return img.to_string(encoding="unicode")


def generate_backup_codes(count: int = 8) -> list[str]:
    """Generate one-time emergency backup recovery codes in XXXX-XXXX format."""
    charset = string.ascii_uppercase + string.digits
    codes = []
    for _ in range(count):
        part1 = "".join(secrets.choice(charset) for _ in range(4))
        part2 = "".join(secrets.choice(charset) for _ in range(4))
        codes.append(f"{part1}-{part2}")
    return codes


def init_mfa_setup(user_id: int) -> tuple[bool, str, dict | None]:
    """
    Generate secret, QR code, and backup codes for the MFA setup workflow.
    Returns (success, message, setup_data).
    """
    user = db.session.get(User, user_id)
    if not user:
        return False, "User not found.", None

    secret = generate_mfa_secret()
    uri = get_totp_uri(secret, user.username, user.email)
    qr_svg = generate_qr_code_svg(uri)
    backup_codes = generate_backup_codes(count=8)

    setup_data = {
        "secret": secret,
        "uri": uri,
        "qr_svg": qr_svg,
        "backup_codes": backup_codes,
    }
    return True, "MFA setup initialized.", setup_data


def confirm_and_enable_mfa(
    user_id: int,
    secret: str,
    initial_code: str,
    backup_codes: list[str],
) -> tuple[bool, str]:
    """
    Verify the initial 6-digit TOTP code and enable MFA for the user account.
    Stores secret and securely hashed backup recovery codes.
    """
    user = db.session.get(User, user_id)
    if not user:
        return False, "User not found."

    clean_code = (initial_code or "").strip().replace(" ", "").replace("-", "")
    if not clean_code or len(clean_code) != 6 or not clean_code.isdigit():
        return False, "Please provide a valid 6-digit verification code from your authenticator app."

    totp = pyotp.TOTP(secret)
    if not totp.verify(clean_code, valid_window=1):
        return False, "Invalid authenticator code. Ensure your device time is synchronized and try again."

    # Hash backup recovery codes before persisting
    hashed_codes = [generate_password_hash(c.replace("-", "").upper()) for c in backup_codes]

    user.mfa_secret = secret
    user.mfa_enabled = True
    user.mfa_backup_codes = json.dumps(hashed_codes)

    log_action(
        user_id=user.id,
        action="mfa_enabled:totp",
        target_table="users",
        target_id=user.id,
    )

    try:
        db.session.commit()
        return True, "Multi-Factor Authentication has been successfully enabled."
    except Exception as exc:
        db.session.rollback()
        logger.error("confirm_and_enable_mfa failed: %s", exc, exc_info=True)
        return False, "Database error while enabling MFA."


def disable_mfa_for_user(
    user_id: int,
    current_password: str | None = None,
    is_admin_override: bool = False,
    actor_id: int | None = None,
) -> tuple[bool, str]:
    """
    Disable MFA on a user account.
    Requires current password confirmation unless overridden by an administrator.
    """
    user = db.session.get(User, user_id)
    if not user:
        return False, "User not found."

    if not is_admin_override:
        if not current_password or not check_password_hash(user.password_hash, current_password):
            return False, "Incorrect account password. Password is required to disable 2FA."

    user.mfa_enabled = False
    user.mfa_secret = None
    user.mfa_backup_codes = None

    effective_actor = actor_id or user.id
    log_action(
        user_id=effective_actor,
        action=f"mfa_disabled:{user.username}",
        target_table="users",
        target_id=user.id,
    )

    try:
        db.session.commit()
        return True, f"Multi-Factor Authentication disabled for '{user.username}'."
    except Exception as exc:
        db.session.rollback()
        logger.error("disable_mfa_for_user failed: %s", exc, exc_info=True)
        return False, "Database error while disabling MFA."


def verify_user_mfa(user: User, code: str) -> tuple[bool, str]:
    """
    Verify TOTP 6-digit code or one-time backup recovery code.
    If a valid backup code is used, it is consumed (removed from database).
    Returns (is_valid: bool, message: str).
    """
    if not user.mfa_enabled or not user.mfa_secret:
        return False, "Multi-Factor Authentication is not active on this account."

    clean_code = (code or "").strip().replace(" ", "").replace("-", "").upper()
    if not clean_code:
        return False, "Security code cannot be empty."

    # 1. Attempt TOTP verification
    if len(clean_code) == 6 and clean_code.isdigit():
        totp = pyotp.TOTP(user.mfa_secret)
        if totp.verify(clean_code, valid_window=1):
            return True, "Two-factor authentication verified successfully."

    # 2. Attempt Backup Code verification
    if user.mfa_backup_codes:
        try:
            hashed_codes = json.loads(user.mfa_backup_codes)
        except Exception:
            hashed_codes = []

        for idx, hashed_code in enumerate(hashed_codes):
            if check_password_hash(hashed_code, clean_code):
                # Consume this single-use recovery code
                hashed_codes.pop(idx)
                user.mfa_backup_codes = json.dumps(hashed_codes)
                log_action(
                    user_id=user.id,
                    action="mfa_backup_code_consumed",
                    target_table="users",
                    target_id=user.id,
                )
                try:
                    db.session.commit()
                except Exception:
                    db.session.rollback()

                remaining = len(hashed_codes)
                return True, f"One-time backup recovery code accepted. ({remaining} backup code(s) remaining)"

    return False, "Invalid authentication code or recovery code."


def count_remaining_backup_codes(user: User) -> int:
    """Return count of unused backup recovery codes."""
    if not user.mfa_backup_codes:
        return 0
    try:
        codes = json.loads(user.mfa_backup_codes)
        return len(codes)
    except Exception:
        return 0
