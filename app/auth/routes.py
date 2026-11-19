from datetime import datetime, timezone, timedelta
import secrets
from flask import (
    render_template,
    request,
    redirect,
    url_for,
    flash,
    session,
    current_app,
)

from flask_login import login_user, logout_user, login_required
from werkzeug.security import generate_password_hash, check_password_hash

from app import db, limiter
from app.models import User
from app.services.security_service import (
    validate_password_complexity,
    sanitize_text,
)
from app.services.audit_service import log_action
from . import auth_bp


@auth_bp.route("/login", methods=["GET", "POST"])
@limiter.limit("15 per minute", methods=["POST"])
def login():

    if request.method == "POST":

        email = (request.form.get("email") or "").strip().lower()
        password = request.form.get("password") or ""
        remember = request.form.get("remember_me") == "on"

        # Validation
        if not email or not password:
            flash("Username/Email and Password are required.", "danger")
            return redirect(url_for("auth.login"))

        # Find User (accepts either corporate email or username)
        user = User.query.filter((User.email == email) | (User.username == email)).first()

        if user:
            # G-4: Check if account is temporarily locked
            now = datetime.now(timezone.utc)
            if user.locked_until:
                locked_dt = user.locked_until
                if locked_dt.tzinfo is None:
                    locked_dt = locked_dt.replace(tzinfo=timezone.utc)
                if locked_dt > now:
                    remaining_sec = int((locked_dt - now).total_seconds())
                    remaining_min = max(1, (remaining_sec + 59) // 60)
                    log_action(
                        user_id=user.id,
                        action=f"login_attempt_locked:{user.username}",
                        target_table="users",
                        target_id=user.id,
                    )
                    flash(f"Account is temporarily locked due to multiple failed login attempts. Please try again after {remaining_min} minute(s) or contact an administrator.", "danger")
                    return redirect(url_for("auth.login"))
                else:
                    # Lockout period expired; reset lock
                    user.locked_until = None
                    user.failed_login_count = 0
                    db.session.commit()

            # Verify password
            if check_password_hash(user.password_hash, password):
                # Account status check
                if not user.is_active:
                    flash("This account has been deactivated. Please contact an administrator.", "danger")
                    return redirect(url_for("auth.login"))

                # Phase 3: MFA / TOTP Challenge
                if user.mfa_enabled:
                    session["mfa_pending_user_id"] = user.id
                    session["mfa_remember"] = remember
                    return redirect(url_for("auth.login_2fa"))

                # G-4: Reset lockout counters on success
                user.failed_login_count = 0
                user.locked_until = None

                # G-3: Track last login timestamp and client IP
                user.last_login = datetime.now(timezone.utc)
                user.last_login_ip = request.remote_addr or "127.0.0.1"

                # G-6: Generate and attach fresh session token
                user_session_token = secrets.token_hex(16)
                user.session_token = user_session_token
                session["_session_token"] = user_session_token

                db.session.commit()

                login_user(user, remember=remember)
                flash("Login successful.", "success")
                return redirect(url_for("dashboard.dashboard"))
            else:
                # Password incorrect: increment failed counter
                user.failed_login_count = (user.failed_login_count or 0) + 1
                threshold = current_app.config.get("ACCOUNT_LOCKOUT_THRESHOLD", 5)
                duration_mins = current_app.config.get("ACCOUNT_LOCKOUT_DURATION_MINUTES", 15)

                if user.failed_login_count >= threshold:
                    user.locked_until = now + timedelta(minutes=duration_mins)
                    db.session.commit()
                    log_action(
                        user_id=user.id,
                        action=f"account_lockout:{user.username}",
                        target_table="users",
                        target_id=user.id,
                    )
                    flash(f"Account has been temporarily locked for {duration_mins} minutes due to {threshold} consecutive failed login attempts. Contact an administrator to unlock sooner.", "danger")
                    return redirect(url_for("auth.login"))
                else:
                    db.session.commit()
                    log_action(
                        user_id=user.id,
                        action=f"login_failed_password:{user.username}",
                        target_table="users",
                        target_id=user.id,
                    )

        flash("Invalid email or password.", "danger")
        return redirect(url_for("auth.login"))

    return render_template("login.html")


@auth_bp.route("/login/2fa", methods=["GET", "POST"])
@limiter.limit("15 per minute", methods=["POST"])
def login_2fa():
    """
    Two-Factor Authentication (TOTP / Emergency Recovery Code) Verification.
    """
    user_id = session.get("mfa_pending_user_id")
    if not user_id:
        return redirect(url_for("auth.login"))

    user = db.session.get(User, user_id)
    if not user or not user.is_active or not user.mfa_enabled:
        session.pop("mfa_pending_user_id", None)
        session.pop("mfa_remember", None)
        return redirect(url_for("auth.login"))

    if request.method == "POST":
        code = (request.form.get("totp_code") or "").strip()
        remember = session.get("mfa_remember", False)

        from app.services.mfa_service import verify_user_mfa
        is_valid, msg = verify_user_mfa(user, code)

        if is_valid:
            # G-4: Reset lockout state
            user.failed_login_count = 0
            user.locked_until = None

            # G-3: Track last login timestamp and client IP
            user.last_login = datetime.now(timezone.utc)
            user.last_login_ip = request.remote_addr or "127.0.0.1"

            # G-6: Attach fresh session token
            user_session_token = secrets.token_hex(16)
            user.session_token = user_session_token
            session["_session_token"] = user_session_token

            db.session.commit()

            # Clean up temporary state
            session.pop("mfa_pending_user_id", None)
            session.pop("mfa_remember", None)

            login_user(user, remember=remember)
            log_action(
                user_id=user.id,
                action=f"mfa_login_success:{user.username}",
                target_table="users",
                target_id=user.id,
            )
            flash("Two-Factor Authentication verified. Login successful.", "success")
            return redirect(url_for("dashboard.dashboard"))
        else:
            log_action(
                user_id=user.id,
                action=f"mfa_login_failed:{user.username}",
                target_table="users",
                target_id=user.id,
            )
            flash(msg, "danger")
            return render_template("login-2fa.html", user=user)

    return render_template("login-2fa.html", user=user)


@auth_bp.route("/register", methods=["GET", "POST"])
@limiter.limit("10 per minute", methods=["POST"])
def register():

    if request.method == "POST":

        username = sanitize_text(request.form.get("username", "")).strip()
        email = (request.form.get("email") or "").strip().lower()
        password = request.form.get("password") or ""
        confirm_password = request.form.get("confirm_password") or ""

        # Validation
        if not username or not email or not password or not confirm_password:
            flash("All fields are required.", "danger")
            return redirect(url_for("auth.register"))

        if password != confirm_password:
            flash("Passwords do not match.", "danger")
            return redirect(url_for("auth.register"))

        # Password Policy Complexity Check (Task 11)
        is_valid_pw, pw_err = validate_password_complexity(password)
        if not is_valid_pw:
            flash(pw_err, "danger")
            return redirect(url_for("auth.register"))

        # Username already exists
        existing_username = User.query.filter_by(username=username).first()
        if existing_username:
            flash("Username already exists.", "warning")
            return redirect(url_for("auth.register"))

        # Email already exists
        existing_email = User.query.filter_by(email=email).first()
        if existing_email:
            flash("Email already exists.", "warning")
            return redirect(url_for("auth.register"))

        # Password Hashing
        hashed_password = generate_password_hash(password)

        # Create User
        user = User(
            username=username,
            email=email,
            password_hash=hashed_password,
            role="user",
            is_active=True,
            api_key=secrets.token_hex(24),
            api_key_created_at=datetime.now(timezone.utc),
        )

        db.session.add(user)
        db.session.commit()

        log_action(
            user_id=user.id,
            action=f"user_registered:{user.username}",
            target_table="users",
            target_id=user.id,
        )

        flash("Registration successful! Please login.", "success")
        return redirect(url_for("auth.login"))

    return render_template("register.html")


@auth_bp.route("/logout")
@login_required
def logout():

    logout_user()
    session.clear()
    flash("You have been logged out successfully.", "success")
    return redirect(url_for("auth.login"))


@auth_bp.route("/reset-password/<token>", methods=["GET", "POST"])
@limiter.limit("10 per minute", methods=["POST"])
def reset_password_token(token):
    """
    Public token-based password reset completion endpoint.
    Validates cryptographic signature, expiry, and single-use fingerprint.
    """
    from app.services.admin_service import reset_password_with_token

    if request.method == "POST":
        new_password = request.form.get("new_password", "")
        confirm_password = request.form.get("confirm_password", "")

        if not new_password or not confirm_password:
            flash("New password and confirm password are required.", "danger")
            return render_template("reset-password.html", token=token)

        if new_password != confirm_password:
            flash("Passwords do not match.", "danger")
            return render_template("reset-password.html", token=token)

        ok, msg = reset_password_with_token(token, new_password)
        if ok:
            flash(msg, "success")
            return redirect(url_for("auth.login"))
        else:
            flash(msg, "danger")
            return render_template("reset-password.html", token=token)

    return render_template("reset-password.html", token=token)
