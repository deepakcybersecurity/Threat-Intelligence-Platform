import os
from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_login import LoginManager
from flask_wtf.csrf import CSRFProtect, CSRFError
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

from config import DevelopmentConfig

# Initialize Extensions
db = SQLAlchemy()
migrate = Migrate()
login_manager = LoginManager()
csrf = CSRFProtect()
limiter = Limiter(
    key_func=get_remote_address,
    default_limits=["2000 per hour", "500 per minute"],
    in_memory_fallback_enabled=True,
    in_memory_fallback=["500 per minute"],
)


def create_app(config_object=None):

    app = Flask(__name__)

    # Load Configurations
    if config_object is None:
        env = os.getenv("FLASK_ENV", "development").lower()
        if env == "production":
            from config import ProductionConfig
            config_object = ProductionConfig
        else:
            config_object = DevelopmentConfig
    app.config.from_object(config_object)

    # ── TLS Termination / Reverse Proxy Support (ProxyFix) ───────────────────
    if app.config.get("BEHIND_PROXY", False):
        from werkzeug.middleware.proxy_fix import ProxyFix
        app.wsgi_app = ProxyFix(
            app.wsgi_app,
            x_for=app.config.get("PROXY_FIX_FOR", 1),
            x_proto=app.config.get("PROXY_FIX_PROTO", 1),
            x_host=app.config.get("PROXY_FIX_HOST", 1),
            x_port=app.config.get("PROXY_FIX_PORT", 1),
            x_prefix=app.config.get("PROXY_FIX_PREFIX", 1),
        )

    app.config["UPLOAD_FOLDER"] = os.path.join(
        app.root_path,
        "uploads",
        "reports"
    )

    os.makedirs(app.config["UPLOAD_FOLDER"], exist_ok=True)

    # Initialize Database & Migrations
    db.init_app(app)
    migrate.init_app(app, db)

    # Initialize Authentication
    login_manager.init_app(app)
    login_manager.login_view = "auth.login"
    login_manager.login_message = "Please login to access this page."
    login_manager.login_message_category = "warning"

    # Initialize Security Extensions (Task 11: Security Hardening)
    csrf.init_app(app)
    limiter.init_app(app)

    from app.models import (
        User,
        ThreatReport,
        ThreatIndicator,
        Malware,
        Alert,
        ThreatNews,
        AuditLog,
        IPLookupHistory,
        APICache
    )

    @login_manager.user_loader
    def load_user(user_id):
        return db.session.get(User, int(user_id))

    # Import and Register Blueprints
    from app.routes.main_routes import main_bp
    app.register_blueprint(main_bp)

    from app.auth import auth_bp
    app.register_blueprint(auth_bp)

    from app.dashboard import dashboard_bp
    app.register_blueprint(dashboard_bp)

    from app.admin import admin_bp
    app.register_blueprint(admin_bp)

    from app.api import api_bp
    app.register_blueprint(api_bp)

    # ── CSRF Exemption for Stateless REST API & Webhooks ───────────────────────
    # REST API v1/v2 and inbound Webhook endpoints use stateless header-based
    # authentication (X-API-Key or Authorization Bearer tokens). Browsers do not
    # attach these custom headers on cross-site requests, making CSRF protection
    # redundant and incompatible with automated machine-to-machine integrations.
    csrf.exempt(api_bp)

    # ── Register Custom CLI Commands (Task 13) ────────────────────────────────
    from app.cli import register_cli_commands
    register_cli_commands(app)

    # ── Security Headers (Task 11) ────────────────────────────────────────────
    @app.after_request
    def add_security_headers(response):
        from app.services.security_service import apply_security_headers
        return apply_security_headers(response, app)

    # ── G-6: Active Session Invalidation & Account Status Enforcement ─────────
    @app.before_request
    def enforce_security_and_session_state():
        from flask_login import current_user, logout_user
        from flask import session as _sess, redirect, url_for, flash, request as _req, jsonify, g

        if _req.endpoint == "static":
            return

        # Ensure g._login_user is evaluated fresh from the current request's session cookie
        g.pop("_login_user", None)

        if current_user.is_authenticated:
            # 1. G-6: Immediate logout if account is deactivated/suspended while in active session
            if not current_user.is_active:
                logout_user()
                _sess.clear()
                if _req.path.startswith("/api/") or _req.is_json:
                    return jsonify({"success": False, "error": "Unauthorized", "message": "Account has been deactivated"}), 401
                flash("Your account has been deactivated. Please contact an administrator.", "danger")
                return redirect(url_for("auth.login"))

            # 2. G-6: Immediate logout if session token does not match (revoked by admin / password reset)
            sess_token = _sess.get("_session_token")
            if current_user.session_token and sess_token and sess_token != current_user.session_token:
                logout_user()
                _sess.clear()
                if _req.path.startswith("/api/") or _req.is_json:
                    return jsonify({"success": False, "error": "Unauthorized", "message": "Session has been revoked"}), 401
                flash("Your session has been terminated or revoked by an administrator. Please log in again.", "warning")
                return redirect(url_for("auth.login"))

    # ── Error Handlers ────────────────────────────────────────────────────────
    @app.errorhandler(400)
    def bad_request(e):
        from flask import render_template as _rt, jsonify, request as _req
        if _req.path.startswith("/api/") or _req.is_json:
            return jsonify({
                "success": False,
                "error": "BadRequest",
                "message": getattr(e, "description", "Bad Request")
            }), 400
        return _rt("400.html", error_message=getattr(e, "description", None)), 400

    @app.errorhandler(CSRFError)
    def handle_csrf_error(e):
        from flask import render_template as _rt, jsonify, request as _req
        if _req.path.startswith("/api/") or _req.is_json:
            return jsonify({
                "success": False,
                "error": "CSRFError",
                "message": e.description or "CSRF token missing or invalid."
            }), 400
        return _rt("400.html", error_message=e.description or "CSRF validation failed."), 400

    @app.errorhandler(403)
    def forbidden(e):
        from flask import render_template as _rt, jsonify, request as _req
        if _req.path.startswith("/api/") or _req.is_json:
            return jsonify({
                "success": False,
                "error": "Forbidden",
                "message": getattr(e, "description", "Access Forbidden")
            }), 403
        return _rt("403.html"), 403

    @app.errorhandler(404)
    def not_found(e):
        from flask import render_template as _rt, jsonify, request as _req
        if _req.path.startswith("/api/") or _req.is_json:
            return jsonify({
                "success": False,
                "error": "NotFound",
                "message": getattr(e, "description", "Resource Not Found")
            }), 404
        return _rt("404.html"), 404

    @app.errorhandler(429)
    def ratelimit_exceeded(e):
        from flask import render_template as _rt, jsonify, request as _req
        if _req.path.startswith("/api/") or _req.is_json:
            return jsonify({
                "success": False,
                "error": "RateLimitExceeded",
                "message": "Too many requests. Please slow down and try again later.",
                "retry_after": getattr(e, "description", None)
            }), 429
        return _rt("429.html"), 429

    return app
