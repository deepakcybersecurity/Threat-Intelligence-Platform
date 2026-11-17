from flask_login import UserMixin
from app import db


class User(UserMixin, db.Model):
    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True)

    username = db.Column(
        db.String(100),
        unique=True,
        nullable=False
    )

    email = db.Column(
        db.String(150),
        unique=True,
        nullable=False
    )

    password_hash = db.Column(
        db.String(255),
        nullable=False
    )

    role = db.Column(
        db.Enum("admin", "analyst", "user"),
        default="user"
    )

    is_active = db.Column(
        db.Boolean,
        nullable=False,
        default=True
    )

    created_at = db.Column(
        db.DateTime,
        server_default=db.func.now()
    )

    # G-3: Last Login Tracking
    last_login = db.Column(
        db.DateTime,
        nullable=True
    )

    last_login_ip = db.Column(
        db.String(45),
        nullable=True
    )

    # G-4: Account Lockout & Brute Force Protection
    failed_login_count = db.Column(
        db.Integer,
        nullable=False,
        default=0
    )

    locked_until = db.Column(
        db.DateTime,
        nullable=True
    )

    # G-6: Force Session Revocation Token
    session_token = db.Column(
        db.String(64),
        nullable=True
    )

    # Phase 3: Multi-Factor Authentication (MFA / TOTP)
    mfa_enabled = db.Column(
        db.Boolean,
        nullable=False,
        default=False
    )

    mfa_secret = db.Column(
        db.String(64),
        nullable=True
    )

    mfa_backup_codes = db.Column(
        db.Text,
        nullable=True
    )

    # Phase 3: Analyst API Key Self-Service
    api_key = db.Column(
        db.String(64),
        unique=True,
        nullable=True
    )

    api_key_created_at = db.Column(
        db.DateTime,
        nullable=True
    )

    api_key_label = db.Column(
        db.String(100),
        nullable=True
    )

    @property
    def masked_api_key(self) -> str:
        """Return masked API key for safe UI rendering."""
        if not self.api_key:
            return ""
        if len(self.api_key) <= 12:
            return "••••••••"
        return f"{self.api_key[:9]}••••••••{self.api_key[-4:]}"

    @property
    def is_locked(self) -> bool:
        """Return True if account is currently locked due to failed attempts."""
        from datetime import datetime, timezone
        if self.locked_until:
            now = datetime.now(timezone.utc)
            locked_dt = self.locked_until
            if locked_dt.tzinfo is None:
                locked_dt = locked_dt.replace(tzinfo=timezone.utc)
            return locked_dt > now
        return False

    def reset_lockout(self):
        """Reset failed login counter and clear lockout timestamp."""
        self.failed_login_count = 0
        self.locked_until = None

    # relationships
    ip_lookup_history = db.relationship(
        "IPLookupHistory",
        back_populates="user",
        lazy=True
    )

    reports = db.relationship(
        "ThreatReport",
        back_populates="user",
        lazy=True
    )

    audit_logs = db.relationship(
        "AuditLog",
        back_populates="user",
        lazy=True
    )

    malwares = db.relationship(
        "Malware",
        back_populates="created_by",
        lazy=True
    )

    threat_indicators = db.relationship(
        "ThreatIndicator",
        back_populates="added_by",
        lazy=True
    )

    alerts = db.relationship(
        "Alert",
        back_populates="user",
        lazy=True
    )
