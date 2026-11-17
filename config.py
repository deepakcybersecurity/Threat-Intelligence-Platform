import os
from datetime import timedelta
from dotenv import load_dotenv
from urllib.parse import quote_plus

# Load environment variables
load_dotenv()


class Config:

    basedir = os.path.abspath(os.path.dirname(__file__))

    # Secret Key
    SECRET_KEY = os.getenv("SECRET_KEY")
    if not SECRET_KEY:
        SECRET_KEY = "dev-insecure-secret-key-change-in-production-2026"

    # Session & Cookie Security
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = "Lax"
    SESSION_COOKIE_SECURE = False  # Enabled in ProductionConfig
    PERMANENT_SESSION_LIFETIME = timedelta(hours=8)
    REMEMBER_COOKIE_HTTPONLY = True
    REMEMBER_COOKIE_SAMESITE = "Lax"
    REMEMBER_COOKIE_SECURE = False

    # CSRF Protection (Flask-WTF)
    WTF_CSRF_ENABLED = True
    WTF_CSRF_TIME_LIMIT = 3600  # 1 hour token validity

    # Rate Limiting (Flask-Limiter)
    RATELIMIT_ENABLED = os.getenv("RATELIMIT_ENABLED", "True").lower() in ("true", "1", "yes")
    RATELIMIT_STORAGE_URI = os.getenv("RATELIMIT_STORAGE_URI", "redis://localhost:6379/0")
    RATELIMIT_IN_MEMORY_FALLBACK_ENABLED = True
    RATELIMIT_DEFAULT = os.getenv("RATELIMIT_DEFAULT", "2000 per hour;500 per minute")
    RATELIMIT_STRATEGY = "fixed-window"

    # Password Policy Configuration
    PASSWORD_MIN_LENGTH = int(os.getenv("PASSWORD_MIN_LENGTH", "8"))
    PASSWORD_REQUIRE_UPPERCASE = True
    PASSWORD_REQUIRE_LOWERCASE = True
    PASSWORD_REQUIRE_NUMBER = True
    PASSWORD_REQUIRE_SPECIAL = True

    # Account Lockout Policy (G-4: Brute Force Protection)
    ACCOUNT_LOCKOUT_THRESHOLD = int(os.getenv("ACCOUNT_LOCKOUT_THRESHOLD", "5"))
    ACCOUNT_LOCKOUT_DURATION_MINUTES = int(os.getenv("ACCOUNT_LOCKOUT_DURATION_MINUTES", "15"))

    # Security Headers & HSTS
    ENABLE_HSTS = os.getenv("ENABLE_HSTS", "False").lower() in ("true", "1", "yes")

    # TLS / Reverse Proxy Configuration (ProxyFix)
    BEHIND_PROXY = os.getenv("BEHIND_PROXY", "False").lower() in ("true", "1", "yes")
    PROXY_FIX_FOR = int(os.getenv("PROXY_FIX_FOR", "1"))
    PROXY_FIX_PROTO = int(os.getenv("PROXY_FIX_PROTO", "1"))
    PROXY_FIX_HOST = int(os.getenv("PROXY_FIX_HOST", "1"))
    PROXY_FIX_PORT = int(os.getenv("PROXY_FIX_PORT", "1"))
    PROXY_FIX_PREFIX = int(os.getenv("PROXY_FIX_PREFIX", "1"))

    # AbuseIPDB API Configuration
    ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY")
    VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY")
    OTX_API_KEY = os.getenv("OTX_API_KEY")

    # SIEM / EDR Webhook Integration Key & Webhook Signature Enforcement
    SIEM_WEBHOOK_API_KEY = os.getenv("SIEM_WEBHOOK_API_KEY", "tip-siem-edr-default-secret-key-2026")
    SIEM_WEBHOOK_SECRET = os.getenv("SIEM_WEBHOOK_SECRET") or SIEM_WEBHOOK_API_KEY
    SIEM_WEBHOOK_REQUIRE_SIGNATURE = os.getenv("SIEM_WEBHOOK_REQUIRE_SIGNATURE", "False").lower() in ("true", "1", "yes")

    # MySQL Database Configuration
    DB_USERNAME = os.getenv("DB_USERNAME")
    DB_PASSWORD = os.getenv("DB_PASSWORD")
    DB_HOST = os.getenv("DB_HOST")
    DB_PORT = os.getenv("DB_PORT")
    DB_NAME = os.getenv("DB_NAME")

    # SQLAlchemy Database URI
    SQLALCHEMY_DATABASE_URI = (
        f"mysql+pymysql://{DB_USERNAME}:{quote_plus(DB_PASSWORD)}"
        f"@{DB_HOST}:{DB_PORT}/{DB_NAME}"
    )

    # Disable modification tracking
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    # File Upload Configuration
    MAX_CONTENT_LENGTH = 16 * 1024 * 1024

    # Upload Folder
    UPLOAD_FOLDER = "app/static/uploads"


class DevelopmentConfig(Config):
    DEBUG = True
    SESSION_COOKIE_SECURE = False
    REMEMBER_COOKIE_SECURE = False
    ENABLE_HSTS = False
    SIEM_WEBHOOK_REQUIRE_SIGNATURE = False
    RATELIMIT_STORAGE_URI = "memory://"


class ProductionConfig(Config):
    DEBUG = False
    SESSION_COOKIE_SECURE = True
    REMEMBER_COOKIE_SECURE = True
    ENABLE_HSTS = True
    BEHIND_PROXY = True
    SIEM_WEBHOOK_REQUIRE_SIGNATURE = os.getenv("SIEM_WEBHOOK_REQUIRE_SIGNATURE", "True").lower() in ("true", "1", "yes")
    RATELIMIT_STORAGE_URI = os.getenv("RATELIMIT_STORAGE_URI", "redis://localhost:6379/0")

    @classmethod
    def validate_production_secrets(cls):
        """Fail safely if required production secrets are missing."""
        secret = os.getenv("SECRET_KEY")
        if not secret or secret == "dev-insecure-secret-key-change-in-production-2026":
            raise ValueError(
                "CRITICAL SECURITY CONFIGURATION ERROR: "
                "SECRET_KEY environment variable MUST be explicitly configured for Production!"
            )

        siem_key = os.getenv("SIEM_WEBHOOK_API_KEY")
        if not siem_key or siem_key == "tip-siem-edr-default-secret-key-2026":
            raise ValueError(
                "CRITICAL SECURITY CONFIGURATION ERROR: "
                "SIEM_WEBHOOK_API_KEY environment variable MUST be explicitly configured with a strong secret for Production!"
            )
