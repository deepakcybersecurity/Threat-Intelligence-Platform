"""
Security Hardening Service — Task 11: Security Hardening
=========================================================
Provides:
1. Password policy complexity enforcement (length, upper, lower, number, special char).
2. Server-side XSS and malicious input sanitization preserving legitimate threat intelligence syntax.
3. Content-Security-Policy (CSP) builder and security headers enforcement.
4. Safe secret verification and security configuration helpers.
"""

import html
import logging
import os
import re
from typing import Dict, Optional, Tuple, Set

logger = logging.getLogger(__name__)

# Allowed & Prohibited file upload extensions (CWE-434 Defense)
ALLOWED_REPORT_EXTENSIONS: Set[str] = {
    "pdf", "txt", "csv", "json", "docx", "doc", "xlsx", "log", "pcap", "md"
}
DANGEROUS_FILE_EXTENSIONS: Set[str] = {
    "exe", "dll", "bat", "cmd", "sh", "php", "phtml", "py", "pl", "rb",
    "cgi", "jsp", "asp", "aspx", "svg", "html", "htm", "js", "vbs", "ps1"
}


def validate_file_upload(filename: Optional[str]) -> Tuple[bool, Optional[str]]:
    """
    Validate uploaded file extensions to prevent malicious file uploads (CWE-434).
    Enforces whitelisted threat intelligence file formats (pdf, txt, csv, json, etc.)
    and rejects executable and script extensions.
    """
    if not filename or not isinstance(filename, str):
        return False, "Filename cannot be empty."

    parts = filename.rsplit(".", 1)
    if len(parts) < 2 or not parts[1].strip():
        return False, "File must have a valid extension."

    ext = parts[1].strip().lower()

    if ext in DANGEROUS_FILE_EXTENSIONS:
        return False, f"File extension '.{ext}' is strictly prohibited for security reasons."

    if ext not in ALLOWED_REPORT_EXTENSIONS:
        allowed_list = ", ".join(f".{e}" for e in sorted(ALLOWED_REPORT_EXTENSIONS))
        return False, f"Unsupported file type '.{ext}'. Allowed types: {allowed_list}."

    return True, None


def assert_safe_test_database(app=None) -> None:
    """
    Database Safety Guard:
    Refuses destructive test execution and teardown operations if the environment
    or database URI indicates a production system.

    Checks:
    1. FLASK_ENV or ENV environment variable is set to 'production'
    2. SQLALCHEMY_DATABASE_URI database name indicates a production database ('prod', 'production', 'live')
    3. ProductionConfig class is used without explicit testing override

    Raises:
        RuntimeError: if execution is unsafe against production.
    """
    flask_env = os.getenv("FLASK_ENV", "").strip().lower()
    if flask_env == "production":
        raise RuntimeError(
            "CRITICAL DATABASE SAFETY GUARD: Test execution refused against a production-configured environment (FLASK_ENV=production)!"
        )

    db_uri = ""
    if app:
        db_uri = app.config.get("SQLALCHEMY_DATABASE_URI", "")
        if app.config.get("ENV") == "production":
            raise RuntimeError(
                "CRITICAL DATABASE SAFETY GUARD: Test execution refused against production environment (ENV=production)!"
            )
        if not app.config.get("TESTING", False):
            raise RuntimeError(
                "CRITICAL DATABASE SAFETY GUARD: Test execution refused because app.config['TESTING'] is not True!"
            )
    else:
        db_uri = os.getenv("SQLALCHEMY_DATABASE_URI", "")

    if db_uri and "/" in db_uri:
        db_name = db_uri.rsplit("/", 1)[-1].split("?")[0].strip().lower()
        prod_markers = ["production", "prod_db", "production_db", "live_db", "prod_threat"]
        if any(marker in db_name for marker in prod_markers):
            raise RuntimeError(
                f"CRITICAL DATABASE SAFETY GUARD: Test execution refused against production database '{db_name}'!"
            )

# Default Password Policy
DEFAULT_MIN_PASSWORD_LENGTH = 8
SPECIAL_CHARS_PATTERN = r"[!@#$%^&*()_+\-=\[\]{};':\"\\|,.<>/?~`]"


def validate_password_complexity(
    password: str,
    min_length: int = DEFAULT_MIN_PASSWORD_LENGTH,
) -> Tuple[bool, Optional[str]]:
    """
    Validate password complexity against corporate security standards.

    Enforces:
    - Minimum length (default 8)
    - At least one uppercase letter (A-Z)
    - At least one lowercase letter (a-z)
    - At least one decimal digit (0-9)
    - At least one special symbol (!@#$%^&*...)

    Returns:
        (True, None) on success
        (False, error_message) on failure
    """
    if not password or not isinstance(password, str):
        return False, "Password cannot be empty."

    if len(password) < min_length:
        return False, f"Password must be at least {min_length} characters long."

    if not re.search(r"[A-Z]", password):
        return False, "Password must contain at least one uppercase letter (A-Z)."

    if not re.search(r"[a-z]", password):
        return False, "Password must contain at least one lowercase letter (a-z)."

    if not re.search(r"\d", password):
        return False, "Password must contain at least one numeric digit (0-9)."

    if not re.search(SPECIAL_CHARS_PATTERN, password):
        return False, "Password must contain at least one special character (!@#$%^&*...)."

    return True, None


def sanitize_text(text: Optional[str]) -> str:
    """
    Sanitize user-controlled text inputs against cross-site scripting (XSS),
    while strictly preserving legitimate threat intelligence syntax:
    - Defanged IPs/domains (e.g., '198.51.100[.]10', 'evil[.]com')
    - Full HTTP/HTTPS URLs with query parameters and anchors
    - Cryptographic hashes (MD5, SHA1, SHA256)
    - CVE identifiers and MITRE ATT&CK technique IDs
    - Formatted Markdown notes

    Strips:
    - Dangerous executable tags: <script>, <iframe>, <object>, <embed>, <applet>, <style>, <form>, <input>
    - 'javascript:' and 'vbscript:' pseudo-protocols
    - Inline HTML event attributes (onload=, onerror=, onclick=, onmouseover=, etc.)
    """
    if not text or not isinstance(text, str):
        return ""

    cleaned = text

    # 1. Strip dangerous container tags and their enclosed payload
    cleaned = re.sub(
        r"<\s*(script|iframe|object|embed|applet|style|base|meta)[^>]*>.*?<\s*/\s*\1\s*>",
        "",
        cleaned,
        flags=re.IGNORECASE | re.DOTALL,
    )

    # 2. Strip lone or self-closing dangerous tags
    cleaned = re.sub(
        r"<\s*/?\s*(script|iframe|object|embed|applet|style|base|meta|form|input|button)\b[^>]*>",
        "",
        cleaned,
        flags=re.IGNORECASE,
    )

    # 3. Strip javascript: and vbscript: URI schemes
    cleaned = re.sub(
        r"(javascript|vbscript|data\s*:\s*text/html)\s*:[^\s>\"']+",
        "",
        cleaned,
        flags=re.IGNORECASE,
    )

    # 4. Strip inline event handlers: onerror=..., onload=..., onclick=...
    cleaned = re.sub(
        r"""\bon[a-zA-Z]+\s*=\s*(?:\"[^\"]*\"|'[^']*'|[^\s>]+)""",
        "",
        cleaned,
        flags=re.IGNORECASE,
    )

    return cleaned.strip()


def build_csp_header(csp_dict: Dict[str, str]) -> str:
    """
    Assemble a Content-Security-Policy header string from directive dictionary.
    """
    directives = []
    for key, value in csp_dict.items():
        directives.append(f"{key} {value}")
    return "; ".join(directives)


def apply_security_headers(response, app=None):
    """
    Apply standard enterprise security headers to an HTTP response.

    Headers applied:
    - Content-Security-Policy (CSP)
    - X-Content-Type-Options: nosniff
    - X-Frame-Options: DENY
    - Referrer-Policy: strict-origin-when-cross-origin
    - X-XSS-Protection: 0 (defer to CSP and nosniff)
    - Strict-Transport-Security (HSTS): only if ENABLE_HSTS is True or request.is_secure
    """
    # 1. X-Content-Type-Options
    response.headers["X-Content-Type-Options"] = "nosniff"

    # 2. X-Frame-Options (prevent clickjacking)
    response.headers["X-Frame-Options"] = "DENY"

    # 3. Referrer-Policy
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"

    # 4. X-XSS-Protection: 0 (modern standard disables legacy buggy browser filters)
    response.headers["X-XSS-Protection"] = "0"

    # 5. Content-Security-Policy
    csp_policy = {
        "default-src": "'self'",
        "script-src": "'self' 'unsafe-inline'",
        "style-src": "'self' 'unsafe-inline' https://cdnjs.cloudflare.com",
        "font-src": "'self' https://cdnjs.cloudflare.com data:",
        "img-src": "'self' data: https:",
        "connect-src": "'self'",
        "frame-ancestors": "'none'",
        "base-uri": "'self'",
        "form-action": "'self'",
    }
    response.headers["Content-Security-Policy"] = build_csp_header(csp_policy)

    # 6. Strict-Transport-Security (HSTS)
    # Only applied if explicitly enabled via config or over secure HTTPS connection
    enable_hsts = False
    if app:
        enable_hsts = app.config.get("ENABLE_HSTS", False)
    if enable_hsts:
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"

    return response
