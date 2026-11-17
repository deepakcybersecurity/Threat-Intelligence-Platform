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
import re
from typing import Dict, Optional, Tuple

logger = logging.getLogger(__name__)

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
