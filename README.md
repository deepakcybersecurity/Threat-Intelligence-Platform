# 🛡️ Threat Intelligence Platform (TIP)

An enterprise-grade, Flask-based **Threat Intelligence Platform (TIP)** designed for Security Operations Centers (SOC), incident responders, and threat analysts. The platform aggregates, correlates, enriches, and operationalizes threat indicators (IOCs), maps adversary tactics to the **MITRE ATT&CK® framework**, automates alert triage, and bridges detection pipelines via bi-directional **SIEM and EDR webhooks**.

![Python Version](https://img.shields.io/badge/python-3.12-blue.svg)
![Flask](https://img.shields.io/badge/framework-Flask%203.0-lightgrey.svg)
![Security Hardened](https://img.shields.io/badge/security-hardened-brightgreen.svg)
![Tests Status](https://img.shields.io/badge/tests-380%2F380%20passing-success.svg)
![Database](https://img.shields.io/badge/database-MySQL%208.x-orange.svg)

---

## 📑 Table of Contents
1. [Core Features & Modules](#-core-features--modules)
2. [Security & Hardening Architecture](#-security--hardening-architecture)
3. [Technology Stack](#-technology-stack)
4. [Project Directory Structure](#-project-directory-structure)
5. [Installation & Setup Guide](#-installation--setup-guide)
6. [CLI Management Commands](#-cli-management-commands)
7. [Running the Application](#-running-the-application)
8. [Automated Testing Suite](#-automated-testing-suite)
9. [REST API & Webhooks](#-rest-api--webhooks)
10. [Production Deployment Guide](#-production-deployment-guide)

---

## 🚀 Core Features & Modules

### 1. Executive Security Dashboard (`/dashboard`)
- Real-time KPI statistics: Total IOCs, Active Threats, Resolved Alerts, Ingested Reports, and Malware samples.
- Live threat telemetry logs and platform health monitoring.

### 2. Indicator of Compromise (IOC) Management (`/threat-feed`)
- Ingestion of IP addresses, domain names, URLs, and cryptographic hashes (MD5, SHA1, SHA256).
- Automated deduplication, confidence calculation, and multi-factor CVSS risk scoring.
- Automated Indicator TTL lifecycle management with periodic expiration and analyst reactivation.
- Multi-provider enrichment caching (VirusTotal, AlienVault OTX, AbuseIPDB).

### 3. Alert Center (`/alerts`)
- Deterministic alert correlation across incoming indicators and malware associations.
- Full incident lifecycle tracking: `Open` ➔ `In Progress` ➔ `Resolved` (with reopening support).
- Severity level classification: `Critical`, `High`, `Medium`, `Low`.

### 4. MITRE ATT&CK® Matrix Navigator (`/mitre-matrix`)
- Interactive coverage mapping of Enterprise Tactics & Techniques.
- Automatic extraction of TTPs from unstructured threat intelligence text and incident notes.
- ATT&CK Navigator Layer JSON export (`/api/v1/mitre/navigator`).

### 5. SIEM & EDR Webhook Ingestion Engine (`/siem-edr-integration`)
- Bi-directional integration portal for enterprise SIEMs (Splunk, Microsoft Sentinel, Elastic) and EDRs (CrowdStrike Falcon, Microsoft Defender for Endpoint, SentinelOne).
- Automated IOC extraction, risk scoring, and alert routing from raw JSON payloads.
- Interactive Webhook & EDR simulator consoles for SOC analyst testing.

### 6. Threat News & Advisory Aggregator (`/threat-news`)
- Automated RSS ingest from leading cybersecurity authorities (CISA Advisories, BleepingComputer, The Hacker News).
- One-click mining of Indicators of Compromise directly from published news articles.

### 7. Threat Reports & Malware Catalog (`/threat-reports`, `/malware-info`)
- Secure multipart upload and storage of technical incident reports.
- Comprehensive malware catalog tracking families, platforms, C2 architectures, and CVE references.

### 8. Admin Governance & Compliance Portal (`/admin`)
- Multi-role permission enforcement: Administrator (`admin`), Security Analyst (`analyst`), and Read-Only (`user`).
- Centralized user management: provision, suspend, activate, role upgrade/downgrade, and password reset links.
- Tamper-proof, filterable Audit Trail Registry with RFC 4180 CSV export.
- Analyst SOC contribution metrics and Top Contributor rankings.

---

## 🔒 Security & Hardening Architecture

The platform has undergone rigorous security auditing and hardening:

| Capability | Implementation Details |
|---|---|
| **Show/Hide Password Toggle** | Accessible SVG eye/eye-off toggle button with ARIA state management on Login, Register, and Reset Password pages. |
| **Webhook Cryptographic Integrity** | Inbound webhooks enforce **HMAC-SHA256 signature verification** (`X-Webhook-Signature`) with constant-time comparison (`secrets.compare_digest`). |
| **Replay Attack Protection** | Enforces a strict 300-second freshness window (`X-Webhook-Timestamp`) to prevent event capture and replay. |
| **Strict Role-Based Access Control** | Non-administrative roles receive `403 Forbidden` on `/admin`, while read-only users cannot perform write operations on API v2. |
| **Brute-Force & Lockout Guardrails** | Automatic account lockout for 15 minutes after 5 consecutive failed login attempts (`User.locked_until`). |
| **Active Session Invalidation** | Modifying passwords, suspending accounts, or clicking "Revoke Session" immediately rotates `User.session_token`, evicting hijacked cookies. |
| **Two-Factor Authentication (MFA)** | RFC 6238 TOTP with inline SVG QR codes and hashed single-use backup recovery codes. |
| **HTTPS / TLS Termination** | `Werkzeug ProxyFix` preserves HTTPS headers behind reverse proxies; enforces HSTS (`Strict-Transport-Security: max-age=31536000; includeSubDomains; preload`). |
| **Distributed Rate Limiting** | Multi-worker rate limiting backed by **Redis** (`RATELIMIT_STORAGE_URI=redis://...`) with automatic in-memory fallback. |
| **Safe Error Handling** | Database traces and sensitive exception details are stripped from client responses and logged exclusively on the server. |

---

## 💻 Technology Stack

- **Backend:** Python 3.12, Flask 3.0.3, Werkzeug 3.1.8
- **Database & Migration:** MySQL 8.x, SQLAlchemy 2.0, Flask-Migrate (Alembic)
- **Security & Crypto:** PyOTP, bcrypt, hashlib, hmac, itsdangerous
- **Rate Limiting & Caching:** Flask-Limiter 4.1.1, Redis 8.x, limits
- **Frontend:** Vanilla HTML5, CSS3 Glassmorphism (dark theme), Vanilla JavaScript ES6 (no heavy frontend frameworks)

---

## 📁 Project Directory Structure

```text
cybser security/
├── app/
│   ├── __init__.py                # App factory, extensions, ProxyFix, and security headers
│   ├── admin/                     # Admin Blueprint: user governance, bulk actions, audit logs
│   ├── api/                       # API Blueprint: REST v1/v2 routes, OpenAPI spec, blocklists
│   ├── auth/                      # Auth Blueprint: login, register, MFA 2FA, password reset
│   ├── cli.py                     # Custom Flask CLI management commands
│   ├── dashboard/                 # Dashboard Blueprint: feeds, alerts, reports, malware
│   ├── models/                    # SQLAlchemy models (User, Indicator, Alert, Malware, etc.)
│   ├── routes/                    # Main blueprint (Home)
│   ├── services/                  # Business logic (SIEM, EDR, Risk scoring, MITRE, STIX)
│   ├── static/                    # CSS stylesheets, Vanilla JS modules, icons
│   └── templates/                 # Jinja2 HTML templates
├── config.py                      # Development, Testing, and Production configurations
├── deploy/                        # Production deployment configurations
│   └── nginx/tip-ssl.conf         # Production Nginx reverse-proxy & TLS termination config
├── tests/                         # Automated test suite (23 modules, 380 tests)
│   ├── test_e2e_full_journey.py   # Comprehensive multi-user End-to-End test suite
│   ├── test_security_hardening.py # Baseline CSRF, Rate limit, CSP, HSTS test suite
│   ├── test_siem_api_security_hardening.py # Webhook signature, anti-replay, and RBAC tests
│   └── ...                        # Additional feature-specific test suites
├── .env.example                   # Clean template for environment variables
├── requirements.txt               # Pinned Python package dependencies
├── run.py                         # Application entrypoint
└── README.md                      # Platform documentation
```

---

## 🛠️ Installation & Setup Guide

### 1. Prerequisites
- **Python:** 3.12 or newer
- **Database:** MySQL 8.0+ running locally or in Docker
- **Redis (Optional for dev, recommended for multi-worker prod):** Redis 6.0+

### 2. Clone and Setup Virtual Environment
```bash
# Clone the repository
git clone <repository_url>
cd "cybser security"

# Create a virtual environment
python -m venv .venv

# Activate virtual environment
# Windows (PowerShell):
.venv\Scripts\Activate.ps1
# Linux / macOS:
source .venv/bin/activate

# Install required dependencies
pip install -r requirements.txt
```

### 3. Configure Environment Variables
Copy `.env.example` to `.env` and configure your credentials:
```bash
cp .env.example .env
```
Key configuration parameters inside `.env`:
```ini
# Generate a strong 64-character secret
SECRET_KEY=generate_with_python_secrets_token_hex_32

# Inbound SIEM Webhook Key & HMAC Secret
SIEM_WEBHOOK_API_KEY=generate_with_python_secrets_token_hex_32
SIEM_WEBHOOK_SECRET=generate_with_python_secrets_token_hex_32
SIEM_WEBHOOK_REQUIRE_SIGNATURE=True

# Database Credentials
DB_USERNAME=root
DB_PASSWORD=your_mysql_password
DB_HOST=localhost
DB_PORT=3306
DB_NAME=threat_intelligence_db

# Security & Proxy Settings
ENABLE_HSTS=True
BEHIND_PROXY=True
RATELIMIT_STORAGE_URI=redis://localhost:6379/0
```

### 4. Initialize Database
```bash
# Apply database migrations
flask db upgrade
```

### 5. Rotate Credentials & Setup Admin
Run the built-in management CLI command to inspect and rotate credentials:
```bash
# Audit database for default test keys or dummy accounts
flask audit-production-credentials

# Rotate admin password and generate live API key
flask rotate-production-credentials --username deepak
```

---

## ⌨️ CLI Management Commands

The platform includes administrative CLI commands via `flask`:

| Command | Description |
|---|---|
| `flask audit-production-credentials` | Audits the database for static test keys, unhashed credentials, and dummy dev accounts. |
| `flask rotate-production-credentials [--username <admin>]` | Rotates admin password, invalidates active sessions, and provisions a production API key. |
| `flask expire-iocs [--dry-run] [--days <ttl>]` | Evaluates active threat indicators against configured TTL policies and expires aged IOCs. |
| `flask ioc-expiry-stats` | Displays real-time breakdown of active, expired, and pending expiration indicators. |

---

## 🏃 Running the Application

### Development Server
```bash
python run.py
```
*Application runs at:* `http://127.0.0.1:5000`

### Production WSGI (Gunicorn / Waitress)
For multi-worker production deployments:
```bash
# Linux (Gunicorn with 4 workers behind Nginx):
gunicorn --workers 4 --bind 127.0.0.1:5000 run:app

# Windows (Waitress):
waitress-serve --listen=127.0.0.1:5000 run:app
```

---

## 🧪 Automated Testing Suite

The repository contains **380 automated tests** covering unit, integration, security hardening, and complete multi-user end-to-end journeys.

```bash
# Run the entire test suite across all 23 modules
python -m unittest discover -s tests

# Run the comprehensive End-to-End (E2E) full journey suite
python -m unittest tests/test_e2e_full_journey.py

# Run dedicated SIEM Webhook & API security hardening suite
python -m unittest tests/test_siem_api_security_hardening.py

# Run general security hardening suite (CSRF, Rate limits, Headers)
python -m unittest tests/test_security_hardening.py
```
*Current test pass rate:* **380 / 380 Passed (100% Success, 0 Failures, 0 Errors).**

---

## 🔌 REST API & Webhooks

### 1. Interactive OpenAPI / Swagger Documentation
Navigate to `http://127.0.0.1:5000/api/v2/docs` to view the full interactive OpenAPI 3.0.3 specification.

### 2. Inbound SIEM Webhook Alert Ingestion
- **Endpoint:** `POST /api/v1/webhook/alert`
- **Headers:**
  - `Content-Type: application/json`
  - `X-API-Key: <your_siem_webhook_key>`
  - `X-Webhook-Signature: sha256=<hmac_sha256_hex>`
  - `X-Webhook-Timestamp: <epoch_seconds>`

**Example cURL:**
```bash
curl -X POST "http://127.0.0.1:5000/api/v1/webhook/alert" \
  -H "Content-Type: application/json" \
  -H "X-API-Key: your_siem_webhook_key" \
  -H "X-Webhook-Signature: sha256=computed_hmac_sha256_hash" \
  -H "X-Webhook-Timestamp: 1731845400" \
  -d '{
    "title": "Suspicious C2 Beacon Detected",
    "source": "Splunk ES",
    "severity": "High",
    "description": "Outbound HTTP connection observed to malicious C2 198.51.100.45"
  }'
```

### 3. Firewall & Sensor Blocklists
- `GET /api/v1/feed/blocklist/plain` — Plaintext IP feed (one per line)
- `GET /api/v1/blocklist/csv` — CSV formatted indicator blocklist
- `GET /api/v1/blocklist/suricata` — Suricata / Snort drop rules
- `GET /api/v1/blocklist/rpz` — DNS Response Policy Zone format
- `GET /api/v1/stix/bundle` — STIX 2.1 JSON bundle export

---

## 🚀 Production Deployment Guide

A production-ready Nginx configuration file with TLS termination and security headers is available in:
[`deploy/nginx/tip-ssl.conf`](deploy/nginx/tip-ssl.conf)

### Deployment Steps:
1. Copy `deploy/nginx/tip-ssl.conf` to `/etc/nginx/sites-available/tip.conf`.
2. Update `server_name` with your actual domain or IP.
3. Configure SSL certificates via Let's Encrypt / Certbot:
   ```bash
   sudo certbot --nginx -d tip.yourdomain.com
   ```
4. Verify Nginx configuration and reload:
   ```bash
   sudo nginx -t && sudo systemctl reload nginx
   ```
5. Start Gunicorn as a systemd background service.

---

## 📄 License & Maintainer
- **Developed for:** Enterprise Threat Intelligence & Incident Response.
- **Maintainer:** SecOps Engineering Team.
