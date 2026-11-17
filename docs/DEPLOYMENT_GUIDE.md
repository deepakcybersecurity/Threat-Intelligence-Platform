# Production Deployment & Operations Guide

This guide covers the production deployment of the Flask Threat Intelligence Platform (TIP) using **Nginx**, **Gunicorn**, **systemd**, **MySQL 8**, and **Redis**.

---

## 1. Production Architecture

```
[ External Clients / SIEM Forwarders / Analysts ]
                        │
                        ▼ (HTTPS : 443)
              ┌───────────────────┐
              │   Nginx Ingress   │  <- TLS Termination, HSTS, Rate Limiting, Static Assets
              └─────────┬─────────┘
                        │ (HTTP : 5000 / Unix Socket)
                        ▼
              ┌───────────────────┐
              │ Gunicorn WSGI Srv │  <- Multi-worker Python processes (4 workers)
              └─────────┬─────────┘
                        │
       ┌────────────────┴────────────────┐
       ▼                                 ▼
┌──────────────┐                 ┌───────────────┐
│ MySQL 8.x DB │                 │ Redis Storage │  <- Shared Rate Limiting Backend
└──────────────┘                 └───────────────┘
```

---

## 2. Server Prerequisites

- **OS:** Ubuntu 22.04 LTS or Debian 12 (recommended)
- **CPU / RAM:** Minimum 2 vCPU, 4GB RAM (8GB recommended for high-volume SIEM feeds)
- **Storage:** 50GB+ SSD storage
- **Packages:**
  ```bash
  sudo apt update && sudo apt install -y python3.12 python3.12-venv python3-pip mysql-server redis-server nginx certbot python3-certbot-nginx libmysqlclient-dev pkg-config
  ```

---

## 3. Database & Redis Setup

### MySQL Database Setup
```bash
sudo mysql -u root
```
```sql
CREATE DATABASE threat_intelligence_db CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
CREATE USER 'tip_user'@'localhost' IDENTIFIED BY 'StrongRandomDbPassword2026!';
GRANT ALL PRIVILEGES ON threat_intelligence_db.* TO 'tip_user'@'localhost';
FLUSH PRIVILEGES;
EXIT;
```

### Redis Server Configuration
Ensure Redis is active and enabled:
```bash
sudo systemctl enable redis-server
sudo systemctl start redis-server
redis-cli ping  # Should return PONG
```

---

## 4. Application Installation

```bash
# Clone application into /var/www/tip
sudo mkdir -p /var/www/tip
sudo chown -R $USER:$USER /var/www/tip
git clone <repository_url> /var/www/tip
cd /var/www/tip

# Create Python 3.12 Virtual Environment
python3.12 -m venv .venv
source .venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt
pip install gunicorn
```

---

## 5. Production Environment Variables (`.env`)

Create `/var/www/tip/.env`:
```ini
FLASK_ENV=production
FLASK_DEBUG=False

# Cryptographically Secure Secrets (Generate with python -c "import secrets; print(secrets.token_hex(32))")
SECRET_KEY=3f3ea2b0b9964f77459472cd1970bd2b0d02b96e8647eeaf7611254cea6437eb
SIEM_WEBHOOK_API_KEY=d96dc1a7939c9750d7e34b7ffbc402e92ff1d20d405b17e376755da989f4046a
SIEM_WEBHOOK_SECRET=a67c0a85b3cc47c65b1e1df9935ae4ad189d121b36ac41261b2b1137cf686b3d
SIEM_WEBHOOK_REQUIRE_SIGNATURE=True

# Database Configuration
DB_USERNAME=tip_user
DB_PASSWORD=StrongRandomDbPassword2026!
DB_HOST=localhost
DB_PORT=3306
DB_NAME=threat_intelligence_db

# Security & Proxy Settings
ENABLE_HSTS=True
BEHIND_PROXY=True
RATELIMIT_ENABLED=True
RATELIMIT_STORAGE_URI=redis://localhost:6379/0
```

Lock permissions so only the application user can read `.env`:
```bash
chmod 600 /var/www/tip/.env
```

Initialize database tables and migrations:
```bash
flask db upgrade
flask rotate-production-credentials --username deepak
```

---

## 6. Systemd Service Setup (`tip.service`)

Create `/etc/systemd/system/tip.service`:
```ini
[Unit]
Description=Threat Intelligence Platform (TIP) Gunicorn Service
After=network.target mysql.service redis-server.service

[Service]
User=www-data
Group=www-data
WorkingDirectory=/var/www/tip
Environment="PATH=/var/www/tip/.venv/bin"
EnvironmentFile=/var/www/tip/.env
ExecStart=/var/www/tip/.venv/bin/gunicorn \
    --workers 4 \
    --threads 2 \
    --bind 127.0.0.1:5000 \
    --access-logfile /var/log/tip/access.log \
    --error-logfile /var/log/tip/error.log \
    --timeout 60 \
    run:app

Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
```

Enable and start the service:
```bash
sudo mkdir -p /var/log/tip
sudo chown -R www-data:www-data /var/log/tip
sudo systemctl daemon-reload
sudo systemctl enable tip
sudo systemctl start tip
sudo systemctl status tip
```

---

## 7. Nginx & SSL Configuration

1. Copy the provided Nginx configuration:
   ```bash
   sudo cp /var/www/tip/deploy/nginx/tip-ssl.conf /etc/nginx/sites-available/tip.conf
   sudo ln -s /etc/nginx/sites-available/tip.conf /etc/nginx/sites-enabled/
   ```
2. Obtain SSL certificate via Let's Encrypt:
   ```bash
   sudo certbot --nginx -d tip.yourdomain.com
   ```
3. Test and reload Nginx:
   ```bash
   sudo nginx -t
   sudo systemctl reload nginx
   ```

---

## 8. Scheduled Maintenance (Cron Jobs)

Set up a root cron job (`sudo crontab -e`) to automate IOC expiration:
```cron
# Run automated IOC TTL expiration every night at 02:00 AM
0 2 * * * cd /var/www/tip && .venv/bin/flask expire-iocs >> /var/log/tip/ioc-expiry.log 2>&1
```

---

## 9. Verification & Health Monitoring

```bash
# Check application status endpoint
curl -s https://tip.yourdomain.com/api/status | jq .
# Expected output: {"status": "operational", ...}

# View live system logs
journalctl -u tip -f
```
