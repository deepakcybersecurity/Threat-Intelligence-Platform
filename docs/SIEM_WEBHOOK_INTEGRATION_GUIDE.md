# SIEM & EDR Webhook Integration Technical Guide

This guide details how to integrate enterprise SIEMs (Splunk, Microsoft Sentinel, Elastic) and EDRs (CrowdStrike Falcon, Microsoft Defender for Endpoint) with the Threat Intelligence Platform (TIP) using secure, authenticated HTTP webhooks.

---

## 1. Webhook Endpoints

| Ingestion Purpose | Method | Endpoint Path | Content-Type |
|---|---|---|---|
| **General SIEM Alert Ingestion** | `POST` | `/api/v1/webhook/alert` | `application/json` |
| **Dedicated EDR Telemetry Ingestion** | `POST` | `/api/v1/edr/alert` | `application/json` |
| **Real-Time IOC Reputation Lookup** | `POST` | `/api/v1/ioc/lookup` | `application/json` |

---

## 2. Authentication & Integrity Headers

All inbound webhook requests must include the following headers:

| Header Name | Type | Description |
|---|---|---|
| `Content-Type` | String | Must be strictly `application/json`. |
| `X-API-Key` | String | Either the system `SIEM_WEBHOOK_API_KEY` or an analyst's personal API key (`tip_live_...`). |
| `X-Webhook-Signature` | String | Cryptographic signature formatted as `sha256=<hex_digest>`. |
| `X-Webhook-Timestamp` | Integer | Current epoch timestamp in seconds (must be within **±300 seconds** of server time). |

---

## 3. Cryptographic Signature Calculation (HMAC-SHA256)

To prevent tampering and replay attacks:

1. Obtain the shared secret (`SIEM_WEBHOOK_SECRET`).
2. Generate current epoch timestamp: `timestamp = str(int(time.time()))`.
3. Concatenate the timestamp, a dot delimiter, and the raw UTF-8 JSON body:
   $$\text{payload\_to\_sign} = \text{timestamp} + "." + \text{raw\_json\_body}$$
4. Compute the HMAC-SHA256 hash using the secret:
   $$\text{signature} = \text{HMAC-SHA256}(\text{secret}, \text{payload\_to\_sign})$$
5. Format the header as:
   `X-Webhook-Signature: sha256=<signature_hex>`

---

## 4. Code Examples for Upstream Forwarders

### Python (Requests)
```python
import hashlib
import hmac
import json
import time
import requests

SERVER_URL = "https://tip.yourdomain.com/api/v1/webhook/alert"
API_KEY = "your_configured_siem_webhook_api_key"
SIGNING_SECRET = "your_configured_siem_webhook_secret"

payload = {
    "title": "Malicious Cobalt Strike Beacon Detected",
    "source": "Splunk Enterprise Security",
    "severity": "Critical",
    "description": "Outbound DNS beaconing detected to known C2 domain malicious-c2-domain.com",
    "external_id": "SPLUNK-INC-2026-9041",
    "tactics": ["Command and Control"],
}

raw_body = json.dumps(payload).encode("utf-8")
timestamp = str(int(time.time()))

# Compute HMAC signature: HMAC(secret, timestamp + "." + raw_body)
payload_to_sign = f"{timestamp}.".encode("utf-8") + raw_body
signature = hmac.new(SIGNING_SECRET.encode("utf-8"), payload_to_sign, hashlib.sha256).hexdigest()

headers = {
    "Content-Type": "application/json",
    "X-API-Key": API_KEY,
    "X-Webhook-Signature": f"sha256={signature}",
    "X-Webhook-Timestamp": timestamp,
}

response = requests.post(SERVER_URL, data=raw_body, headers=headers)
print("Status:", response.status_code)
print("Response:", response.json())
```

### Node.js / JavaScript
```javascript
const crypto = require('crypto');
const axios = require('axios');

const serverUrl = 'https://tip.yourdomain.com/api/v1/webhook/alert';
const apiKey = 'your_configured_siem_webhook_api_key';
const secret = 'your_configured_siem_webhook_secret';

const payload = {
  title: 'Ransomware Artifact Identified',
  source: 'Microsoft Defender for Endpoint',
  severity: 'High',
  description: 'Suspicious executable dropped in %TEMP% with SHA256 e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'
};

const rawBody = JSON.stringify(payload);
const timestamp = Math.floor(Date.now() / 1000).toString();

const hmac = crypto.createHmac('sha256', secret);
hmac.update(`${timestamp}.${rawBody}`);
const signature = hmac.digest('hex');

axios.post(serverUrl, rawBody, {
  headers: {
    'Content-Type': 'application/json',
    'X-API-Key': apiKey,
    'X-Webhook-Signature': `sha256=${signature}`,
    'X-Webhook-Timestamp': timestamp
  }
}).then(res => {
  console.log('Success:', res.data);
}).catch(err => {
  console.error('Error:', err.response ? err.response.data : err.message);
});
```

---

## 5. Webhook Response Formats

### Successful Ingestion (HTTP 201 Created)
```json
{
  "success": true,
  "message": "SIEM/EDR alert ingested and analyzed successfully",
  "alert": {
    "id": 1420,
    "title": "[SIEM/EDR Ingest] Malicious Cobalt Strike Beacon Detected",
    "severity": "Critical",
    "status": "Open",
    "alert_type": "SIEM/EDR",
    "created": true
  },
  "total_iocs_found": 1,
  "indicators": ["malicious-c2-domain.com"],
  "indicators_created": 1,
  "indicators_reused": 0,
  "max_risk_score": 85.0,
  "source": "Splunk Enterprise Security"
}
```

### Invalid Signature (HTTP 401 Unauthorized)
```json
{
  "success": false,
  "error": "InvalidSignature",
  "message": "Invalid webhook HMAC signature"
}
```

### Expired Timestamp / Replay Window (HTTP 401 Unauthorized)
```json
{
  "success": false,
  "error": "InvalidSignature",
  "message": "Webhook timestamp is outside the allowed 300-second replay window"
}
```
