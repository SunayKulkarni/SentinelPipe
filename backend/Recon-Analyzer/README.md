# Recon-Analyzer

Recon-Analyzer is a Flask-based threat intelligence and OSINT microservice. It accepts IPs, domains, emails, phone numbers, and usernames and returns structured intelligence data — used as part of the **SecFlow** automated threat analysis pipeline.

---

## 🚀 Features

- **IP & Domain Threat Intel (`/scan`)**: Geolocation, Cisco Talos blocklist, Tor exit node check, Tranco domain ranking, ThreatFox IOC lookup.
- **Digital Footprint OSINT (`/footprint`)**: Email breach exposure (XposedOrNot), phone number validation (NumVerify), and username search across social platforms (Sagemode multithreaded scraper).
- **Auto-type detection**: Input type (IP / domain / email / phone / username) is detected automatically — no separate endpoint per type.
- **Self-updating local databases**: Talos and Tor blocklists are downloaded automatically on first use.

---

## 🛠️ Installation

### Option 1 — Docker (recommended)

```bash
cd backend/Recon-Analyzer
docker compose up --build
```

Service will be available at `http://localhost:5003`.

### Option 2 — Local (Python 3.12+)

```bash
cd backend/Recon-Analyzer
pip install -r requirements.txt
cp .env.example .env   # add API keys
cd src
python main.py
```

Service will be available at `http://localhost:5000`.

### Environment variables (`.env`)

| Variable | Used by | Required? |
|---|---|---|
| `NUMVERIFY_API_KEY` | Phone validation | Optional |
| `THREATFOX_API_KEY` | ThreatFox IOC lookup | Optional |
| `ipAPI_KEY` | IP geolocation | Optional |

---

## ▶️ Usage

### API Prefix

All endpoints are available with or without the prefix:
- With prefix: `/api/Recon-Analyzer/<route>` (**capital R and A — required in production**)
- Without prefix: `/<route>` (for local dev)

---

### Endpoints

#### `GET /api/Recon-Analyzer/health`
Health check.
```bash
curl http://localhost:5003/api/Recon-Analyzer/health
# {"status": "healthy"}
```

---

#### `GET /api/Recon-Analyzer/`
Lists all available endpoints.
```bash
curl http://localhost:5003/api/Recon-Analyzer/
```

---

#### `POST /api/Recon-Analyzer/scan`
Scan an **IP address or domain** for threat intelligence.

Request body key is `query` (not `target`, not `url`):
```json
{"query": "8.8.8.8"}
```
or
```json
{"query": "example.com"}
```

**Auto-detection:**
- Valid IPv4 → runs geolocation, Talos blocklist, Tor exit check
- Valid domain → resolves IP, runs all IP checks + Tranco ranking + ThreatFox IOC
- Invalid format → `400 {"error": "Invalid IP or domain format."}`

**Response — IP:**
```json
{
  "query": "8.8.8.8",
  "ipapi": {
    "ip_info": [{"status": "success", "country": "United States", "isp": "Google LLC", "as": "AS15169 Google LLC", ...}],
    "dns_info": {"dns": {"ip": "...", "geo": "..."}, ...}
  },
  "talos": {"blacklisted": false},
  "tor":   {"is_tor_exit": false}
}
```

**Response — Domain** (adds `tranco` and `threatfox`):
```json
{
  "query": "google.com",
  "ipapi":    { ... },
  "talos":    {"blacklisted": false},
  "tor":      {"is_tor_exit": false},
  "tranco":   {"found": true, "rank": 1},
  "threatfox": {"found": false}
}
```

```bash
# curl examples
curl -X POST http://localhost:5003/api/Recon-Analyzer/scan \
  -H "Content-Type: application/json" \
  -d '{"query": "8.8.8.8"}'

curl -X POST http://localhost:5003/api/Recon-Analyzer/scan \
  -H "Content-Type: application/json" \
  -d '{"query": "google.com"}'
```

---

#### `POST /api/Recon-Analyzer/footprint`
Digital footprint analysis for **email, phone number, or username**.

Request body key is `query` — type is detected automatically:
```json
{"query": "user@example.com"}
```
or
```json
{"query": "+14155552671"}
```
or
```json
{"query": "johndoe"}
```

**Auto-detection logic:**
- Matches email regex → email breach scan via XposedOrNot
- Matches phone regex (`+?` digits, max 15) → phone validation via NumVerify
- Neither → username search via Sagemode (multithreaded scraper, 15s timeout per site)

**Response — Email:**
```json
{
  "query": "user@example.com",
  "type": "email",
  "email_scan": {
    "exposed": true,
    "breach_count": 3,
    "breaches": [{"breach": "Adobe", "domain": "adobe.com", "xposed_data": "Emails, Passwords", ...}],
    "password_strength": [{"EasyToCrack": 2, "StrongHash": 1}],
    "risk": [{"risk_label": "High Risk", "risk_score": 8}]
  }
}
```

**Response — Phone:**
```json
{
  "query": "+14155552671",
  "type": "phone",
  "phone_scan": {
    "valid": true,
    "country_code": "US",
    "country_name": "United States",
    "location": "California",
    "carrier": "AT&T",
    "line_type": "mobile"
  }
}
```

**Response — Username:**
```json
{
  "query": "johndoe",
  "type": "username",
  "username_scan": [
    {"site": "GitHub", "url": "https://github.com/johndoe"},
    {"site": "Twitter", "url": "https://twitter.com/johndoe"}
  ]
}
```

```bash
# curl examples
curl -X POST http://localhost:5003/api/Recon-Analyzer/footprint \
  -H "Content-Type: application/json" \
  -d '{"query": "test@example.com"}'

curl -X POST http://localhost:5003/api/Recon-Analyzer/footprint \
  -H "Content-Type: application/json" \
  -d '{"query": "johndoe"}'
```

---


## 🤝 Contributing

We welcome contributions! Follow these steps to contribute:

1. Fork the repository.
2. Create a new branch: `git checkout -b feature/your-feature`.
3. Commit your changes: `git commit -m "Add new feature"`.
4. Push to the branch: `git push origin feature/your-feature`.
5. Submit a pull request.

Please ensure your code follows the existing style and includes tests where applicable.

---

## 📜 License

This project is licensed under the **MIT License**. See the [LICENSE](LICENSE) file for more details.

---

**Recon-Analyzer** — Threat intelligence and OSINT for the SecFlow pipeline. 🌐
