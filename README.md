# PhishGuard: CTI Phishing URL Intelligence Platform

PhishGuard is a Cyber Threat Intelligence project focused on suspicious URL and domain analysis, IOC extraction, risk scoring, dashboarding, and report export. It is designed for a university CTI project demo and runs without paid API keys.

## Features

- Analyze suspicious URLs and domains, one or many at a time.
- Detect phishing signals: no HTTPS, IP hosts, punycode, risky TLDs, URL shorteners, suspicious keywords, brand impersonation, redirect parameters, deep paths, encoded characters, and abnormal length.
- Extract supporting IOCs from submitted text: URLs, domains, IPs, hashes, and CVEs.
- Optional free/public enrichment:
  - URLHaus community lookup: https://urlhaus.abuse.ch/api/
  - CISA Known Exploited Vulnerabilities JSON: https://www.cisa.gov/known-exploited-vulnerabilities-catalog
- Advanced passive intelligence:
  - RDAP/domain age lookup for creation date, registrar, expiry date, nameservers, and newly registered domain warnings.
  - DNS lookups for A, AAAA, MX, NS, and TXT records.
  - Redirect tracing without rendering suspicious pages.
  - Optional free API-key sources: VirusTotal, AbuseIPDB, AlienVault OTX, and urlscan.io.
- Optional active/dynamic analysis:
  - Submit URLs to urlscan.io for browser-based sandbox scanning when enabled.
  - Capture urlscan result links, screenshots, final page metadata, and observed downloads.
  - Extract downloaded file hashes and check those hashes with VirusTotal.
- Save all analyses to SQLite.
- Premium SOC dashboard with severity counts, average risk, source health, 7-day trend, recent activity, high-risk findings, and top domains.
- Export history as CSV.
- Export each investigation as JSON or printable HTML report.

## Setup

```powershell
cd "C:\Users\hamza\Downloads\cti project"
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
python -m uvicorn app.main:app --reload
```

Open:

```text
http://127.0.0.1:8000
```

## Test

```powershell
python -m pytest
```

## Web Deployment

PhishGuard is deploy-ready for Python web hosts that support FastAPI, including Render, Railway, Fly.io, and Docker-based hosts.

### Render from GitHub

1. Push this repository to GitHub.
2. In Render, create a new Blueprint or Web Service from the GitHub repository.
3. Use these settings if creating a Web Service manually:
   - Build command: `pip install -r requirements.txt`
   - Start command: `uvicorn app.main:app --host 0.0.0.0 --port $PORT`
   - Environment variable: `ENABLE_URLSCAN_SUBMISSION=false`
4. Optional API keys can be added as environment variables:
   - `VIRUSTOTAL_API_KEY`
   - `ABUSEIPDB_API_KEY`
   - `OTX_API_KEY`
   - `URLSCAN_API_KEY`

The app uses SQLite by default. On hosted platforms, analysis history persists only when the platform provides persistent storage for the configured `PHISHGUARD_DATA_DIR`.

### Docker

```powershell
docker build -t phishguard-cti .
docker run --rm -p 8000:8000 phishguard-cti
```

## Optional Free API Keys

The app works without API keys. To enable extra enrichment, copy `.env.example` to `.env` and add keys from free-tier accounts:

```powershell
Copy-Item .env.example .env
```

```text
VIRUSTOTAL_API_KEY=
ABUSEIPDB_API_KEY=
OTX_API_KEY=
URLSCAN_API_KEY=
ENABLE_URLSCAN_SUBMISSION=false
URLSCAN_VISIBILITY=unlisted
URLSCAN_INITIAL_WAIT_SECONDS=10
URLSCAN_POLL_INTERVAL_SECONDS=5
URLSCAN_POLL_TIMEOUT_SECONDS=45
```

Security rules:

- Do not commit `.env`.
- Do not paste keys into reports or screenshots.
- `ENABLE_URLSCAN_SUBMISSION=false` searches existing urlscan.io results without submitting the URL.
- `ENABLE_URLSCAN_SUBMISSION=true` actively submits the URL to urlscan.io for dynamic browser scanning. The app then extracts observed download hashes and checks them with VirusTotal. Use `URLSCAN_VISIBILITY=unlisted` or `private` when your account supports it to reduce exposure.

## Sample Inputs

Use `sample_inputs.txt` or click `Load Sample Data` in the sidebar. The main input should be a URL or domain.

```text
https://www.microsoft.com/security
http://login-microsoft-security-update.xyz/verify/account?redirect=http://192.168.10.20
http://paypal.com.account-verify-login.top/session/update
http://bit.ly/security-verification-login
paypal-login-check.xyz
verify-account-update.top
```

## CTI Value

PhishGuard supports tactical cyber threat intelligence by producing actionable indicators and analyst-ready reports. It helps a SOC or CTI analyst decide whether a suspicious URL or domain should be blocked, escalated, or monitored.

## Suggested Final Report Outline

1. Introduction and problem statement
2. Cyber Threat Intelligence background
3. Phishing URL threat model
4. System architecture
5. Passive enrichment methodology: RDAP, DNS, redirects, URLHaus, CISA KEV, optional APIs
6. Detection and scoring methodology
7. Screenshots and demo workflow
8. Testing and validation
9. Limitations and future work
10. Conclusion

## Demo Talking Points

- This is a passive CTI system for suspicious URLs/domains: it does not render or interact with malicious web pages.
- It explains every score with evidence, which is important for SOC analysts.
- It combines local heuristics, public no-key feeds, domain registration intelligence, DNS intelligence, redirect behavior, and optional free API-key reputation services.
- Reports are exportable for incident documentation or classroom submission.

## Project Structure

```text
app/
  analyzer.py      URL parsing, IOC extraction, and risk scoring
  enrichment.py    URLHaus and CISA KEV public enrichment
  domain_intel.py  RDAP/domain age intelligence
  dns_intel.py     DNS record enrichment
  redirects.py     Passive redirect tracing
  optional_sources.py VirusTotal, AbuseIPDB, OTX, urlscan.io integrations
  main.py          FastAPI routes and web pages
  models.py        SQLite models
  reports.py       CSV, JSON, and HTML report helpers
  static/          CSS and JavaScript
  templates/       Server-rendered dashboard pages
tests/             Backend tests
data/              SQLite database created at runtime
```

## Notes

- The app still works if public feed lookups fail.
- No paid API key is required.
- The SQLite database is created automatically at `data/phishguard.db`.
- Existing old reports still open, but only new scans include the advanced enrichment fields.
