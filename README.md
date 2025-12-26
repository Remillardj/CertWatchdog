# CertWatchdog 🐕

A Python-based SSL/TLS health checker with both CLI and web UI modes. Scan domains for certificate and TLS configuration issues, configure severity thresholds, and receive alerts when problems are detected.

# Demo
Visit [CertWatchdog website[(https://certwatchdog.com/).

## Features

- **5 Comprehensive Checks**: Certificate expiry, chain validation, protocol versions, cipher strength, hostname verification
- **Configurable Severity Thresholds**: Define what constitutes critical, warning, or informational issues
- **Beautiful CLI Output**: Color-coded results with Rich formatting
- **Web Dashboard**: FastAPI + HTMX powered interface for browser-based scanning
- **Webhook Alerts**: Slack-compatible notifications for critical issues

## Installation

```bash
# Clone the repository
git clone https://github.com/yourusername/certwatchdog.git
cd certwatchdog

# Create virtual environment and install
python3 -m venv .venv && source .venv/bin/activate
pip install -e .
```

## Quick Start

### CLI Usage

```bash
# Single domain check
certwatchdog check example.com

# JSON output
certwatchdog check example.com --json

# Check multiple domains from file
certwatchdog check --file domains.txt

# Custom port
certwatchdog check example.com --port 8443
```

### Web UI

```bash
# Start the web server
certwatchdog serve

# Custom host/port
certwatchdog serve --host 0.0.0.0 --port 8080
```

Then open http://localhost:8000 in your browser.

### Configuration

```bash
# Generate example config
certwatchdog config init

# Validate config file
certwatchdog config validate config.yaml
```

## Configuration

CertWatchdog uses YAML configuration for severity thresholds and alerting:

```yaml
severity:
  critical:
    cert_expiry_days: 7
    protocols:
      - "SSLv2"
      - "SSLv3"
      - "TLSv1.0"
    weak_ciphers: true
    chain_invalid: true
    hostname_mismatch: true
  
  warning:
    cert_expiry_days: 30
    protocols:
      - "TLSv1.1"
  
  info:
    cert_expiry_days: 60

alerting:
  enabled: true
  min_severity: warning
  
  webhook:
    enabled: true
    url: "https://hooks.slack.com/services/<placeholder>"
```

## Checks Performed

| Check | Description |
|-------|-------------|
| **Certificate Expiry** | Days until certificate expires |
| **Chain Validation** | Verifies complete certificate chain |
| **Protocol Support** | Detects deprecated TLS/SSL versions |
| **Cipher Strength** | Identifies weak cipher suites |
| **Hostname Match** | Verifies certificate matches domain |

## Example CLI Output

```
$ certwatchdog check github.com

🔍 Scanning github.com:443...

╭──────────────────────── github.com Overall: 🟢 OK ─────────────────────────╮
│                                                                            │
│    ✅     Certificate Expiry      Expires in 42 days                       │
│    ✅     Chain Validation        Chain verified (Sectigo Limited)         │
│    ✅     Protocol Support        Only modern protocols (TLS 1.2+)         │
│    ✅     Cipher Strength         Strong cipher: TLS_AES_128_GCM_SHA256    │
│    ✅     Hostname Match          Certificate matches domain               │
│                                                                            │
╰────────────────────────────────────────────────────────────────────────────╯

Certificate: github.com
Issuer: Sectigo ECC Domain Validation Secure Server CA
Expires: 2026-02-05 23:59:59 UTC
```

## API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/` | GET | Web dashboard |
| `/scan` | POST | Perform scan (HTMX) |
| `/settings` | GET | Settings page |
| `/settings/save` | POST | Save settings |
| `/api/scan/{domain}` | GET | JSON API for scanning |
| `/api/settings` | GET | Get current settings |
| `/health` | GET | Health check |

## License
Copyright (c) 2025 Jaryd Remillard. All rights reserved.

This software is licensed for personal, non-commercial use only. You may use and modify the software for private purposes, but distribution is prohibited.

Key restrictions:

✅ Personal use allowed

✅ Modifications for personal use allowed

❌ No distribution of original or modified versions

❌ No commercial use

Commercial licensing: For commercial use or distribution rights, contact jaryd.remillard@gmail.com

See the LICENSE file for full terms.
