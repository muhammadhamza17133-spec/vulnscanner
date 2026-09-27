# VulnScanner

A lightweight network vulnerability scanner written in pure Python — no external dependencies required.

## What it does

- Multithreaded TCP port scanning
- Service fingerprinting via banner grabbing
- Signature-based checks against a small embedded vulnerability database
- Web security checks (missing security headers, exposed sensitive paths, cookie flags, CORS issues)
- TLS/SSL checks (certificate validity, expiry, weak ciphers, legacy protocol support)
- Reports in console, JSON, HTML, and CSV formats

## Usage

```bash
python vulnscanner.py -t 127.0.0.1 -p 1-1024 --web --ssl -y
```

Save an HTML report:

```bash
python vulnscanner.py -t 127.0.0.1 -p 1-1024 --web --ssl -o report.html -y
```

## Requirements

Python 3.8+. No third-party packages needed.

## ⚠️ Important

Only scan systems you own or have explicit written permission to test. Unauthorized scanning is illegal in most countries.

## Author

Muhammad Hamza Khan
