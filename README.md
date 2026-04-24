# threatBlade

A CLI toolkit for SOC analysts to automate common investigation tasks — reputation checks, URL decoding, email analysis, breach lookups, and more.

## Features

| Module | What it does |
|---|---|
| Reputation Check | IP/Domain/URL/Hash lookup via VirusTotal + AbuseIPDB |
| URL Tools | Defang, refang, decode ProofPoint/SafeLinks/Base64, expand short URLs |
| DNS & WHOIS | A/MX/TXT/NS/CNAME/SOA records, WHOIS, reverse DNS |
| File Hash | MD5/SHA1/SHA256 hashing + VirusTotal hash reputation |
| Email Analyzer | Parse .eml files, extract IOCs, check SPF/DKIM, phishing indicators |
| Breach Check | HaveIBeenPwned email/domain lookup, safe password exposure check |
| IP Tools | GeoIP, Tor exit node check, DNSBL blacklist check |
| Templates | Generate phishing/malware/account-compromise response emails |

## Setup

```bash
cd threatBlade
pip install -r requirements.txt
```

### Web App (recommended)
```bash
python app.py
```
Open [http://localhost:5000](http://localhost:5000) in your browser.

### CLI
```bash
python threatblade.py
```

## API Keys

On first run, go to **Settings (option 9)** to add your API keys:

| Key | Where to get it |
|---|---|
| VirusTotal | https://www.virustotal.com/gui/my-apikey |
| AbuseIPDB | https://www.abuseipdb.com/account/api |
| HIBP | https://haveibeenpwned.com/API/Key |
| URLScan.io | https://urlscan.io/user/profile/ |

Keys are stored locally in `config/keys.json`.

## Usage

```
python threatblade.py
```

Navigate the menu with number keys. No CLI flags required — fully interactive.
