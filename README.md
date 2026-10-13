# webpent

Web application pentest helper — probes for reflected XSS, SQL injection (error + boolean based), SSRF, open redirect, and security-header misconfigurations, with JSON and Markdown report output.

> **Authorized testing only.** Only run this against systems you own or have written permission to assess.

## Install

```bash
pip install -r requirements.txt
```

## Usage

```bash
# Scan a URL's query parameters + response headers
python -m webpent "https://target.example/search?q=test"

# POST body parameters
python -m webpent "https://target.example/login" -d "user=admin&pass=test"

# Specific probes, through Burp, with reports
python -m webpent "https://target.example/page?id=1" \
  --probes sqli,xss --proxy http://127.0.0.1:8080 \
  -o report

# With session cookie and rate limiting
python -m webpent "https://target.example/account?file=x" \
  --cookie "sid=abc123" --delay 0.5 --json out.json --md out.md
```

### Options

| Flag | Description |
|---|---|
| `--probes` | `all` (default) or comma list: `headers,xss,sqli,ssrf,redirect` |
| `-d/--data` | POST body (`key=value&...`), implies POST |
| `--timeout` | Request timeout (default 10s) |
| `--delay` | Delay between requests (rate-limit friendliness) |
| `-k/--insecure` | Skip TLS verification |
| `--cookie` | Cookie header value |
| `--proxy` | Route traffic through a proxy (e.g. Burp) |
| `-o PREFIX` | Write `PREFIX.json` + `PREFIX.md` |
| `--json PATH` / `--md PATH` | Individual report outputs |
| `-v` | Verbose logging |

Exit code: `1` if findings exist, `0` if clean — CI-friendly.

## Probes

| Probe | Detects | Severity |
|---|---|---|
| `headers` | Missing HSTS/CSP/XFO/nosniff, cookie flags, server disclosure | INFO–MEDIUM |
| `xss` | Unencoded reflection of injected canary payloads | HIGH |
| `sqli` | DB error messages in response, boolean TRUE/FALSE content divergence | HIGH–CRITICAL |
| `ssrf` | URL params fetching attacker canary / cloud metadata / loopback bypasses | HIGH–CRITICAL |
| `redirect` | 3xx `Location` pointing at attacker domain | MEDIUM |

## Local demo target

A deliberately vulnerable server for testing the tool:

```bash
python testsite.py        # listens on http://127.0.0.1:8000
python -m webpent "http://127.0.0.1:8000/search?q=test" -o demo
```

## Project layout

```
webpent/
├── cli.py               # argparse entrypoint
├── report.py            # JSON / Markdown / console output
├── core/
│   ├── http.py          # session, retries, proxy, rate limit
│   ├── models.py        # Finding / ScanResult / Severity
│   └── targets.py       # URL & parameter manipulation
└── probes/
    ├── headers.py
    ├── xss.py
    ├── sqli.py
    ├── ssrf.py
    └── redirect.py
```

## Disclaimer

This tool is for defensive security testing and authorized engagements. Misuse against systems without permission is prohibited.
