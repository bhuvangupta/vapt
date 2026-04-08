# VAPT Test Suite

> **EXPERIMENTAL PROJECT** — This tool is under active development. It has not been audited by a third party and may produce false positives, miss real vulnerabilities, or behave unexpectedly against certain targets. Do not rely on it as your sole security assessment. Always complement automated results with manual penetration testing by qualified security professionals. Use at your own risk.

Standalone Vulnerability Assessment & Penetration Testing toolkit for web applications. Produces professional reports (HTML + PDF) with automated security scanning. No AI or cloud dependency — your QA team runs everything locally.

---

## Table of Contents

- [Prerequisites](#prerequisites)
- [Setup](#setup)
- [Configuration](#configuration)
- [Running Scans](#running-scans)
- [CLI Reference](#cli-reference)
- [Scanner Categories](#scanner-categories)
- [Understanding Reports](#understanding-reports)
- [Security Posture Score](#security-posture-score)
- [External Tools (Optional)](#external-tools-optional)
- [Project Structure](#project-structure)
- [Troubleshooting](#troubleshooting)
- [Authorization & Legal](#authorization--legal)

---

## Prerequisites

| Requirement | Minimum Version | Check Command |
|-------------|----------------|---------------|
| Python | 3.10+ | `python3 --version` |
| pip | any | `pip3 --version` |
| OpenSSL | any (usually pre-installed) | `openssl version` |
| dig | any (usually pre-installed) | `dig -v` |
| curl | any (usually pre-installed) | `curl --version` |

> Python 3.10+ is required for `match` statements and `X | Y` type union syntax used throughout the codebase.

---

## Setup

### Step 1: Clone / Navigate to the project

```bash
cd /path/to/vapt
```

### Step 2: Create a Python virtual environment

```bash
python3 -m venv .venv
```

### Step 3: Activate the virtual environment

```bash
# macOS / Linux
source .venv/bin/activate

# Windows (PowerShell)
.venv\Scripts\Activate.ps1

# Windows (CMD)
.venv\Scripts\activate.bat
```

You should see `(.venv)` in your terminal prompt.

### Step 4: Install Python dependencies

```bash
pip install -r requirements.txt
```

This installs:

| Package | Purpose |
|---------|---------|
| `httpx` | Async HTTP client (with HTTP/2 support) |
| `pyyaml` | Config file parsing |
| `jinja2` | HTML report templating |
| `rich` | Colored terminal output, progress bars, tables |
| `reportlab` | PDF report generation |

### Step 5: Verify installation

```bash
python run_vapt.py --version
# Output: vapt 1.0.0
```

```bash
python run_vapt.py --config config.yaml --dry-run
```

This should display:
- The VAPT banner
- Tool detection results (which external tools are available)
- Target count and scanner list
- No actual scanning is performed

---

## Configuration

All scan settings are controlled via `config.yaml`. Copy and edit the default config for your needs.

### Minimal config

```yaml
targets:
  - url: https://www.example.com
    name: "My Website"

settings:
  timeout: 10
  rate_limit: 2

reporting:
  formats: [html, pdf]
  output_dir: ./reports

authorization:
  basis: "own_infra"
  authorized_by: "QA Team"
  ref: "VAPT-2026-001"
```

### Full config with bearer token authentication

Use this when your app uses Google login, SSO, or any OAuth/JWT flow where
you cannot automate form login. Log in manually in a browser, copy the token
from DevTools (Network tab → any API request → Authorization header), and
set it as an environment variable.

```yaml
targets:
  - url: https://www.yourdomain.com
    name: "Public Website"
    scope:
      - "*.yourdomain.com"

  - url: https://admin.yourdomain.com
    name: "Admin Portal"
    auth:
      auth_type: bearer                     # bearer | api_key | basic | form
      token_header: "Authorization"         # header name (default: Authorization)
      token: "${VAPT_ADMIN_TOKEN}"          # bearer token from browser DevTools
      # For API key auth instead:
      # auth_type: api_key
      # api_key: "${VAPT_API_KEY}"
      # For basic form login (when possible):
      # auth_type: form
      # login_url: https://admin.yourdomain.com/login
      # username: "qa_test_user"
      # password: "${VAPT_ADMIN_PASSWORD}"

settings:
  timeout: 10              # seconds per HTTP request
  max_concurrent: 5        # max parallel requests per target
  user_agent: "VAPT-Scanner/1.0 (Authorized Security Test)"
  rate_limit: 2            # requests per second (per target)
  follow_redirects: true

scanners:
  skip: []                 # categories to skip, e.g. [network, cloud]

reporting:
  formats:
    - html
    - pdf
  output_dir: ./reports
  severity_threshold: info   # info | low | medium | high | critical

authorization:
  basis: "own_infra"        # own_infra | pentest_engagement | bug_bounty | ctf
  authorized_by: "QA Team"
  ref: "VAPT-2026-001"
```

### Config fields explained

| Section | Field | Description | Default |
|---------|-------|-------------|---------|
| `targets[].url` | Target URL | **Required.** Full URL including scheme | — |
| `targets[].name` | Display name | Shown in reports and terminal | URL |
| `targets[].scope` | Scope patterns | Limits subdomain testing | Full domain |
| `targets[].auth` | Auth config | Login credentials for authenticated testing | None |
| `targets[].auth.auth_type` | Auth method | `form` (POST login), `basic` (HTTP Basic), `bearer` (token), `api_key` | `form` |
| `targets[].auth.password` | Password | Use `${ENV_VAR}` syntax to read from environment | — |
| `settings.timeout` | Request timeout | Seconds per HTTP request | 10 |
| `settings.max_concurrent` | Concurrency | Max parallel requests per target | 5 |
| `settings.rate_limit` | Rate limit | Requests per second per target | 2 |
| `scanners.skip` | Skip list | Scanner names to skip | `[]` |
| `reporting.formats` | Report types | `html`, `pdf`, or both | `[html, pdf]` |
| `reporting.output_dir` | Output path | Where reports are saved | `./reports` |
| `reporting.severity_threshold` | Min severity | Only include findings at or above this level | `info` |
| `authorization.basis` | Auth basis | Legal basis for testing | — |

### Environment variables

Secrets should not be hardcoded. Use `${ENV_VAR}` in config.yaml:

```bash
# For bearer token auth (Google login, SSO, OAuth):
# 1. Log in to your app in a browser
# 2. Open DevTools → Network tab → copy the Authorization header value
# 3. Set it as an env var:
export VAPT_ADMIN_TOKEN="eyJhbGciOiJSUzI1NiIs..."

# For form-based login:
export VAPT_ADMIN_PASSWORD="your_password_here"

# For API key auth:
export VAPT_API_KEY="your_api_key_here"

# Then run the scan
python run_vapt.py --config config.yaml --active
```

| Variable | Purpose |
|----------|---------|
| `VAPT_ADMIN_TOKEN` | Bearer token for SSO/OAuth/Google login (copy from browser DevTools) |
| `VAPT_ADMIN_PASSWORD` | Password for form-based login |
| `VAPT_API_KEY` | API key for API key auth |

---

## Running Scans

### Passive scan (safe mode, default)

Runs only non-intrusive tests. No attack payloads are sent. Safe to run against production.

```bash
python run_vapt.py --config config.yaml
```

**What passive mode tests:**
- DNS records, subdomains, WHOIS lookups
- SSL certificates, TLS protocol versions, cipher suites
- Security headers (CSP, HSTS, CORS, cookie flags)
- Open ports and service detection
- Directory discovery (HEAD requests only), CMS detection

### Full scan with active tests

Includes injection payloads, brute force resistance checks, and other active tests. **Only run against targets you are authorized to test.**

```bash
python run_vapt.py --config config.yaml --active
```

**What active mode adds:**
- SQL injection, XSS, SSTI, command injection payloads
- Login brute force resistance, session analysis, JWT testing
- IDOR, privilege escalation, forced browsing
- API security (BOLA, BFLA, mass assignment, rate limiting)
- Race conditions, business logic flaws
- Cloud misconfiguration, S3 bucket testing
- WebSocket and GraphQL security

### Preview mode (dry run)

See what would be tested without executing anything:

```bash
python run_vapt.py --config config.yaml --dry-run
python run_vapt.py --config config.yaml --active --dry-run
```

### Scan specific categories only

```bash
# Only test SSL and security headers
python run_vapt.py -c config.yaml --only ssl_tls,headers

# Run everything except network and cloud scanning
python run_vapt.py -c config.yaml --active --skip network,cloud
```

### Override target from command line

```bash
# Add a staging target alongside config targets
python run_vapt.py -c config.yaml -t https://staging.yourdomain.com

# Multiple extra targets
python run_vapt.py -c config.yaml -t https://staging.yourdomain.com -t https://api.yourdomain.com
```

### Filter by severity

```bash
# Only report medium, high, and critical findings
python run_vapt.py -c config.yaml --severity medium

# Only critical findings
python run_vapt.py -c config.yaml --severity critical
```

### Custom output directory

```bash
python run_vapt.py -c config.yaml -o ./my-reports
```

### Adjust rate limiting

```bash
# Slower (1 req/sec) — safer for rate-limited targets
python run_vapt.py -c config.yaml --rate-limit 1

# Faster (5 req/sec) — for internal/staging targets
python run_vapt.py -c config.yaml --rate-limit 5
```

---

## CLI Reference

```
python run_vapt.py [OPTIONS]
```

| Flag | Short | Description |
|------|-------|-------------|
| `--config PATH` | `-c` | **Required.** Path to YAML config file |
| `--target URL` | `-t` | Add/override target URL (repeatable) |
| `--active` | | Enable active tests (injection, brute force) |
| `--skip CATS` | | Comma-separated categories to skip |
| `--only CATS` | | Run only these categories |
| `--severity LEVEL` | | Minimum severity: `critical\|high\|medium\|low\|info` |
| `--output-dir PATH` | `-o` | Override report output directory |
| `--format FMTS` | `-f` | Report formats: `html,pdf` (comma-separated) |
| `--timeout SECS` | | Per-request timeout in seconds |
| `--rate-limit RPS` | | Requests per second per target |
| `--verbose` | `-v` | Verbose output during scanning |
| `--quiet` | `-q` | Only show findings and final score |
| `--dry-run` | | Preview mode (no actual scanning) |
| `--version` | | Show version and exit |

---

## Scanner Categories

### Wave 1 — Reconnaissance (passive)

| Scanner | Name | What It Tests |
|---------|------|---------------|
| Recon | `recon` | DNS records (A/AAAA/MX/TXT/NS), subdomain enumeration via crt.sh, WHOIS analysis, technology fingerprinting, robots.txt/sitemap.xml/security.txt, Google dork suggestions |
| SSL/TLS | `ssl_tls` | Certificate validity/expiry/chain, TLS protocol versions (SSLv3 through TLS 1.3), cipher suite strength, HSTS header, OCSP stapling, mixed content detection |
| Headers | `headers` | CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy, HSTS, CORS misconfiguration, cookie flags (HttpOnly/Secure/SameSite), HTTP methods (TRACE/PUT/DELETE), server information disclosure |

### Wave 2 — Scanning (passive)

| Scanner | Name | What It Tests |
|---------|------|---------------|
| Network | `network` | Port scanning (top 22 common ports), service detection, risk assessment per service (FTP/Telnet/SMB/DB/Redis/MongoDB exposure) |
| Web App | `webapp` | Directory discovery (66 common paths), backup/config file detection (.env/.git/.htaccess), CMS detection (WordPress/Drupal/Joomla), error page information disclosure |

### Wave 3 — Testing (active, requires `--active`)

| Scanner | Name | What It Tests |
|---------|------|---------------|
| Injection | `injection` | SQL injection (error/boolean/time-based), reflected XSS, SSTI, command injection, XXE, Host header injection, CRLF injection |
| Auth | `auth` | Login form detection, brute force resistance (10-attempt lockout test), username enumeration, session token entropy, JWT analysis (alg:none, missing exp), password reset flows |
| Authorization | `authz` | Forced browsing (admin/dashboard access without auth), IDOR patterns (sequential ID enumeration), HTTP method tampering, path traversal |
| API | `api` | Swagger/OpenAPI discovery, unauthenticated endpoint access, BOLA, mass assignment, rate limiting (50-request burst), GraphQL introspection |
| Business Logic | `logic` | Race conditions (10 concurrent requests), numeric boundary abuse (negative/zero/overflow), workflow step bypass, idempotency violations |
| Cloud | `cloud` | Cloud provider detection, S3/GCS/Azure bucket enumeration, subdomain takeover (CNAME dangling), exposed cloud config files, Firebase database access |
| WebSocket | `websocket` | WebSocket endpoint discovery, CSWSH (Cross-Site WebSocket Hijacking), transport security (ws:// vs wss://), Socket.IO detection |
| GraphQL | `graphql` | Introspection exposure, query depth limits, alias-based batching/rate-limit bypass, SQL injection via arguments |

### Execution flow

```
Wave 1 (parallel) ──> Wave 2 (parallel) ──> Wave 3 (parallel) ──> Scoring + Reports
   recon                  network                injection              HTML
   ssl_tls                webapp                 auth                   PDF
   headers                                       authz, api, logic      JSON
                                                  cloud, websocket
                                                  graphql
```

Each wave runs its scanners in parallel. Waves execute sequentially so later waves can use findings from earlier waves (e.g., Wave 3 injection scanner tests endpoints discovered by Wave 2 webapp scanner).

---

## Understanding Reports

After a scan completes, reports are saved to:

```
./reports/VAPT-{domain}-{YYYYMMDD}/
  report.html      Interactive HTML report
  report.pdf       Professional PDF for stakeholders
  findings.json    Machine-readable data for CI/CD
```

### HTML Report (`report.html`)

The primary deliverable. Open in any browser. Features:

- **Score gauge** — SVG circle showing 0-100 posture score, color-coded
- **Severity distribution** — Colored bars showing finding breakdown
- **Sortable findings table** — Click column headers to sort by ID, severity, CVSS, etc.
- **Collapsible findings** — Click to expand/collapse individual finding details
- **Print-friendly** — Use browser print or the Print button for clean printouts
- **Self-contained** — All CSS/JS inline, no external dependencies; share the single HTML file

### PDF Report (`report.pdf`)

Professional report for stakeholders and compliance. Contains:

- Cover page with CONFIDENTIAL notice
- Executive summary with score and severity table
- Category breakdown with per-category scores
- Detailed findings sorted by severity (Critical first)
- Methodology section

### JSON Export (`findings.json`)

Machine-readable format for CI/CD integration:

```json
{
  "generated_at": "2026-04-08T12:00:00+00:00",
  "posture_score": {
    "overall_score": 62.5,
    "rating": "Fair",
    "categories": [...]
  },
  "findings": [
    {
      "id": "FINDING-001",
      "title": "SQL Injection in login parameter",
      "severity": "Critical",
      "cvss_score": 9.8,
      "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
      "cwe_id": "CWE-89",
      "remediation": "Use parameterized queries...",
      ...
    }
  ]
}
```

### Each finding includes

| Field | Description |
|-------|-------------|
| ID | Unique identifier (FINDING-001, FINDING-002, ...) |
| Title | One-line summary |
| Severity | Critical / High / Medium / Low / Info |
| CVSS Score | 0.0 - 10.0 (CVSS v3.1) |
| CVSS Vector | Full vector string |
| CWE | Weakness classification (e.g., CWE-89 SQL Injection) |
| OWASP | OWASP Top 10 mapping (e.g., A03:2021 Injection) |
| URL | Affected endpoint |
| Parameter | Affected input parameter |
| Description | What was found |
| Steps to Reproduce | Numbered steps to verify the finding |
| Evidence | Request/response pairs proving the vulnerability |
| Impact | Business impact assessment |
| Remediation | How to fix (with code examples) |
| References | Links to CWE, OWASP, and related documentation |

---

## Security Posture Score

The suite calculates a weighted **Security Posture Score (0-100)** based on all findings:

### Score ratings

| Score | Rating | Meaning |
|-------|--------|---------|
| 90-100 | Excellent | Strong security posture, minimal issues |
| 70-89 | Good | Minor issues to address, no critical risks |
| 50-69 | Fair | Several concerns need attention |
| 30-49 | Poor | Significant vulnerabilities present |
| 0-29 | Critical | Immediate remediation required |

### Category weights

| Category | Weight | What It Covers |
|----------|--------|---------------|
| Injection | 20% | SQLi, XSS, SSTI, command injection, XXE |
| Authentication | 15% | Login security, sessions, JWT, MFA |
| Authorization | 12% | IDOR, privilege escalation, access control |
| API Security | 12% | BOLA, BFLA, mass assignment, rate limiting |
| SSL/TLS | 10% | Certificates, protocols, ciphers |
| Security Headers | 8% | CSP, CORS, HSTS, cookie flags |
| Network Exposure | 8% | Open ports, exposed services |
| Web App Surface | 7% | Exposed dirs, backup files, CMS vulns |
| Business Logic | 5% | Race conditions, workflow bypass |
| Recon Exposure | 3% | DNS exposure, tech disclosure |

### Penalty per finding

| Finding Severity | Score Penalty |
|-----------------|---------------|
| Critical | -40 points |
| High | -25 points |
| Medium | -15 points |
| Low | -5 points |
| Info | 0 points |

---

## External Tools (Optional)

The suite works with **pure Python** out of the box. When external security tools are installed, it uses them automatically for deeper coverage and falls back to Python when they're missing.

### Tool tiers

| Tier | Tools | Effect If Missing |
|------|-------|-------------------|
| **Core** | curl, openssl, dig, whois | Usually pre-installed. Fallback to Python stdlib |
| **Recommended** | nmap, sqlmap, nuclei, nikto, ffuf, testssl.sh, subfinder | Reduced scan depth; Python fallbacks used |
| **Optional** | whatweb, sslscan, wpscan, hydra, gobuster, dalfox, websocat | Minor coverage reduction |

### Install recommended tools

**macOS (Homebrew):**
```bash
brew install nmap sqlmap nuclei nikto ffuf
```

**Ubuntu/Debian:**
```bash
sudo apt install nmap nikto
pip install sqlmap
# nuclei: https://github.com/projectdiscovery/nuclei
# ffuf: https://github.com/ffuf/ffuf
```

### Tool detection

Run a dry-run to see which tools are detected:

```bash
python run_vapt.py -c config.yaml --dry-run
```

Output shows:
```
Tool Detection:
  CORE: ✓ curl, openssl, dig, whois
  RECOMMENDED: ✓ nmap  ✗ sqlmap, nuclei, nikto, ffuf, testssl.sh, subfinder
  OPTIONAL: ✗ whatweb, sslscan, wpscan, hydra, gobuster, dalfox, websocat
```

Reports include a "Tools Used" section documenting exactly which tools ran and which used fallbacks, so you know the coverage level.

---

## Project Structure

```
vapt/
├── run_vapt.py                    # Entry point — run this
├── config.yaml                    # Target configuration
├── requirements.txt               # Python dependencies
├── .gitignore
│
├── vapt/                          # Main package
│   ├── cli.py                     # CLI argument parsing, banner
│   ├── config.py                  # YAML config loader with env var support
│   ├── runner.py                  # Wave-based scan orchestrator
│   ├── tools.py                   # External tool detection
│   ├── utils.py                   # HTTP client, rate limiter, subprocess helpers
│   │
│   ├── models/                    # Data structures
│   │   ├── finding.py             # Finding dataclass
│   │   ├── target.py              # Target configuration
│   │   └── score.py               # Posture score models
│   │
│   ├── scanners/                  # One module per test category
│   │   ├── base.py                # Abstract base scanner class
│   │   ├── recon.py               # Reconnaissance & OSINT
│   │   ├── network.py             # Port scanning & services
│   │   ├── ssl_tls.py             # SSL/TLS & certificates
│   │   ├── headers.py             # Security headers & CORS
│   │   ├── webapp.py              # Web app surface scanning
│   │   ├── injection.py           # SQLi, XSS, SSTI, CMDi
│   │   ├── auth.py                # Authentication & sessions
│   │   ├── authz.py               # Authorization & access control
│   │   ├── api.py                 # API security testing
│   │   ├── logic.py               # Business logic flaws
│   │   ├── cloud.py               # Cloud misconfiguration
│   │   ├── websocket_scan.py      # WebSocket security
│   │   └── graphql.py             # GraphQL security
│   │
│   ├── scoring/                   # Scoring engine
│   │   ├── cvss.py                # CVSS v3.1 calculator
│   │   └── posture.py             # Security posture score
│   │
│   └── reports/                   # Report generators
│       ├── html_report.py         # HTML report + JSON export
│       ├── pdf_report.py          # PDF report
│       └── templates/
│           └── report.html        # Jinja2 HTML template
│
├── payloads/                      # Test payloads (text files)
│   ├── sqli.txt                   # SQL injection payloads
│   ├── xss.txt                    # XSS payloads
│   ├── ssti.txt                   # SSTI payloads
│   ├── paths.txt                  # Directory discovery paths
│   ├── subdomains.txt             # Subdomain prefixes
│   └── default_creds.txt          # Default credential pairs
│
└── reports/                       # Generated reports (gitignored)
```

---

## Troubleshooting

### "command not found: python" or "pip"

Use `python3` and `pip3` explicitly, or ensure your virtual environment is activated:
```bash
source .venv/bin/activate
```

### "externally-managed-environment" error from pip

You must use a virtual environment. See [Setup Step 2](#step-2-create-a-python-virtual-environment).

### PDF reports not generating

Install reportlab:
```bash
pip install reportlab
```
If reportlab fails to install, HTML + JSON reports still generate normally.

### Scans timing out

Increase the timeout:
```bash
python run_vapt.py -c config.yaml --timeout 30
```

Or adjust in `config.yaml`:
```yaml
settings:
  timeout: 30
```

### Rate limiting / WAF blocking

Lower the request rate:
```bash
python run_vapt.py -c config.yaml --rate-limit 1
```

### Scanner fails with an error

Individual scanner errors don't stop the suite. The failed scanner is marked with a red `✗` in terminal output, and all other scanners continue. The error is noted in the report's methodology section.

### "No module named 'vapt'"

Make sure you're running from the project root directory:
```bash
cd /path/to/vapt
python run_vapt.py -c config.yaml
```

---

## Authorization & Legal

**This tool is for authorized security testing only.**

Before scanning any target, ensure you have:

1. Written authorization from the system owner (pentest engagement, SOW, or contract)
2. A defined scope of testing (which domains, which test types)
3. An understanding of any off-limits areas (production databases, payment systems)

The `authorization` section in `config.yaml` documents your testing basis. This information is included in every generated report for audit trail purposes.

| Authorization Basis | When to Use |
|--------------------|-------------|
| `own_infra` | Testing your own systems |
| `pentest_engagement` | Contracted penetration test with signed SOW |
| `bug_bounty` | Target has a bug bounty program and you're within scope |
| `ctf` | Capture The Flag or lab environment |

Unauthorized testing of systems you do not own or have permission to test is illegal in most jurisdictions.
