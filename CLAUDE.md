## Project: VAPT Test Suite

Standalone Python VAPT (Vulnerability Assessment & Penetration Testing) toolkit. QA teams run it against any web target to produce HTML + PDF security reports.

### Architecture

- **Entry point:** `run_vapt.py` → `vapt/cli.py` (argparse) → `vapt/runner.py` (wave orchestrator)
- **14 scanners** in `vapt/scanners/`, all inherit from `BaseScanner` and register via `@register_scanner`
- **Wave execution:** Wave 1 (recon, ssl_tls, headers) → Wave 2 (network, webapp) → Wave 3 (active scanners) → Scoring + Reports
- **Each scanner gets its own HTTP client** — prevents auth state bleeding between parallel scanners
- **Scope enforcement** in `AsyncHttpClient._check_scope()` — blocks all off-scope requests including redirect hops
- **Soft-404 detection** in `BaseScanner.is_soft_404()` — prevents false positives from SPAs returning 200 for all routes

### Key Design Decisions

- `verify_ssl=True` by default — scanner must not MITM itself
- Redirect following is manual (`_follow_with_scope`) — checks scope on every hop, strips auth on cross-host redirects
- `shlex.quote()` on all shell-interpolated values in ssl_tls.py
- Confidence field on findings: `confirmed` | `firm` | `tentative` — auto-enforced by `add_finding()` for titles starting with "Potential"
- Evidence redaction strips tokens/passwords/cookies before writing reports
- Payloads loaded from `payloads/*.txt` files, fallback to hardcoded lists

### Scanner Categories

| Scanner | Category | Mode | Weight |
|---------|----------|------|--------|
| recon | recon | passive | 3% |
| ssl_tls | ssl | passive | 10% |
| headers | headers | passive | 8% |
| network | network | passive | 8% |
| webapp | scan | passive | 7% |
| injection | injection | active | 20% |
| auth | authentication | active | 15% |
| authz | authorization | active | 12% |
| api | api | active | 12% |
| logic | logic | active | 5% |
| cloud | network | active | 0% |
| websocket | api | active | 0% |
| graphql | api | active | 0% |
| ssrf | injection | active | 0% |
| zap | injection | active | 0% |

### Auth Support

Config supports: `bearer` (token from browser DevTools), `api_key`, `basic`, `form`. Auth headers built centrally in `BaseScanner.build_auth_headers()`. Token value in `auth.token`, header name in `auth.token_header`.

### Reports

- HTML: Jinja2 template at `vapt/reports/templates/report.html` — self-contained, sortable, collapsible
- PDF: ReportLab at `vapt/reports/pdf_report.py` — cover page, exec summary, detailed findings
- JSON: `findings.json` — machine-readable for CI/CD
- CI/CD exit code: `sys.exit(1)` on critical/high findings

### Testing Against Real Targets

See `oxyzo.md` for execution steps (gitignored, local only).

### Known Limitations (documented in README)

- Experimental project — not audited by third party
- Heuristic findings marked `tentative` require manual verification
- No stored XSS, DOM XSS, deserialization, HTTP smuggling, or CVE database lookups yet
- Automated scanning cannot replace manual pentesting
