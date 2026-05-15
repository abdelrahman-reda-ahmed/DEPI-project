# DORA — Full Project Specification

> **Purpose:** This document contains the complete specification for the DORA Automated
> Reconnaissance & Pentesting Assistant. Give this to any AI coding tool to recreate
> the project faithfully.

---

## 1. Project Overview

**Name:** DORA (Automated Reconnaissance & Pentesting Assistant)  
**Version:** 0.1.0  
**Language:** Python 3.10+  
**License:** MIT  

**Description:** A modular, async-first reconnaissance tool that automates the pentesting
recon workflow — from passive subdomain enumeration to active vulnerability checks —
with zero external system dependencies (no nmap, no Go tools, no binaries).

---

## 2. Directory Structure

```
project_root/
├── config.yaml                  # Default YAML configuration
├── pyproject.toml               # Build/project metadata (setuptools)
├── requirements.txt             # pip dependencies
├── README.md                    # Full documentation
├── QUICKSTART.md                # Quick-start guide
├── AGENTS.md                    # AI/LLM context file
├── .gitignore                   # __pycache__, *.pyc, reports/, .env, build/
│
├── wordlists/
│   ├── subdomains.txt           # 5,016 entries — SecLists top 5k + custom
│   ├── subdomains_deepmagic.txt # 49,928 entries — deepmagic prefixes
│   ├── directories.txt          # 4,649 entries — SecLists common + custom
│   └── parameters.txt           # 6,453 entries — SecLists Burp param names
│
├── dora/
│   ├── __init__.py              # __version__ = "0.1.0"
│   ├── cli.py                   # Typer CLI entry point
│   ├── gui.py                   # Tkinter desktop GUI
│   ├── engine.py                # Scan orchestrator, phase resolution, dedup
│   ├── config.py                # YAML + env-var config with validation
│   ├── models.py                # Finding, Target, ScanResult dataclasses
│   ├── targets.py               # Domain/IP/CIDR parsing
│   │
│   ├── phases/
│   │   ├── __init__.py          # (empty)
│   │   ├── passive.py           # Subdomain enum (crt.sh, DNS, tech detect, DNS brute-force)
│   │   ├── active.py            # TCP port scan (raw sockets), banner grab, HTTP probe
│   │   ├── fuzzing.py           # Dir/API/param fuzzing, response size filtering, subdomain fuzzing
│   │   ├── js_mining.py         # JS crawl, URL/secret extraction (15 regex patterns)
│   │   ├── vuln_check.py        # SSL/TLS, security headers, CORS, NVD CVE lookup
│   │   └── reporting.py         # Report generation orchestrator
│   │
│   └── utils/
│       ├── __init__.py          # (empty)
│       ├── http.py              # AsyncHTTPClient (httpx wrapper with retries)
│       ├── async_runner.py      # Semaphore-based concurrent task runner + rate limiter
│       └── output.py            # Rich console, JSON/MD/HTML export
```

---

## 3. Dependencies

### Python (from requirements.txt / pyproject.toml)

```
typer>=0.9.0          # CLI framework
httpx>=0.25.0         # Async HTTP client
rich>=13.0.0          # Terminal formatting
pyyaml>=6.0           # YAML config parsing
jinja2>=3.1.0         # HTML report templating
pydantic>=2.0.0       # (installed but not used — safe to omit)
dnspython>=2.4.0      # DNS resolution
beautifulsoup4>=4.12.0  # HTML parsing
lxml>=4.9.0           # XML parser for BeautifulSoup
tqdm>=4.66.0          # Progress bars in async runner
```

### System Dependencies

**Zero.** No nmap, no Go, no external binaries. TCP port scanning uses raw Python sockets.

---

## 4. Configuration

### 4.1 config.yaml Schema

```yaml
api_keys:
  securitytrails: ""        # Optional — SecurityTrails API key
  virustotal: ""            # Optional — VirusTotal API key
  shodan: ""                # Optional — Shodan API key
  builtwith: ""             # Optional — BuiltWith API key
  github: ""               # Optional — GitHub token

scan:
  threads: 20               # Max concurrent tasks (1-100)
  timeout: 10               # HTTP request timeout in seconds (1-120)
  retries: 2                # HTTP retry count
  user_agent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) DORA/0.1"
  rate_limit: 0.1           # Delay between requests in seconds
  min_response_size: 100    # Minimum response body bytes for fuzzing results

port_scan:
  ports: "21,22,23,25,53,80,110,143,443,445,993,995,1433,1521,2049,3306,3389,5432,5900,6379,8080,8443,9000,27017"
  timing_template: "T4"     # (informational, not used by raw sockets)

wordlists:
  subdomains: "wordlists/subdomains.txt"
  subdomains_large: "wordlists/subdomains_deepmagic.txt"
  directories: "wordlists/directories.txt"
  parameters: "wordlists/parameters.txt"

output:
  format: "json"            # json, html, md, markdown, all
  dir: "reports/"
  verbose: false
```

### 4.2 Environment Variable Overrides

| Variable | Overrides | Notes |
|----------|-----------|-------|
| `DORA_SECURITYTRAILS_KEY` | `api_keys.securitytrails` | |
| `DORA_VIRUSTOTAL_KEY` | `api_keys.virustotal` | |
| `DORA_SHODAN_KEY` | `api_keys.shodan` | |
| `DORA_BUILTWITH_KEY` | `api_keys.builtwith` | |
| `DORA_GITHUB_KEY` | `api_keys.github` | |
| `DORA_THREADS` | `scan.threads` | |
| `DORA_TIMEOUT` | `scan.timeout` | |

### 4.3 Config Validation

`DORAConfig.validate()` checks and prints warnings for:
- Missing wordlist files
- Invalid port_scan.ports format
- scan.threads < 1
- scan.timeout < 1
- scan.rate_limit < 0
- scan.min_response_size < 0
- No API keys configured (informational)
- Invalid output.format

Called from CLI (`scan`, `quick`) and GUI before scan starts.

---

## 5. Data Models (`dora/models.py`)

### 5.1 Enums

**`Severity`**: `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `INFO`

**`FindingType`**: `OPEN_PORT`, `SUBDOMAIN`, `DIRECTORY`, `API_ENDPOINT`, `PARAMETER`,
`JS_ENDPOINT`, `SECRET`, `CVE`, `SSL_ISSUE`, `MISSING_HEADER`, `CORS_ISSUE`,
`TECH_STACK`, `DNS_RECORD`, `OSINT`

### 5.2 Dataclasses

**`Finding`**:
- `type: FindingType`
- `name: str`
- `severity: Severity`
- `value: str`
- `description: str = ""`
- `evidence: str = ""`
- `source: str = ""`
- `extra: dict = field(default_factory=dict)`
- `to_dict() -> dict` — serializes to plain dict

**`Target`**:
- `raw: str` — original input
- `domain: Optional[str]` — extracted domain
- `ip: Optional[str]` — extracted IP
- `cidr: Optional[str]` — extracted CIDR
- `ports: list[int]` — populated by active phase
- `_parse()` — auto-runs in `__post_init__`, parses URL/IP/domain/CIDR from raw
- `base_url: str` — property: `https://{domain}` or `http://{ip}` or raw

**`ScanResult`**:
- `target: Target`
- `start_time: datetime`
- `end_time: Optional[datetime]`
- `findings: list[Finding]`
- `phases_executed: list[str]`
- `add_finding(finding)`
- `by_severity() -> dict`
- `by_type() -> dict`
- `summary() -> dict`
- `to_dict() -> dict`

### 5.3 Target Parsing (`dora/targets.py`)

- `parse_target(raw: str) -> Target` — wraps `Target(raw=raw)`
- `parse_targets(raw_targets: list[str]) -> list[Target]`

Parsing logic in `Target._parse()`:
1. If raw starts with `http://` or `https://`, extract hostname via `urlparse`
2. Else split on `/` then `:` to get hostname
3. Try `ipaddress.ip_address(hostname)` → set `self.ip`
4. Try `ipaddress.ip_network(hostname, strict=False)` → set `self.cidr`, return
5. Match domain regex `^(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}$` → set `self.domain`

---

## 6. Engine (`dora/engine.py`)

### 6.1 PHASE_MAP

```python
PHASE_MAP = {
    "passive": ("Passive Reconnaissance", run_passive_phase),
    "active":  ("Active Reconnaissance", run_active_phase),
    "fuzzing": ("Directory & Parameter Fuzzing", run_fuzzing_phase),
    "js":      ("JavaScript & Secret Mining", run_js_mining_phase),
    "vuln":    ("Vulnerability Checking", run_vuln_check_phase),
}
```

### 6.2 PHASE_DEPENDENCIES

```python
PHASE_DEPENDENCIES = {
    "active":  ["passive"],
    "fuzzing": ["active"],
    "js":      ["active"],
    "vuln":    ["active"],
}
```

Dependencies auto-resolve: requesting `fuzzing` automatically adds `active` and `passive`.

### 6.3 CLI Aliases (resolved by engine)

- `subdomain` → `passive`
- `dirs` → `fuzzing`
- `secrets` → `js`

### 6.4 DORAEngine

```python
class DORAEngine:
    def __init__(self, config: DORAConfig)
    def resolve_phases(requested: Optional[list[str]]) -> list[str]
    async def run(targets_raw: list[str], phases=None, output_path=None, no_report=False) -> list[ScanResult]
```

**`run()` flow:**
1. Parse targets via `parse_targets()`
2. Resolve phase list (dependencies + aliases)
3. Print header with targets and phases
4. Iterate through resolved phases, calling each runner with shared `findings: list[Finding]`
5. After all phases: deduplicate findings via `deduplicate_findings()`
6. For each target: create `ScanResult`, call `generate_report()`
7. Return results

### 6.5 Deduplication

```python
def deduplicate_findings(findings: list[Finding]) -> list[Finding]:
    """Remove duplicates keyed by (type.value, value, name)."""
```

Called after all phases complete in both CLI engine and GUI worker.

---

## 7. Phase Implementations

### 7.1 Passive Reconnaissance (`dora/phases/passive.py`)

**Runner:** `run_passive_phase(targets, config, findings)`

**Sub-techniques (in order):**

| # | Function | Description |
|---|----------|-------------|
| 1 | `run_crtsh(client, domain)` | Query crt.sh certificate transparency logs (`/crt.sh/?q=%.{domain}&output=json`) |
| 2 | `run_wayback(client, domain)` | Query Wayback Machine CDX API for historical URLs |
| 3 | `run_securitytrails(client, domain, api_key)` | (Optional) SecurityTrails subdomain API |
| 4 | `run_virustotal(client, domain, api_key)` | (Optional) VirusTotal subdomain API |
| 5 | `run_dns_enum(domain)` | DNS record enumeration: A, AAAA, MX, NS, TXT, CNAME, SOA |
| 6 | `check_zone_transfer(domain)` | Attempt DNS zone transfer on each nameserver |
| 7 | `run_tech_detect(client, domain)` | HTML meta generator + script src heuristic tech detection |
| 8 | `run_dns_bruteforce(domain, config)` | DNS A-record brute-force using subdomain wordlist |

**After all per-target sources:** collect all unique subdomain values → `probe_subdomains()`
which HTTP-probes each subdomain with HEAD/GET (https first, then http) and creates
"Live Subdomain" findings for responsive ones.

**DNS brute-force details:**
- Loads wordlist from `config.wordlist_subdomains` (e.g. `wordlists/subdomains.txt`)
- For each prefix, resolves `{prefix}.{domain}` A record via `dns.resolver.resolve()`
- Uses `run_concurrently()` with `config.scan_threads` parallelism
- Timeout per lookup: 5 seconds
- Results in `FindingType.SUBDOMAIN` with source `"dns.bruteforce"`

**Tech detection heuristics (13 patterns):**
react, angular, vue, jquery, next, nuxt, gatsby, django, laravel, wordpress, wp-, shopify, cloudflare

### 7.2 Active Reconnaissance (`dora/phases/active.py`)

**Runner:** `run_active_phase(targets, config, findings)`

**Sub-techniques:**

1. `run_port_scan(target, config)` — TCP connect scan
   - Parse port string with `_parse_ports()` (supports comma-separated and ranges like `8080-8082`)
   - Resolve hostname to IP via `socket.gethostbyname_ex()` / `gethostbyname()`
   - Raw TCP socket `connect_ex()` with configured timeout
   - Batch size: 50 concurrent connections
   - Banner grab on open ports via `_banner_grab()` (sends `GET / HTTP/1.1` on HTTP ports)
   - Service identification via `_KNOWN_SERVICES` map (24 known ports)
   - Severity: MEDIUM for sensitive ports (22, 3389, 3306, 5432, 6379, 27017, 1433), LOW otherwise

2. `run_http_probe(target, config)` — HTTP service probing on open ports
   - For each open port, try HTTPS then HTTP
   - Fetch title via BeautifulSoup
   - Record server header

**Port range parsing:** comma-separated list, supports `start-end` ranges.

### 7.3 Fuzzing Phase (`dora/phases/fuzzing.py`)

**Runner:** `run_fuzzing_phase(targets, config, findings)`

**Sub-techniques:**

1. **Directory fuzzing** (`dir_fuzz_target`):
   - Uses `config.wordlist_directories` wordlist
   - Tests each entry with extensions `["", "/"]`
   - **Response size filtering:** skips responses with `content_len < config.min_response_size`
   - Catches status codes: 200, 201, 204, 301, 302, 307, 308, 401, 403, 500
   - Severity: HIGH for paths containing `admin`, `api`, `.git`, `.env`; MEDIUM for 403; LOW otherwise
   - Concurrency: batched with semaphore (`max_concurrent * 2` batch size)

2. **API endpoint fuzzing** (`fuzz_api_endpoints`):
   - 25 predefined API paths (api/v1, graphql, swagger, openapi.json, etc.)
   - Catches statuses: 200, 201, 401, 403, 405, 500

3. **Parameter fuzzing** (`fuzz_parameters`):
   - 45 common parameter names
   - Tests both GET and POST methods
   - Flags parameters that don't return 404

4. **Subdomain-level fuzzing** (NEW):
   - After fuzzing primary targets, iterates over all `SUBDOMAIN` findings
   - Fuzzes each subdomain: `https://{sub.value}`
   - Same directory/API/parameter fuzzing applied to each subdomain

Helper `_fuzz_single_target(client, base_url, domain, config, findings)` wraps
dir + API + param fuzzing for one base URL, reused for both primary targets and subdomains.

### 7.4 JavaScript & Secret Mining (`dora/phases/js_mining.py`)

**Runner:** `run_js_mining_phase(targets, config, findings)`

**Process:**
1. Crawl page HTML for `<script src="...">` tags and inline JS URL regex
2. Also discovers sourcemap URLs (`//# sourceMappingURL=`)
3. For each JS file found:
   - Extract URLs via regex (`https?://...`)
   - Extract API paths via regex (`/api/...`, `/v1/...`)
   - Scan for secrets using **15 regex patterns**

**Secret patterns (all with severity):**

| Pattern | Name | Severity |
|---------|------|----------|
| `aws_access_key_id` / `AWS_ACCESS_KEY` | AWS Access Key ID | CRITICAL |
| `aws_secret_access_key` / `AWS_SECRET_KEY` | AWS Secret Access Key | CRITICAL |
| `ghp_\|gho_\|ghu_\|ghs_\|ghr_[A-Za-z0-9_]{36,}` | GitHub Token | CRITICAL |
| `sk_live_\|pk_live_[A-Za-z0-9]{20,}` | Stripe Live Key | CRITICAL |
| `sk_test_\|pk_test_[A-Za-z0-9]{20,}` | Stripe Test Key | HIGH |
| `AIza[0-9A-Za-z_-]{35}` | Google API Key | HIGH |
| `-----BEGIN (RSA \|EC )?PRIVATE KEY-----` | Private Key | CRITICAL |
| `-----BEGIN CERTIFICATE-----` | Certificate | MEDIUM |
| `slack\|discord\.com/api/.*hook` | Webhook URL | CRITICAL |
| `token[=:]["']?([A-Za-z0-9._-]{20,})["']?` | Generic Token/Secret | HIGH |
| `(password\|passwd\|pwd)[=:]["']?([^"\'&\s]{6,})["']?` | Password | CRITICAL |
| `(api[_-]?key\|apikey)[=:]["']?([A-Za-z0-9._-]{10,})["']?` | API Key | HIGH |
| `secret[=:]["']?([A-Za-z0-9._-]{10,})["']?` | Generic Secret | HIGH |
| `mongodb(?:\+srv)?://...` | MongoDB Connection String | CRITICAL |
| `postgres(?:ql)?://...` | PostgreSQL Connection String | CRITICAL |
| `mysql://...` | MySQL Connection String | CRITICAL |
| `redis://...` | Redis Connection String | CRITICAL |

### 7.5 Vulnerability Checking (`dora/phases/vuln_check.py`)

**Runner:** `run_vuln_check_phase(targets, config, findings)`

**Sub-techniques:**

1. **Security Headers** (`check_security_headers`):
   - Checks for 6 missing headers: HSTS, CSP, X-Content-Type-Options, X-Frame-Options, X-XSS-Protection, Referrer-Policy
   - Reports uncommon Server headers and X-Powered-By (OSINT)
   - CORS misconfiguration detection (`Access-Control-Allow-Origin: *`)

2. **SSL/TLS Check** (`check_ssl_tls`):
   - Certificate expiry (CRITICAL if expired, HIGH if < 30 days)
   - Hostname mismatch (CN/SAN doesn't match target)
   - Weak TLS version detection (TLSv1.0, TLSv1.1, SSLv2, SSLv3 → HIGH)

3. **CVE Lookup from NVD** (`run_cve_check` + `_query_nvd`):

   **`_query_nvd(keywords)`** — queries NVD API 2.0:
   ```
   GET https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch={query}&resultsPerPage=10
   ```
   Returns up to 10 CVEs with CVE ID, English description (first 300 chars), and CVSS v3.1 base score.

   **`run_cve_check(target, findings_so_far, config)`**:
   - Extracts service + version from OPEN_PORT findings' banners
   - Searches NVD for each service+version combination
   - Severity mapped from CVSS score: >=9.0 CRITICAL, >=7.0 HIGH, >=4.0 MEDIUM, else LOW
   - Deduplicates by CVE ID
   - Creates `FindingType.CVE` findings with source `"nvd.api"`

---

## 8. CLI (`dora/cli.py`)

### Commands

**`scan`** — Full scan with options:
```
dora scan [OPTIONS] TARGET...
```
Options: `--phase, -p` (repeatable), `--config, -c`, `--output, -o`, `--format, -f`,
`--threads, -t`, `--timeout`, `--no-report`, `--verbose, -v`, `--version, -V`

**`quick`** — Quick scan (all phases, HTML default):
```
dora quick [OPTIONS] TARGET
```
Delegates to `scan` with all phases enabled.

**`list-phases`** — List available phases and aliases.

### Entry Points (pyproject.toml)

```toml
[project.scripts]
dora = "dora.cli:app"
dora-gui = "dora.gui:main"
```

---

## 9. GUI (`dora/gui.py`)

### Overview

A Tkinter desktop GUI with a professional dark theme (Catppuccin-inspired color palette).
Uses `ttk` themed widgets for consistent cross-platform appearance.

### Color Palette

```
BG_ROOT      #1e1e2e   (main background)
BG_PANEL     #181825   (panel/labelframe background)
BG_CARD      #11111b   (card/console background)
FG_TEXT      #cdd6f4   (primary text)
FG_DIM       #585b70   (dim/secondary text)
FG_GREEN     #a6e3a1   (success/INFO)
FG_CYAN      #89b4fa   (headings/links)
FG_RED       #f38ba8   (error/CRITICAL)
FG_YELLOW    #f9e2af   (warning/MEDIUM)
FG_ORANGE    #fab387   (HIGH)
```

### Fonts

- UI: `Segoe UI` (10pt default)
- Console/code: `Consolas` (9pt)
- Header: `Consolas` 16pt bold

### Layout (grid, 5 rows)

```
Row 0: Header         — Logo + title + version + separator
Row 1: Controls       — Target input, Scan/Quick/Stop/Clear/Reports buttons
                        Phases checkboxes + Output format + Threads/Timeout spinners
Row 2: Output         — Notebook with Console tab + Findings tab
Row 3: Progress bar   — Determinate bar with phase name overlay
Row 4: Status bar     — Status dot + label + timer + target + finding count
```

### Findings Table

- 5 columns: Severity, Type, Name, Value, Source
- Color-coded rows by severity
- **Filter dropdown:** "all", "critical", "high", "medium", "low", "info"
- **Search box:** real-time text search across name, value, description, evidence, type
- **Severity breakdown labels:** live counts for each severity level
- **Double-click** opens detail popup with full finding info
- **Copy Selected** — copies `[SEVERITY] Name: Value` to clipboard
- **Export JSON** — exports all findings to `reports/findings_{target}_{ts}.json`
- **Open Reports** — opens the `reports/` directory in file explorer

### Progress & Status

- **Determinate progress bar** — advanced per-phase (max = number of phases)
- **Phase label overlay** — shows current phase name (e.g. "Running: Active Reconnaissance")
- **Elapsed timer** — real-time countdown during scan
- **Status dot** — green = scanning, dim = ready, yellow = cancelling
- **Config validation** — runs `DORAConfig.validate()` before scan, displays warnings in console

### Scan Worker

- Runs in a background `threading.Thread` with `asyncio.run()`
- Thread-safe cancellation via `threading.Event`
- Captures stdout via `TextHandler` → queue → GUI console
- Runs dedup after all phases
- Saves auto-named Markdown report to `reports/`
- Calls the standard report generator for configured format

### Helper Functions

- `_tooltip(widget, text)` — hover tooltips for all interactive controls
- `_center_window(win, w, h, parent=None)` — centers window on screen or relative to parent

### Improvement Summary (vs. original)

| Aspect | Original | Current |
|--------|----------|---------|
| Color scheme | Harsh #0a0a0a black + #00ff41 green | Professional dark theme |
| Layout | Single cramped control row | 2-row grouped layout |
| Findings | Plain table | Filter + search + severity counts + detail popup |
| Progress | Indeterminate spinner | Determinate per-phase + label |
| Timer | None | Elapsed time display |
| Tooltips | None | All controls have hover tooltips |
| Export | Hidden in radio buttons | Explicit Export JSON + Copy buttons |
| Reports | No quick access | "Reports" + "Open Reports" buttons |
| Window position | Top-left | Centered on screen |
| Config validation | Not shown | Pre-scan validation in console |
| Dedup in GUI | Not done | Runs after phases in worker |

---

## 10. Utilities

### 10.1 AsyncHTTPClient (`dora/utils/http.py`)

Context manager wrapping `httpx.AsyncClient`:
- `__aenter__` — creates client with timeout, user-agent, redirect following, SSL verify=False
- `get(url)` — retries on ConnectError/ReadTimeout/RemoteProtocolError up to `config.scan_retries` times
- `head(url)` — HEAD request
- `fetch_text(url)` — GET → text
- `fetch_json(url)` — GET → JSON
- `probe(url)` — HEAD first, fallback GET, returns `(url, status_code, headers)` or `(url, 0, {})`

### 10.2 Async Runner (`dora/utils/async_runner.py`)

**`run_concurrently(tasks, max_concurrent, desc, show_progress)`**:
- Semaphore-based concurrency limiter
- Optional `tqdm` progress bar via `as_completed()`
- Falls back to `asyncio.gather()` when progress disabled

**`rate_limited(max_per_second)`**:
- Decorator that limits calls to `max_per_second` using `asyncio.sleep()`

### 10.3 Output (`dora/utils/output.py`)

- `print_finding(finding)` — single finding to console
- `print_summary(result)` — scan summary with severity/type breakdowns
- `print_findings_table(findings, title)` — Rich table
- `export_json(result, path)` — JSON file
- `export_markdown(result, path)` — Full Markdown report with header, summary, findings
- `export_html(result, path)` — Jinja2 HTML report (dark-themed)

### 10.4 Reporting (`dora/phases/reporting.py`)

`generate_report(result, config, output_path=None)`:
- Sets `result.end_time`
- Creates output directory
- Generates report in configured format(s): JSON, MD, HTML
- Prints summary + severity tables to console

---

## 11. Wordlists

Bundled in `wordlists/` directory, sourced from SecLists and other public collections:

| File | Entries | Source | Used By |
|------|---------|--------|---------|
| `subdomains.txt` | 5,016 | SecLists top 5k + custom | DNS brute-force |
| `subdomains_deepmagic.txt` | 49,928 | deepmagic prefixes | DNS brute-force (optional) |
| `directories.txt` | 4,649 | SecLists common + custom | Directory fuzzing |
| `parameters.txt` | 6,453 | SecLists Burp param names | Parameter fuzzing |

Format: one entry per line, blank lines and `#` comment lines ignored.

---

## 12. Deviation from Original

The following enhancements have been added to the base specification:

1. **DNS brute-force subdomain enumeration** (`passive.py:253-286`) — resolves wordlist prefixes via DNS A-record lookups
2. **Response size filtering** (`fuzzing.py:43-44`) — `min_response_size` config skips trivially small responses
3. **Deduplicate findings** (`engine.py:38-46`) — removes duplicates keyed by `(type.value, value, name)` after all phases
4. **Subdomain-level fuzzing** (`fuzzing.py:215-218`) — fuzzes each discovered subdomain after primary targets
5. **CVE lookup from NVD** (`vuln_check.py:183-220`) — queries NVD API 2.0 with service+version keywords
6. **Config validation** (`config.py:154-203`) — validates wordlists, ports, ranges, API keys, format

---

## 13. File-by-File Code Implementation Guide

### 13.1 `dora/__init__.py`
```python
__version__ = "0.1.0"
```

### 13.2 `dora/models.py`

Define `Severity` (str enum), `FindingType` (str enum, 14 values), `Finding` dataclass
with `to_dict()`, `Target` dataclass with `_parse()` and `base_url` property,
`ScanResult` dataclass with `add_finding()`, `by_severity()`, `by_type()`, `summary()`, `to_dict()`.

### 13.3 `dora/targets.py`

Simple: `parse_target(raw)` → `Target(raw=raw)`, `parse_targets` → list.

### 13.4 `dora/config.py`

- Load YAML on init, apply env var overrides
- Properties for all config fields (typed, with defaults)
- Properties added by enhancements: `wordlist_subdomains_large`, `wordlist_parameters`, `min_response_size`
- `validate()` method returning list of warning strings

### 13.5 `dora/engine.py`

- PHASE_MAP dict: `{"passive": ("name", runner_func), ...}`
- PHASE_DEPENDENCIES dict
- `deduplicate_findings()` function
- DORAEngine class with `resolve_phases()`, `run()`

### 13.6 `dora/phases/passive.py`

- All functions listed in section 7.1
- Internal helper: `_load_wordlist(path)`, `_extract_domain_parts(domain)`, `_domain_to_tld(domain)`
- `run_passive_phase()` orchestrates all sub-techniques

### 13.7 `dora/phases/active.py`

- `_parse_ports(port_str)` — parse comma/range port strings
- `_tcp_scan(host, port, timeout)` — raw socket connect
- `_banner_grab(host, port, timeout)` — banner extraction
- `_KNOWN_SERVICES` dict (24 entries)
- `run_port_scan(target, config)` — full port scan
- `run_http_probe(target, config)` — HTTP service detection
- `run_active_phase()` — orchestrator

### 13.8 `dora/phases/fuzzing.py`

- `_load_wordlist(path)` — wordlist file reader
- `dir_fuzz_target()` — directory brute-force with response size filtering
- `fuzz_api_endpoints()` — 25 API paths
- `fuzz_parameters()` — 45 parameters, GET + POST
- `_fuzz_single_target()` — wraps all three for a single base URL
- `run_fuzzing_phase()` — primary targets + subdomain iteration

### 13.9 `dora/phases/js_mining.py`

- `_JS_URL_RE`, `_URL_IN_JS_RE`, `_API_PATH_RE` regexes
- `_SECRET_PATTERNS` — 15 entries (regex, name, severity)
- `_crawl_js_urls()` — discover JS files
- `_analyze_js_content()` — extract URLs, APIs, secrets
- `run_js_mining_phase()` — orchestrator

### 13.10 `dora/phases/vuln_check.py`

- `check_ssl_tls(host, port)` — cert expiry, hostname mismatch, weak TLS
- `check_security_headers(client, url)` — 6 headers + server/CORS
- `_query_nvd(keywords)` — NVD API 2.0 query
- `run_cve_check(target, findings, config)` — correlate banners → CVEs
- `run_vuln_check_phase()` — orchestrator

### 13.11 `dora/phases/reporting.py`

- `generate_report(result, config, output_path)` — orchestrator
- Delegates to `export_json/export_markdown/export_html` from `dora.utils.output`

### 13.12 `dora/utils/http.py`

- `AsyncHTTPClient` context manager wrapping `httpx.AsyncClient`
- Methods: `get()`, `head()`, `fetch_text()`, `fetch_json()`, `probe()`

### 13.13 `dora/utils/async_runner.py`

- `run_concurrently(tasks, max_concurrent, desc, show_progress)` — semaphore-limited concurrent execution
- `rate_limited(max_per_second)` — async rate-limiting decorator

### 13.14 `dora/utils/output.py`

- Console coloring, print functions, report exporters
- HTML uses Jinja2 template embedded in Python string

### 13.15 `dora/cli.py`

- Typer app with `scan`, `quick`, `list-phases` commands
- `scan` — full options, creates DORAConfig + DORAEngine, runs async
- `quick` — all phases, HTML default
- `entry()` → `app()` for `[project.scripts]`

### 13.16 `dora/gui.py`

- Full implementation as described in section 9
- `DORAGUI` class with internal methods for building UI, scan control, findings management
- `FindingsTable` widget class with filtering
- `TextHandler` for stdout capture
- `_tooltip()` and `_center_window()` helpers

### 13.17 `config.yaml`

As described in section 4.1.

### 13.18 `pyproject.toml`

```toml
[build-system]
requires = ["setuptools>=68.0", "wheel"]
build-backend = "setuptools.build_meta"

[project]
name = "dora-pentest"
version = "0.1.0"
description = "Automated reconnaissance and pentesting assistant"
requires-python = ">=3.10"
dependencies = [
    "typer>=0.9.0", "httpx>=0.25.0", "rich>=13.0.0", "pyyaml>=6.0",
    "jinja2>=3.1.0", "pydantic>=2.0.0", "dnspython>=2.4.0",
    "beautifulsoup4>=4.12.0", "lxml>=4.9.0", "tqdm>=4.66.0",
]

[project.scripts]
dora = "dora.cli:app"
dora-gui = "dora.gui:main"

[tool.setuptools.packages.find]
include = ["dora*"]
```

### 13.19 `.gitignore`

```
__pycache__/
*.py[cod]
*.egg-info/
build/
dist/
reports/
.env
```

---

## 14. Testing

No formal test framework. Verification is done via:
- `python -c "import dora; ..."` for import checks
- `python -m dora.cli scan example.com --phase passive --no-report` for integration
- `python -m dora.cli list-phases` for CLI verification
- `python -m dora.gui` (requires display) for GUI verification
- Direct function calls for dedup, config validation, and model tests

---

## 15. Complete Wordlist File Contents

### 15.1 `subdomains.txt`

5,016 lines. First 10 entries: `www`, `mail`, `ftp`, `admin`, `api`, `blog`, `dev`, `test`, `webmail`, `vpn`
Sourced from SecLists/Discovery/DNS/subdomains-top1million-5000.txt plus custom additions.

### 15.2 `subdomains_deepmagic.txt`

49,928 lines. All possible 3-5 character alphanumeric prefixes from deepmagic's common prefixes list.
Used for deeper DNS brute-force when needed.

### 15.3 `directories.txt`

4,649 lines. First 10 entries: `admin`, `wp-admin`, `administrator`, `login`, `backup`, `backups`, `db`, `config`, `css`, `js`
Sourced from SecLists/Discovery/Web-Content/common.txt plus custom API/web paths.

### 15.4 `parameters.txt`

6,453 lines. First 10 entries: `id`, `q`, `s`, `search`, `query`, `page`, `limit`, `offset`, `sort`, `order`
Sourced from SecLists/Discovery/Web-Content/burp-parameter-names.txt.
