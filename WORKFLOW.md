# DORA Workflow

## Overview

DORA is an automated reconnaissance and pentesting assistant that runs a series of **phases** against a target domain/IP. Each phase discovers different types of information, and all findings are collected into a single report.

```
Target ──► Passive ──► Active ──► Fuzzing ──► JS Mining ──► Vuln Check ──► Report
              │            │            │             │              │
              ▼            ▼            ▼             ▼              ▼
         Subdomains    Open Ports   Endpoints     Secrets       Vulnerabilities
         DNS Records   Services     APIs          URLs          SSL Issues
         Tech Stack    Banners      Parameters    API Paths     CORS Issues
```

---

## Entry Points

### CLI (`dora scan`)
```bash
dora scan google.com                          # all phases, HTML report
dora scan google.com --phase passive          # passive only
dora scan google.com --phase vuln -T 60       # vuln with 60s timeout
dora scan google.com -p passive -p active -f json  # select phases + format
```

### CLI (`dora quick`)
```bash
dora quick google.com                         # all phases, defaults
dora quick google.com -T 120                  # with phase timeout
```

### GUI (`dora-gui`)
```bash
dora-gui                                      # launch Tkinter GUI
python -m dora.gui                            # alternative
```

---

## Phase Execution Flow

### 1. Config Loading
```
CLI ──► DORAConfig(config.yaml) ──► env overrides (DORA_*)
         │
         ├── scan.threads       (default: 20)
         ├── scan.timeout       (default: 10s)
         ├── scan.phase_timeout (default: 0 = no limit)
         ├── scan.rate_limit    (default: 0.1s)
         └── api_keys: { securitytrails, virustotal, shodan, builtwith, github }
```

### 2. Phase Resolution
```
requested: ["vuln"]
     │
     ▼
resolve_phases(["vuln"])
     │
     ├── vuln depends on active ──► add "active" first
     │
     └── resolved: ["active", "vuln"]
```

### 3. Phase: Passive Reconnaissance
```
passive.py:run_passive_phase()
 │
 ├── run_crtsh()              HTTPS   crt.sh certificate transparency
 ├── run_wayback()            HTTPS   Wayback Machine CDX
 ├── run_securitytrails()     HTTPS   SecurityTrails API (requires key)
 ├── run_virustotal()         HTTPS   VirusTotal API (requires key)
 ├── run_dns_enum()           Thread  DNS A/AAAA/MX/NS/TXT/CNAME/SOA
 ├── check_zone_transfer()    Thread  DNS zone transfer attempt
 ├── run_tech_detect()        HTTPS   HTML meta + JS framework detection
 ├── run_dns_bruteforce()     Thread  5k wordlist DNS resolution
 │
 └── probe_subdomains()       HTTPS   HTTP probe all discovered subdomains
```

**Output findings:** `SUBDOMAIN`, `DNS_RECORD`, `TECH_STACK`

### 4. Phase: Active Reconnaissance
```
active.py:run_active_phase()
 │
 ├── run_port_scan()          Thread  TCP connect scan on 24 common ports
 │   └── per port: socket.connect_ex() via asyncio.to_thread()
 │
 └── run_http_probe()         HTTPS   HTTP banner + title extraction on open ports
```

**Output findings:** `OPEN_PORT`, `TECH_STACK`

### 5. Phase: Directory & Parameter Fuzzing
```
fuzzing.py:run_fuzzing_phase()
 │
 ├── dir_fuzz_target()        HTTPS   4.6k wordlist directory brute-force
 ├── fuzz_api_endpoints()     HTTPS   Common API paths (/api/v1, /graphql, etc.)
 └── fuzz_parameters()        HTTPS   Parameter fuzzing on discovered endpoints
```

**Output findings:** `DIRECTORY`, `API_ENDPOINT`, `PARAMETER`

### 6. Phase: JavaScript & Secret Mining
```
js_mining.py:run_js_mining_phase()
 │
 ├── _crawl_js_urls()         HTTPS   Extract .js URLs from HTML + sourcemaps
 └── _analyze_js_content()    HTTPS   Regex scan for:
     ├── URLs / API paths
     ├── AWS keys, GitHub tokens
     ├── Stripe keys, Google API keys
     ├── Private keys, certificates
     ├── Webhooks, tokens, passwords
     └── DB connection strings
```

**Output findings:** `JS_ENDPOINT`, `API_ENDPOINT`, `SECRET`

### 7. Phase: Vulnerability Checking
```
vuln_check.py:run_vuln_check_phase()
 │
 ├── check_security_headers() HTTPS   HSTS, CSP, X-Frame-Options, CORS...
 ├── check_ssl_tls()          Socket  Certificate expiry, weak TLS, hostname mismatch
 └── run_cve_check()          HTTPS   NVD API — CVE lookup by service + version
```

**Output findings:** `MISSING_HEADER`, `SSL_ISSUE`, `CORS_ISSUE`, `CVE`, `OSINT`

### 8. Deduplication
```
findings[:] = deduplicate_findings(findings)
     │
     └── dedup key: (finding.type + finding.value + finding.name)
```

### 9. Report Generation
```
generate_report(result, config)
 │
 ├── export_json()      ────► reports/<target>_<timestamp>.json
 ├── export_markdown()  ────► reports/<target>_<timestamp>.md
 ├── export_html()      ────► reports/<target>_<timestamp>.html
 │
 └── print_summary()    ────► terminal output
```

---

## Finding Types

| FindingType     | Severities           | Source Phase | Description                    |
|----------------|----------------------|--------------|--------------------------------|
| `SUBDOMAIN`    | INFO / LOW           | passive      | Discovered subdomains          |
| `DNS_RECORD`   | INFO                 | passive      | DNS A/MX/NS/TXT/etc.          |
| `TECH_STACK`   | INFO                 | passive      | CMS, JS frameworks detected    |
| `OPEN_PORT`    | LOW / MEDIUM         | active       | Open TCP ports + service       |
| `DIRECTORY`    | LOW / MEDIUM / HIGH  | fuzzing      | Accessible directory paths     |
| `API_ENDPOINT` | MEDIUM               | fuzzing/js   | API paths found                |
| `PARAMETER`    | INFO                 | fuzzing      | Accepted GET/POST parameters   |
| `JS_ENDPOINT`  | INFO                 | js           | JavaScript files found         |
| `SECRET`       | MEDIUM / HIGH / CRIT | js           | Keys, tokens, passwords in JS  |
| `MISSING_HEADER` | LOW / MEDIUM       | vuln         | Missing security HTTP headers  |
| `SSL_ISSUE`    | MEDIUM / HIGH / CRIT | vuln         | SSL cert problems              |
| `CORS_ISSUE`   | INFO / MEDIUM        | vuln         | CORS misconfiguration          |
| `CVE`          | LOW→CRITICAL         | vuln         | Known vulnerabilities (NVD)    |
| `OSINT`        | INFO                 | vuln         | Server info leak               |

---

## Configuration

### config.yaml
```yaml
api_keys:
  securitytrails: ""    # set via env: DORA_SECURITYTRAILS_KEY
  virustotal: ""
  shodan: ""
  builtwith: ""
  github: ""

scan:
  threads: 20
  timeout: 10           # HTTP request timeout (seconds)
  retries: 2
  rate_limit: 0.1       # seconds between API calls
  phase_timeout: 0      # per-phase timeout (0 = no limit)

port_scan:
  ports: "21,22,23,..." # comma/range format

wordlists:
  subdomains: "wordlists/subdomains.txt"
  directories: "wordlists/directories.txt"
  parameters: "wordlists/parameters.txt"

output:
  format: "json"       # json, html, md, all
  dir: "reports/"
```

### Environment Variables
| Variable | Overrides | Example |
|----------|-----------|---------|
| `DORA_SECURITYTRAILS_KEY` | `api_keys.securitytrails` | `sk-...` |
| `DORA_VIRUSTOTAL_KEY` | `api_keys.virustotal` | `abcd...` |
| `DORA_SHODAN_KEY` | `api_keys.shodan` | `key...` |
| `DORA_BUILTWITH_KEY` | `api_keys.builtwith` | `uuid...` |
| `DORA_GITHUB_KEY` | `api_keys.github` | `ghp_...` |
| `DORA_THREADS` | `scan.threads` | `50` |
| `DORA_TIMEOUT` | `scan.timeout` | `30` |

---

## Data Flow Diagram

```
┌──────────────┐     ┌──────────────────┐     ┌───────────────┐
│   CLI/GUI    │────►│   DORAEngine     │────►│  Report Files │
│  (entrypoint)│     │  (orchestrator)  │     │ (json/md/html)│
└──────────────┘     └────────┬─────────┘     └───────────────┘
                              │
                    ┌─────────▼─────────┐
                    │   DORAConfig      │
                    │  (YAML + env)     │
                    └─────────┬─────────┘
                              │
          ┌───────────────────┼───────────────────┐
          ▼                   ▼                   ▼
   ┌──────────┐       ┌──────────────┐    ┌──────────────┐
   │  phases/ │       │   utils/     │    │   wordlists/ │
   │ passive  │       │ http.py      │    │ subdomains   │
   │ active   │       │ async_runner │    │ directories  │
   │ fuzzing  │       │ output.py    │    │ parameters   │
   │ js_mining│       │ log.py       │    └──────────────┘
   │ vuln_check│      └──────────────┘
   │ reporting│
   └──────────┘
```

---

## Error Handling

- All `except` blocks log to `logs/dora.log` at `DEBUG` level
- Phase failures don't abort the scan — next phase continues
- Phase timeouts log a warning + wrap in `asyncio.TimeoutError`
- HTTP client retries on `ConnectError` / `ReadTimeout` (configurable via `scan.retries`)
- API failures return empty results silently (logged to debug)

---

## Performance Notes

| Phase | Bottleneck | Mitigation |
|-------|-----------|------------|
| Passive (DNS) | Sync DNS lookup | `asyncio.to_thread()` — non-blocking |
| Passive (probe) | Network latency | Concurrent with semaphore (20 threads) |
| Active (port scan) | Socket connect timeout | Thread pool + configurable timeout |
| Fuzzing | Wordlist size (4.6k paths) | Batched with `asyncio.gather` |
| JS mining | Large JS files | Regex scan, not full parse |
