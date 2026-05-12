# DORA — Automated Reconnaissance & Pentesting Assistant

DORA is a modular, async-first reconnaissance tool that automates the pentesting recon workflow — from passive subdomain enumeration to active vulnerability checks — with zero external system dependencies (no nmap, no Go tools).

## Features

- **5 built-in phases** covering the full recon pipeline
- **No system dependencies** — pure Python, raw sockets for port scanning, `httpx` for HTTP
- **Async-first** — asyncio + semaphore-based concurrency for speed
- **CLI + GUI** — terminal-first with a hacker-themed desktop GUI
- **Auto-saving** — every scan automatically saves a well-structured Markdown report
- **Rich output** — colored terminal output, HTML/JSON/Markdown reports
- **API-key optional** — core scans work out of the box with no keys

---

## Table of Contents

- [Installation](#installation)
- [Quick Start (CLI)](#quick-start-cli)
- [GUI Usage](#gui-usage)
- [CLI Reference](#cli-reference)
- [Configuration](#configuration)
- [Phases](#phases)
- [Output & Reports](#output--reports)
- [Architecture](#architecture)
- [Development](#development)
- [API Keys](#api-keys)
- [License](#license)

---

## Installation

### Prerequisites

Python 3.10 or higher.

```bash
python --version
```

### From source

```bash
git clone https://github.com/abdelrahman-reda-ahmed/DEPI-project
cd DEPI-project
pip install .
```

### From source (editable, for development)

```bash
pip install -e .
```

### Verify

```bash
dora --version
dora list-phases
```

---

## Quick Start (CLI)

```bash
# Full scan (all phases)
dora scan example.com

# Quick scan — all phases, HTML report
dora quick example.com

# Specific phases
dora scan example.com --phase passive
dora scan example.com --phase passive --phase active --phase vuln

# Custom output
dora scan example.com --format md
dora scan example.com --format html -o report.html

# Full workflow
dora scan example.com --phase passive --phase active --format all --verbose
```

---

## GUI Usage

The hacker-themed desktop GUI wraps the entire scan workflow in a terminal-aesthetic interface.

```bash
# Launch the GUI (after pip install)
dora-gui

# Or directly
python -m dora.gui
```

### GUI Layout

```
┌────────────────────────────────────────────────────────────┐
│  ██████╗  ██████╗ ██████╗  █████╗                        │
│  ╚════██╗██╔═══██╗██╔══██╗██╔══██╗                       │
│   █████╔╝██║   ██║██████╔╝███████║                       │
│  ╚═══██╗ ██║   ██║██╔══██╗██╔══██║                       │
│  ██████╔╝╚██████╔╝██║  ██║██║  ██║                       │
│  ╚═════╝  ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝                       │
│ Automated Reconnaissance & Pentesting Assistant            │
├────────────────────────────────────────────────────────────┤
│ Target: [example.com          ] [⚡ SCAN] [⚡ QUICK] [■ STOP]│
│ Phases: [✔ Passive] [✔ Active] [✔ Fuzzing] [✔ JS] [✔ Vuln]│
│ Output: ○ HTML  ○ JSON  ○ MD  ○ ALL   Threads: [20]  ... │
├────────────────────────────────────────────────────────────┤
│ ┌─ Console ───────────────────────────────────────────┐   │
│ │ [14:30:01] [>] Starting scan: example.com           │   │
│ │ [14:30:01] [*] Phase: Passive Reconnaissance        │   │
│ │ [14:30:05]     OK — 12 total findings               │   │
│ │ [14:30:06] [+] Saved: reports/example_com_*.md      │   │
│ │ [14:30:06] [✓] Scan complete — 23 findings          │   │
│ └─────────────────────────────────────────────────────┘   │
│ ┌─ Findings ─────────────────────────────────────────┐   │
│ │ Severity │ Type        │ Name         │ Value      │   │
│ │ CRITICAL │ open_port   │ Open Port    │ 22/tcp     │   │
│ │ HIGH     │ subdomain   │ Subdomain    │ admin.×..  │   │
│ └─────────────────────────────────────────────────────┘   │
│ [████████████████████████████████████████] progress       │
├────────────────────────────────────────────────────────────┤
│ ● Scanning...   │ Target: example.com   │ Findings: 23    │
└────────────────────────────────────────────────────────────┘
```

### GUI Features

| Feature | Description |
|---------|-------------|
| **Target Entry** | Input field with Enter-key binding |
| **SCAN** | Runs only the selected phases |
| **QUICK** | Enables all phases and runs immediately |
| **STOP** | Thread-safe scan cancellation |
| **Phase Checkboxes** | Toggle individual phases on/off |
| **Output Format** | Choose HTML, JSON, MD, or ALL |
| **Threads / Timeout** | Concurrency and request timeout controls |
| **Console Tab** | Real-time color-coded output (green=ok, cyan=info, red=error) |
| **Findings Tab** | Sortable table with severity-colored rows |
| **Progress Bar** | Indeterminate progress indicator during scan |
| **Auto-Save** | Every scan automatically saves to `reports/{target}_{date}.md` |
| **Status Bar** | Live status dot, target name, finding count |

---

## CLI Reference

### Commands

| Command | Description |
|---------|-------------|
| `dora scan` | Run a scan (single or multiple targets) |
| `dora quick` | Quick scan — all phases, default output |
| `dora list-phases` | List available phases and aliases |
| `dora-gui` | Launch the desktop GUI |

### `dora scan` Options

| Flag | Default | Description |
|------|---------|-------------|
| `TARGET...` | _(required)_ | Domain(s), IP(s), or CIDR range(s) |
| `-p, --phase` | `all` | Phase(s): all, passive, active, fuzzing, js, vuln |
| `-f, --format` | `html` | Output format: json, html, md, all |
| `-o, --output` | — | Output file path (ext determines format) |
| `-t, --threads` | `20` | Max concurrent connections |
| `--timeout` | `10` | Request timeout in seconds |
| `-v, --verbose` | — | Verbose output |
| `-c, --config` | `config.yaml` | Path to config YAML file |
| `--no-report` | — | Skip report generation |
| `-V, --version` | — | Show version and exit |

### Aliases

| Alias | Maps To |
|-------|---------|
| `subdomain` | `passive` |
| `dirs` | `fuzzing` |
| `secrets` | `js` |

### Examples

```bash
# Multiple targets
dora scan example.com 192.168.1.0/24

# Single phase with alias
dora scan example.com -p subdomain

# All output formats, high concurrency
dora scan example.com -f all -t 50

# Custom config and output path
dora scan example.com -c custom.yaml -o results/report.html

# Quiet, no report (terminal output only)
dora scan example.com --no-report
```

---

## Configuration

Configuration is loaded from `config.yaml` in the working directory. Environment variables take precedence over YAML values.

### config.yaml

```yaml
api_keys:
  securitytrails: ""
  virustotal: ""
  shodan: ""
  github: ""

scan:
  threads: 20
  timeout: 10
  retries: 2
  user_agent: "Mozilla/5.0 DORA/0.1"
  rate_limit: 0.1

port_scan:
  ports: "21,22,23,25,53,80,110,143,443,445,993,995,1433,1521,2049,3306,3389,5432,5900,6379,8080,8443,9000,27017"
  timing_template: "T4"

wordlists:
  subdomains: "wordlists/subdomains.txt"
  directories: "wordlists/directories.txt"

output:
  format: "json"
  dir: "reports/"
  verbose: false
```

### Environment Variables

| Variable | Overrides | Description |
|----------|-----------|-------------|
| `DORA_SECURITYTRAILS_KEY` | `api_keys.securitytrails` | SecurityTrails API key |
| `DORA_VIRUSTOTAL_KEY` | `api_keys.virustotal` | VirusTotal API key |
| `DORA_SHODAN_KEY` | `api_keys.shodan` | Shodan API key |
| `DORA_BUILTWITH_KEY` | `api_keys.builtwith` | BuiltWith API key |
| `DORA_GITHUB_KEY` | `api_keys.github` | GitHub token |
| `DORA_THREADS` | `scan.threads` | Max concurrent connections |
| `DORA_TIMEOUT` | `scan.timeout` | Request timeout in seconds |

---

## Phases

### Passive Reconnaissance (`passive`)

Subdomain enumeration and OSINT data collection. No API keys required for crt.sh and Wayback Machine.

| Technique | Source | Key Required |
|-----------|--------|-------------|
| Certificate transparency logs | crt.sh | No |
| Historical snapshots | Wayback Machine | No |
| DNS records (A, AAAA, MX, NS, TXT, CNAME, SOA) | System DNS | No |
| DNS zone transfer attempt | Target nameservers | No |
| Technology stack detection | Response analysis | No |
| Subdomain enrichment | SecurityTrails | `DORA_SECURITYTRAILS_KEY` |
| Subdomain enrichment | VirusTotal | `DORA_VIRUSTOTAL_KEY` |

### Active Reconnaissance (`active`)

TCP port scanning with service detection, banner grabbing, and HTTP service probing.

- Scans all configured ports using raw TCP sockets (no nmap)
- Identifies common services via port mapping (FTP, SSH, HTTP, MySQL, Redis, MongoDB, etc.)
- Grabs banners on open ports
- Probes HTTP services with HEAD/GET requests

### Directory & Parameter Fuzzing (`fuzzing`)

Brute-force directory discovery, API endpoint enumeration, and common parameter testing.

- Loads wordlists from `wordlists/` directory
- Tests common API paths (`/api/v1`, `/graphql`, `/swagger.json`, etc.)
- Tests common parameter names (`id`, `q`, `search`, `token`, `debug`, etc.)
- Flags sensitive paths (admin, api, .git, .env) as HIGH severity

### JavaScript & Secret Mining (`js`)

Crawls JavaScript files and extracts embedded URLs, API endpoints, and secrets.

- Finds script tags and sourcemaps
- Extracts URLs and API paths from JS content
- Detects secrets via 15 regex patterns:
  - AWS Access/Secret Keys (CRITICAL)
  - GitHub tokens (CRITICAL)
  - Stripe keys (CRITICAL)
  - Google API keys (HIGH)
  - Private keys / certificates (CRITICAL)
  - Webhooks (CRITICAL)
  - Connection strings (MongoDB, PostgreSQL, MySQL, Redis)
  - Generic tokens, passwords, secrets

### Vulnerability Checking (`vuln`)

SSL/TLS validation, security headers audit, and CORS misconfiguration detection.

| Check | What It Detects |
|-------|----------------|
| SSL/TLS | Certificate expiry, hostname mismatch, weak protocol versions (SSLv2/v3, TLSv1.0/v1.1) |
| Security Headers | Missing HSTS, CSP, X-Content-Type-Options, X-Frame-Options, X-XSS-Protection, Referrer-Policy |
| CORS | Wildcard origin (`*`) misconfiguration |
| OSINT | Server header and X-Powered-By information disclosure |

---

## Output & Reports

### Auto-Save (GUI)

Every scan run from the GUI automatically saves a well-structured Markdown report to:

```
reports/{target}_{YYYYMMDD_HHMMSS}.md
```

The report includes:
- Target metadata (domain, IP, ports)
- Executive summary with severity and type breakdowns
- All findings organized by severity (critical first)
- Each finding with full detail (type, value, description, evidence)

### CLI Reports

The CLI saves reports based on the `--format` flag:

```bash
dora scan example.com --format json    # -> reports/example_com_*.json
dora scan example.com --format md      # -> reports/example_com_*.md
dora scan example.com --format html    # -> reports/example_com_*.html
dora scan example.com --format all     # -> all three formats
```

### Directory Structure

```
reports/
├── example_com_20260512_143001.json
├── example_com_20260512_143001.html
└── example_com_20260512_143001.md
```

---

## Architecture

```
dora/
├── cli.py             # Typer CLI entry point
├── gui.py             # Tkinter hacker-themed GUI
├── engine.py          # Scan orchestrator, phase resolution
├── config.py          # YAML + env-var config loader
├── models.py          # Target, Finding, ScanResult dataclasses
├── targets.py         # Target parsing (domain/IP/CIDR)
├── phases/
│   ├── passive.py     # Subdomain enum (crt.sh, DNS, tech detect)
│   ├── active.py      # TCP port scan, banner grab, HTTP probe
│   ├── fuzzing.py     # Dir/API/param fuzzing with wordlists
│   ├── js_mining.py   # JS crawl, URL/secret extraction
│   ├── vuln_check.py  # SSL/TLS, security headers, CORS
│   └── reporting.py   # Report generation orchestrator
└── utils/
    ├── http.py        # Async HTTP client wrapper (httpx)
    ├── async_runner.py # Semaphore-based concurrent runner
    └── output.py      # Rich console + report exporters (JSON/MD/HTML)
```

### Data Flow

1. **CLI/GUI** parses user input and creates a `DORAConfig`
2. **DORAEngine** resolves requested phases (including dependencies) and iterates through them
3. Each **phase runner** receives `targets`, `config`, and a shared `findings: list[Finding]`
4. Phase runners use **utils** (`AsyncHTTPClient`, `run_concurrently`) for async I/O
5. After all phases, **generate_report** exports findings to the configured format
6. GUI additionally saves an auto-named Markdown report to `reports/`

### Key Design Decisions

| Decision | Rationale |
|----------|-----------|
| Pure Python, no system deps | Easy install on any platform (Windows, Linux, macOS) |
| Async via asyncio + httpx | High concurrency without thread overhead |
| Raw sockets for port scanning | Avoids nmap dependency; works everywhere |
| Findings as shared list | Simple, append-only pattern; phases are independent |
| Dataclasses for models | Lightweight, serializable, no ORM overhead |
| ttk theme for GUI | Zero extra dependencies (built-in tkinter) |

---

## Development

### Setup

```bash
git clone https://github.com/abdelrahman-reda-ahmed/DEPI-project
cd DEPI-project
pip install -e .
```

### Adding a New Phase

1. Create `dora/phases/new_phase.py` with an async runner function:

```python
async def run_new_phase(targets: list[Target], config: DORAConfig, findings: list[Finding]):
    for target in targets:
        findings.append(Finding(
            type=FindingType.OSINT,
            name="Example Finding",
            severity=Severity.INFO,
            value="some_value",
            description="Description here",
            source="new_phase",
        ))
```

2. Register it in `PHASE_MAP` in `dora/engine.py`:

```python
PHASE_MAP = {
    ...
    "new_phase": ("New Phase", run_new_phase),
}
```

3. Optionally add dependencies in `PHASE_DEPENDENCIES`.

### Conventions

- All I/O is async (`asyncio` + `httpx`)
- Phase runners append findings to the shared `list[Finding]` — they never return findings directly
- Findings use `Severity` and `FindingType` enums from `models.py`
- Config is accessed via `DORAConfig` properties (never raw dict access outside `config.py`)
- Wordlists live in `wordlists/` and use paths configured in `config.yaml`

### Project Structure for New Code

```
dora/
├── phases/         # Phase runners (one file per phase)
├── utils/          # Shared utilities
├── models.py       # Data models
├── engine.py       # Phase orchestration
├── config.py       # Configuration
├── cli.py          # CLI entry point
└── gui.py          # GUI entry point
```

---

## API Keys

No API keys are required for core functionality. The following services are optional and enrich passive reconnaissance results.

| Variable | Service | Free Tier | Used By |
|----------|---------|-----------|---------|
| `DORA_SECURITYTRAILS_KEY` | SecurityTrails | 50 req/month | Passive phase — subdomain enumeration |
| `DORA_VIRUSTOTAL_KEY` | VirusTotal | 500 req/day | Passive phase — subdomain enumeration |
| `DORA_SHODAN_KEY` | Shodan | 1 req/second | Passive phase — enrichment |
| `DORA_GITHUB_KEY` | GitHub | Unlimited (public) | Passive phase — enrichment |

Set them as environment variables or in `config.yaml`:

```bash
# PowerShell
$env:DORA_VIRUSTOTAL_KEY = "your_key_here"

# cmd
set DORA_VIRUSTOTAL_KEY=your_key_here

# Linux/macOS
export DORA_VIRUSTOTAL_KEY=your_key_here
```

```yaml
# config.yaml
api_keys:
  virustotal: "your_key_here"
  shodan: "your_key_here"
```

---

## License

MIT
