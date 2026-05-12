# AGENTS.md

## Project

DORA — a Python CLI tool for automated reconnaissance in pentesting workflows.

## Architecture

```
dora/
├── cli.py           # Typer CLI entry point
├── engine.py         # Scan orchestrator, phase resolution
├── config.py         # YAML + env-var config loader
├── models.py         # Target, Finding, ScanResult dataclasses
├── targets.py        # Target parsing (domain/IP/CIDR)
├── phases/
│   ├── passive.py    # Subdomain enum (crt.sh, DNS, tech detect)
│   ├── active.py     # TCP port scan, banner grab, HTTP probe
│   ├── fuzzing.py    # Dir/API/param fuzzing with wordlists
│   ├── js_mining.py  # JS crawl, URL/secret extraction (regex)
│   ├── vuln_check.py # SSL/TLS, security headers, CORS
│   └── reporting.py  # JSON/MD/HTML report generation
└── utils/
    ├── http.py       # Async HTTP client wrapper
    ├── async_runner.py # Semaphore-based concurrent runner
    └── output.py     # Rich console + report exporters
```

## Key Commands

```bash
pip install .                     # install from source
dora scan example.com             # full scan
dora scan example.com -p passive  # single phase
dora scan example.com --format html
dora quick example.com            # all phases, default config
dora list-phases                  # show available phases
```

## Conventions

- All I/O is async via `asyncio` + `httpx`. Phase runners receive a shared `findings: list[Finding]` that they append to.
- New phases follow the pattern: `async def run_*_phase(targets, config, findings)` in `phases/`, registered in `PHASE_MAP` in `engine.py`.
- Findings use `Finding` dataclass from `models.py` with typed `Severity` and `FindingType` enums.
- Config is loaded from `config.yaml` with `DORA_*` env var overrides. API keys go in config or env vars.
- Reports default to `reports/` dir. Format: json/html/md.

## API Keys (Optional)

No keys needed for core scans. Optional keys for enriched subdomain data:
`DORA_SECURITYTRAILS_KEY`, `DORA_VIRUSTOTAL_KEY`, `DORA_SHODAN_KEY`, `DORA_GITHUB_KEY`.

## Dependencies

Python 3.10+, no system deps besides Python. Nmap and Go tools are **not** required — port scanning uses raw sockets, fuzzing uses httpx. Wordlists are bundled.
