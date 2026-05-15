# AGENTS.md

## Entrypoints

- CLI: `dora.cli:app` (Typer) → `dora scan`, `dora quick`, `dora list-phases`
- GUI: `dora.gui:main` → `dora-gui` or `python -m dora.gui`

## Dev install

`pip install -e .` — no test/lint/typecheck/CI infrastructure exists.

## Architecture

```
dora/
├── cli.py              # Typer entry point
├── gui.py              # Tkinter GUI (hacker-themed)
├── engine.py           # DORAEngine — orchestrator, PHASE_MAP, PHASE_DEPENDENCIES
├── config.py           # DORAConfig — YAML + DORA_* env var overrides
├── models.py           # Target, Finding, ScanResult dataclasses; Severity/FindingType enums
├── targets.py          # domain/IP/CIDR parsing
├── phases/
│   ├── passive.py      # Subdomain enum (crt.sh, DNS, tech detect)
│   ├── active.py       # TCP port scan (raw sockets, no nmap), banner grab, HTTP probe
│   ├── fuzzing.py      # Dir/API/param fuzzing with bundled wordlists
│   ├── js_mining.py    # JS crawl, URL/secret extraction (regex)
│   ├── vuln_check.py   # SSL/TLS, security headers, CORS
│   └── reporting.py    # Report export (synchronous, NOT a scan phase)
└── utils/
    ├── http.py         # AsyncHTTPClient (httpx wrapper)
    ├── async_runner.py # Semaphore-based concurrent task runner
    └── output.py       # Rich console + JSON/MD/HTML export
```

## Phase system

- Register new phases in `engine.py` `PHASE_MAP` dict and optional `PHASE_DEPENDENCIES`.
- Dependencies auto-resolve: `active→passive`, `fuzzing/js/vuln→active`.
- Runner signature: `async def run_*_phase(targets: list[Target], config: DORAConfig, findings: list[Finding])`.
- All phases **append** to the same shared `findings` list — never return their own.
- CLI aliases (engine resolves them): `subdomain→passive`, `dirs→fuzzing`, `secrets→js`.
- `dora quick` is a separate CLI command (runs all phases, defaults to HTML output).
- `reporting.py` lives in `phases/` but is NOT a scan phase — it is synchronous, called by `DORAEngine.run()` after all phases complete.

## Conventions

- All I/O is async (`asyncio` + `httpx`), except `reporting.py`.
- Config via `DORAConfig` properties only (never raw dict). Loaded from `config.yaml` or `--config`.
- API keys optional via `DORA_*` env vars: `SECURITYTRAILS`, `VIRUSTOTAL`, `SHODAN`, `BUILTWITH`, `GITHUB`.
- Wordlists bundled in `wordlists/`, sourced from SecLists: `subdomains.txt` (5k), `directories.txt` (4.6k), `parameters.txt` (6.4k), plus `subdomains_deepmagic.txt` (50k). Paths configured in `config.yaml`.
- Reports written to `reports/` (gitignored). Formats: `json`, `html`, `md`, `all`.
- TCP port scanning uses raw Python sockets — no nmap or other system deps.
