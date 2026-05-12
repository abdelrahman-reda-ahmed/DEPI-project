# DORA — Quickstart Guide

## 1. Prerequisites

Python 3.10 or higher.

```bash
python --version
```

## 2. Install Dependencies

```bash
pip install -r requirements.txt
```

Or install the full package from source:

```bash
pip install .
```

## 3. Set API Keys (Optional but Recommended)

DORA works without any keys, but with keys you get richer results (subdomains via SecurityTrails / VirusTotal, Shodan enrichment).

### Option A — Environment Variables (preferred)

```bash
# Windows (cmd)
set DORA_VIRUSTOTAL_KEY=your_key_here
set DORA_SHODAN_KEY=your_key_here
set DORA_GITHUB_KEY=your_key_here

# Windows (PowerShell)
$env:DORA_VIRUSTOTAL_KEY = "your_key_here"
$env:DORA_SHODAN_KEY = "your_key_here"
$env:DORA_GITHUB_KEY = "your_key_here"

# Linux / macOS
export DORA_VIRUSTOTAL_KEY=your_key_here
export DORA_SHODAN_KEY=your_key_here
export DORA_GITHUB_KEY=your_key_here
```

### Option B — config.yaml

Edit `config.yaml` in the project root:

```yaml
api_keys:
  virustotal: "your_key_here"
  shodan: "your_key_here"
  github: "your_key_here"
```

**Warning:** Do not commit `config.yaml` to a public repo if it contains keys.

### Where to get free API keys

| Service | Sign Up | Free Tier |
|---------|---------|-----------|
| VirusTotal | https://virustotal.com | 500 req/day |
| SecurityTrails | https://securitytrails.com | 50 req/mo |
| Shodan | https://shodan.io | 1 req/sec |
| GitHub | https://github.com/settings/tokens | unlimited public |

## 4. Run a Scan

### Full scan (all phases)

```bash
dora scan example.com
```

### Quick scan (all phases, HTML report)

```bash
dora quick example.com
```

### Single phase

```bash
dora scan example.com --phase passive
dora scan example.com --phase fuzzing
```

### Multiple phases

```bash
dora scan example.com --phase passive --phase active
```

### Custom output

```bash
dora scan example.com --format html -o myreport.html
dora scan example.com --format json
dora scan example.com --format md
```

### List available phases

```bash
dora list-phases
```

## 5. Output

Reports are written to `reports/` by default.

```
reports/
├── example_com_20260512_123456.json
├── example_com_20260512_123456.html
└── example_com_20260512_123456.md
```

## Full Workflow Example

```bash
# 1. Install
git clone https://github.com/abdelrahman-reda-ahmed/DEPI-project
cd DEPI-project
pip install .

# 2. Set keys
set DORA_VIRUSTOTAL_KEY=your_key_here
set DORA_SHODAN_KEY=your_key_here

# 3. Run full scan
dora scan example.com --format html

# 4. View report
open reports/example_com_*.html
```
