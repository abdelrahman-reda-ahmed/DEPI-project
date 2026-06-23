from __future__ import annotations

import os
from pathlib import Path
from typing import Any, Optional

import yaml
from rich.console import Console

DEFAULT_CONFIG_PATH = Path("config.yaml")

_console = Console()


class DORAConfig:
    def __init__(self, path: Optional[Path] = None):
        self._data: dict[str, Any] = {}
        self._load(path or DEFAULT_CONFIG_PATH)
        self._apply_env_overrides()

    def _load(self, path: Path):
        if path.exists():
            with open(path) as f:
                self._data = yaml.safe_load(f) or {}
        else:
            self._data = {}

    def _apply_env_overrides(self):
        env_key_map = {
            "DORA_SECURITYTRAILS_KEY": ("api_keys", "securitytrails"),
            "DORA_VIRUSTOTAL_KEY": ("api_keys", "virustotal"),
            "DORA_SHODAN_KEY": ("api_keys", "shodan"),
            "DORA_BUILTWITH_KEY": ("api_keys", "builtwith"),
            "DORA_GITHUB_KEY": ("api_keys", "github"),
            "DORA_THREADS": ("scan", "threads"),
            "DORA_TIMEOUT": ("scan", "timeout"),
        }
        for env_var, keys in env_key_map.items():
            value = os.environ.get(env_var)
            if value is not None:
                section = self._data
                for key in keys[:-1]:
                    section = section.setdefault(key, {})
                section[keys[-1]] = value

    def _get(self, *keys: str, default: Any = None) -> Any:
        section = self._data
        for key in keys:
            if isinstance(section, dict):
                section = section.get(key)
                if section is None:
                    return default
            else:
                return default
        return section if section is not None else default

    @property
    def api_key_securitytrails(self) -> str:
        return str(self._get("api_keys", "securitytrails", default="") or "")

    @property
    def api_key_virustotal(self) -> str:
        return str(self._get("api_keys", "virustotal", default="") or "")

    @property
    def api_key_shodan(self) -> str:
        return str(self._get("api_keys", "shodan", default="") or "")

    @property
    def api_key_builtwith(self) -> str:
        return str(self._get("api_keys", "builtwith", default="") or "")

    @property
    def api_key_github(self) -> str:
        return str(self._get("api_keys", "github", default="") or "")

    @property
    def scan_threads(self) -> int:
        try:
            return int(self._get("scan", "threads", default=20))
        except (ValueError, TypeError):
            return 20

    @property
    def scan_timeout(self) -> int:
        try:
            return int(self._get("scan", "timeout", default=10))
        except (ValueError, TypeError):
            return 10

    @property
    def phase_timeout(self) -> int:
        try:
            return int(self._get("scan", "phase_timeout", default=0))
        except (ValueError, TypeError):
            return 0

    @property
    def scan_retries(self) -> int:
        try:
            return int(self._get("scan", "retries", default=2))
        except (ValueError, TypeError):
            return 2

    @property
    def user_agent(self) -> str:
        return str(self._get("scan", "user_agent",
                             default="Mozilla/5.0 DORA/0.1"))

    @property
    def rate_limit(self) -> float:
        try:
            return float(self._get("scan", "rate_limit", default=0.1))
        except (ValueError, TypeError):
            return 0.1

    @property
    def port_scan_ports(self) -> str:
        return str(self._get("port_scan", "ports",
                             default="21,22,23,25,53,80,110,143,443,445,993,995,1433,1521,2049,3306,3389,5432,5900,6379,8080,8443,9000,27017"))

    @property
    def port_scan_timing(self) -> str:
        return str(self._get("port_scan", "timing_template", default="T4"))

    @property
    def wordlist_subdomains(self) -> Path:
        return Path(str(self._get("wordlists", "subdomains", default="wordlists/subdomains.txt")))

    @property
    def wordlist_subdomains_large(self) -> Path:
        return Path(str(self._get("wordlists", "subdomains_large", default="wordlists/subdomains_deepmagic.txt")))

    @property
    def wordlist_directories(self) -> Path:
        return Path(str(self._get("wordlists", "directories", default="wordlists/directories.txt")))

    @property
    def wordlist_parameters(self) -> Path:
        return Path(str(self._get("wordlists", "parameters", default="wordlists/parameters.txt")))

    @property
    def min_response_size(self) -> int:
        try:
            return int(self._get("scan", "min_response_size", default=100))
        except (ValueError, TypeError):
            return 100

    @property
    def output_format(self) -> str:
        return str(self._get("output", "format", default="json"))

    @property
    def output_dir(self) -> Path:
        return Path(str(self._get("output", "dir", default="reports/")))

    @property
    def verbose(self) -> bool:
        return bool(self._get("output", "verbose", default=False))

    def validate(self) -> list[str]:
        warnings: list[str] = []

        wordlist_paths = {
            "wordlists.subdomains": self.wordlist_subdomains,
            "wordlists.subdomains_large": self.wordlist_subdomains_large,
            "wordlists.directories": self.wordlist_directories,
            "wordlists.parameters": self.wordlist_parameters,
        }
        for name, path in wordlist_paths.items():
            if not path.exists():
                warnings.append(f"Wordlist not found: {name} → {path}")

        try:
            ports_str = self.port_scan_ports
            parts = [p.strip() for p in ports_str.split(",") if p.strip()]
            for part in parts:
                if "-" in part:
                    start, end = part.split("-", 1)
                    int(start); int(end)
                else:
                    int(part)
        except (ValueError, TypeError):
            warnings.append(f"Invalid port_scan.ports value: {self.port_scan_ports!r}")

        if self.scan_threads < 1:
            warnings.append(f"scan.threads should be >= 1 (got {self.scan_threads})")
        if self.scan_timeout < 1:
            warnings.append(f"scan.timeout should be >= 1 (got {self.scan_timeout})")
        if self.rate_limit < 0:
            warnings.append(f"scan.rate_limit should be >= 0 (got {self.rate_limit})")
        if self.min_response_size < 0:
            warnings.append(f"scan.min_response_size should be >= 0 (got {self.min_response_size})")

        api_keys_present = sum(1 for k in ["api_key_securitytrails", "api_key_virustotal",
                                            "api_key_shodan", "api_key_builtwith", "api_key_github"]
                               if getattr(self, k, ""))
        if api_keys_present == 0:
            warnings.append("No API keys configured — set DORA_* env vars or add to config.yaml")

        valid_formats = {"json", "html", "md", "markdown", "all"}
        if self.output_format not in valid_formats:
            warnings.append(f"output.format should be one of {valid_formats} (got {self.output_format!r})")

        if warnings:
            _console.print("[yellow]Config warnings:[/yellow]")
            for w in warnings:
                _console.print(f"  [dim]- {w}[/]")

        return warnings
