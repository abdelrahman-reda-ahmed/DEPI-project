from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Optional

import typer
from rich.console import Console

from dora import __version__
from dora.config import DORAConfig
from dora.engine import DORAEngine
from dora.phases.reporting import generate_report
from dora.utils.output import console

app = typer.Typer(
    name="dora",
    help="DORA - Automated Reconnaissance & Pentesting Assistant",
    add_completion=False,
    rich_markup_mode="rich",
)


def _version_callback(value: bool):
    if value:
        console.print(f"DORA v{__version__}")
        raise typer.Exit()


@app.callback()
def _main(
    version: bool = typer.Option(
        False, "--version", "-V",
        help="Show version and exit",
        callback=_version_callback,
        is_eager=True,
    ),
):
    pass


@app.command()
def scan(
    target: list[str] = typer.Argument(
        ...,
        help="Target domain(s), IP(s), or CIDR range(s)",
    ),
    phases: Optional[list[str]] = typer.Option(
        None, "--phase", "-p",
        help="Phase(s) to run: all, passive, active, fuzzing, js, vuln, subdomain, dirs, secrets",
    ),
    config: Optional[Path] = typer.Option(
        None, "--config", "-c",
        help="Path to config YAML file",
        exists=True,
        dir_okay=False,
    ),
    output: Optional[str] = typer.Option(
        None, "--output", "-o",
        help="Output file path (ext determines format: .json, .md)",
    ),
    output_format: str = typer.Option(
        "json", "--format", "-f",
        help="Output format: json, md, all",
    ),
    threads: int = typer.Option(
        20, "--threads", "-t",
        help="Max concurrent threads/connections",
    ),
    timeout: int = typer.Option(
        10, "--timeout",
        help="Request timeout in seconds",
    ),
    no_report: bool = typer.Option(
        False, "--no-report",
        help="Skip report generation",
    ),
    max_time: int = typer.Option(
        0, "--max-time", "-T",
        help="Maximum time per phase in seconds (0 = no limit)",
    ),
    verbose: bool = typer.Option(
        False, "--verbose", "-v",
        help="Verbose output",
    ),
):
    cfg = DORAConfig(config)

    if output_format:
        cfg._data.setdefault("output", {})["format"] = output_format
    if threads:
        cfg._data.setdefault("scan", {})["threads"] = threads
    if timeout:
        cfg._data.setdefault("scan", {})["timeout"] = timeout
    if max_time:
        cfg._data.setdefault("scan", {})["phase_timeout"] = max_time
    if verbose:
        cfg._data.setdefault("output", {})["verbose"] = verbose

    cfg.validate()

    engine = DORAEngine(cfg)

    phase_list = phases or ["all"]
    asyncio.run(engine.run(target, phases=phase_list, output_path=output, no_report=no_report))


@app.command()
def quick(
    target: str = typer.Argument(
        ...,
        help="Target domain or IP",
    ),
    config: Optional[Path] = typer.Option(
        None, "--config", "-c",
        help="Path to config YAML file",
        exists=True,
        dir_okay=False,
    ),
    max_time: int = typer.Option(
        0, "--max-time", "-T",
        help="Maximum time per phase in seconds (0 = no limit)",
    ),
):
    cfg = DORAConfig(config)
    if max_time:
        cfg._data.setdefault("scan", {})["phase_timeout"] = max_time
    cfg.validate()
    engine = DORAEngine(cfg)
    asyncio.run(engine.run([target], phases=["all"], no_report=False))


@app.command()
def list_phases():
    console.print("[bold]Available Phases:[/bold]")
    console.print("  all       - Run all phases")
    console.print("  passive   - Passive reconnaissance (subdomain enumeration, DNS, tech detection)")
    console.print("  active    - Active reconnaissance (port scanning, HTTP probing)")
    console.print("  fuzzing   - Directory, API endpoint, and parameter fuzzing")
    console.print("  js        - JavaScript analysis and secret mining")
    console.print("  vuln      - Vulnerability checks (SSL/TLS, security headers, CORS)")
    console.print()
    console.print("[bold]Aliases:[/bold]")
    console.print("  subdomain - Alias for passive")
    console.print("  dirs      - Alias for fuzzing")
    console.print("  secrets   - Alias for js")


def entry():
    app()


if __name__ == "__main__":
    entry()
