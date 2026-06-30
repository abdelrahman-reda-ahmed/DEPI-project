from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path

from rich.console import Console
from rich.table import Table

from dora.models import Finding, ScanResult, Severity

console = Console()

SEVERITY_COLORS = {
    Severity.CRITICAL: "red bold",
    Severity.HIGH: "red",
    Severity.MEDIUM: "yellow",
    Severity.LOW: "blue",
    Severity.INFO: "green",
}


def print_finding(finding: Finding):
    color = SEVERITY_COLORS.get(finding.severity, "white")
    console.print(f"  [{color}][{finding.severity.value.upper()}][/] "
                  f"{finding.name}: {finding.value}")


def print_summary(result: ScanResult):
    summary = result.summary()
    console.print("\n[bold]=== Scan Complete ===[/bold]")
    console.print(f"Target: {result.target.raw}")
    console.print(f"Duration: {result.start_time.isoformat()} -> "
                  f"{result.end_time.isoformat() if result.end_time else 'N/A'}")
    console.print(f"Total findings: {summary['total_findings']}")

    by_severity = result.by_severity()
    if by_severity:
        console.print("\n[bold]By Severity:[/bold]")
        for sev in [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]:
            count = len(by_severity.get(sev.value, []))
            if count > 0:
                color = SEVERITY_COLORS.get(sev, "white")
                console.print(f"  [{color}]{sev.value}: {count}[/]")

    by_type = result.by_type()
    if by_type:
        console.print("\n[bold]By Type:[/bold]")
        for ftype, items in by_type.items():
            console.print(f"  {ftype}: {len(items)}")


def print_findings_table(findings: list[Finding], title: str = "Findings"):
    if not findings:
        return
    table = Table(title=title)
    table.add_column("Severity", style="bold")
    table.add_column("Type")
    table.add_column("Name")
    table.add_column("Value")

    for f in findings:
        color = SEVERITY_COLORS.get(f.severity, "white")
        table.add_row(
            f"[{color}]{f.severity.value.upper()}[/]",
            f.type.value,
            f.name,
            f.value,
        )
    console.print(table)


def export_raw_findings_by_type(result: ScanResult, raw_dir: Path):
    raw_dir.mkdir(parents=True, exist_ok=True)
    by_type = result.by_type()
    for ftype, findings in by_type.items():
        safe_name = ftype.replace(" ", "_").lower()
        filepath = raw_dir / f"{safe_name}.txt"
        lines: list[str] = []
        lines.append(f"# {ftype.upper()} — {len(findings)} finding(s)")
        lines.append(f"# Target: {result.target.raw}")
        lines.append(f"# Scan: {result.start_time.strftime('%Y-%m-%d %H:%M:%S UTC')}")
        lines.append("")
        for i, f in enumerate(findings, 1):
            lines.append(f"[{i}] {f.name}")
            lines.append(f"    Value:       {f.value}")
            lines.append(f"    Severity:    {f.severity.value}")
            lines.append(f"    Source:      {f.source}")
            if f.description:
                lines.append(f"    Description: {f.description}")
            if f.evidence:
                lines.append(f"    Evidence:    {f.evidence}")
            if f.extra:
                for k, v in f.extra.items():
                    lines.append(f"    {k}: {v}")
            lines.append("")
        filepath.write_text("\n".join(lines), encoding="utf-8")
    console.print(f"[green]Raw findings saved to {raw_dir.resolve()}/ ({len(by_type)} files)[/]")


def export_json(result: ScanResult, path: Path):
    path.write_text(json.dumps(result.to_dict(), indent=2, default=str))
    console.print(f"[green]JSON report saved: {path}[/]")


def export_markdown(result: ScanResult, path: Path):
    from datetime import datetime
    from dora import __version__

    start = result.start_time
    end = result.end_time or datetime.utcnow()
    duration = (end - start).total_seconds()
    total = len(result.findings)
    by_sev = result.by_severity()
    by_type = result.by_type()

    sev_order = ["critical", "high", "medium", "low", "info"]
    sev_labels = {"critical": "CRITICAL", "high": "HIGH", "medium": "MEDIUM", "low": "LOW", "info": "INFO"}

    lines: list[str] = []
    _w = lambda *parts: lines.extend(parts)

    _w(f"# DORA Scan Report — {result.target.raw}")
    _w("")
    _w("| Field | Value |")
    _w("|-------|-------|")
    _w(f"| **Target** | `{result.target.raw}` |")
    _w(f"| **Scan Date** | {start.strftime('%Y-%m-%d %H:%M:%S UTC')} |")
    _w(f"| **Duration** | {duration:.1f}s |")
    if result.phases_executed:
        _w(f"| **Phases Executed** | {', '.join(p.capitalize() for p in result.phases_executed)} |")
    _w(f"| **Total Findings** | {total} |")
    _w("")

    # ── Executive Summary ───────────────────────────────────────────
    _w("---")
    _w("")
    _w("## Executive Summary")
    _w("")
    _w("### Severity Breakdown")
    _w("")
    _w("| Severity | Count |")
    _w("|----------|-------|")
    for sev in sev_order:
        count = len(by_sev.get(sev, []))
        _w(f"| {sev_labels[sev]} | {count} |")

    if by_type:
        _w("")
        _w("### Finding Type Breakdown")
        _w("")
        _w("| Type | Count |")
        _w("|------|-------|")
        for ftype in sorted(by_type, key=lambda t: len(by_type[t]), reverse=True):
            _w(f"| {ftype} | {len(by_type[ftype])} |")

    if result.target.domain or result.target.ip:
        _w("")
        _w("### Target Details")
        _w("")
        _w("| Property | Value |")
        _w("|----------|-------|")
        if result.target.domain:
            _w(f"| **Domain** | {result.target.domain} |")
        if result.target.ip:
            _w(f"| **IP** | {result.target.ip} |")
        if result.target.cidr:
            _w(f"| **CIDR** | {result.target.cidr} |")
        if result.target.ports:
            _w(f"| **Open Ports** | {', '.join(str(p) for p in result.target.ports)} |")

    # ── Findings ────────────────────────────────────────────────────
    _w("")
    _w("---")
    _w("")
    _w("## Findings")
    _w("")
    _w(f"*{total} finding(s) listed below, ordered by severity (highest first).*")
    _w("")

    findings_by_sev: dict[str, list[Finding]] = {}
    for f in result.findings:
        findings_by_sev.setdefault(f.severity.value, []).append(f)

    any_findings = False
    for sev in sev_order:
        items = findings_by_sev.get(sev, [])
        if not items:
            continue
        any_findings = True
        _w(f"### {sev_labels[sev]}")
        _w("")
        for i, f in enumerate(items, 1):
            _w(f"#### {i}. {f.name}")
            _w("")
            _w("| Detail | Value |")
            _w("|--------|-------|")
            _w(f"| **Type** | {f.type.value} |")
            _w(f"| **Value** | `{f.value}` |")
            _w(f"| **Severity** | {sev_labels.get(f.severity.value, f.severity.value.upper())} |")
            _w(f"| **Source** | {f.source} |")
            if f.description:
                _w(f"| **Description** | {f.description} |")
            if f.evidence:
                _w(f"| **Evidence** | {f.evidence} |")
            if f.extra:
                for k, v in f.extra.items():
                    _w(f"| **{k}** | {v} |")
            _w("")

    if not any_findings:
        _w("*No findings were discovered during this scan.*")
        _w("")

    # ── Footer ──────────────────────────────────────────────────────
    _w("---")
    _w("")
    _w(f"*Report generated by DORA v{__version__} on {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}*")

    path.write_text("\n".join(lines))
    console.print(f"[green]Markdown report saved: {path}[/]")



