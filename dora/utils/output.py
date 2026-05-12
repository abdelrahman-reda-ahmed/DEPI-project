from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from typing import Optional

from rich.console import Console
from rich.table import Table
from rich.tree import Tree

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


def export_json(result: ScanResult, path: Path):
    path.write_text(json.dumps(result.to_dict(), indent=2, default=str))
    console.print(f"[green]JSON report saved: {path}[/]")


def export_markdown(result: ScanResult, path: Path):
    lines = [
        f"# DORA Scan Report: {result.target.raw}",
        "",
        f"**Scan Time**: {result.start_time.isoformat()}",
        f"**Duration**: {(result.end_time - result.start_time).total_seconds():.1f}s" if result.end_time else "",
        f"**Total Findings**: {len(result.findings)}",
        "",
        "## Summary",
        "",
        "| Severity | Count |",
        "|----------|-------|",
    ]
    by_sev = result.by_severity()
    for sev in ["critical", "high", "medium", "low", "info"]:
        count = len(by_sev.get(sev, []))
        lines.append(f"| {sev.capitalize()} | {count} |")

    lines.extend(["", "## Findings", ""])
    for f in result.findings:
        lines.extend([
            f"### {f.severity.value.upper()}: {f.name}",
            f"**Value**: `{f.value}`",
            f"**Type**: {f.type.value}",
            f"**Source**: {f.source}",
            f"**Description**: {f.description}",
            f"**Evidence**: {f.evidence}" if f.evidence else "",
            "",
        ])

    path.write_text("\n".join(lines))
    console.print(f"[green]Markdown report saved: {path}[/]")


def export_html(result: ScanResult, path: Path):
    try:
        from jinja2 import Template
        template = Template("""
<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <title>DORA Report - {{ target }}</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #0d1117; color: #c9d1d9; padding: 2rem; }
        h1 { color: #58a6ff; margin-bottom: 0.5rem; }
        h2 { color: #f0f6fc; margin: 1.5rem 0 0.5rem; }
        .meta { color: #8b949e; margin-bottom: 2rem; }
        .severity-critical { border-left: 4px solid #f85149; }
        .severity-high { border-left: 4px solid #d29922; }
        .severity-medium { border-left: 4px solid #d29922; }
        .severity-low { border-left: 4px solid #58a6ff; }
        .severity-info { border-left: 4px solid #8b949e; }
        .card { background: #161b22; border-radius: 6px; padding: 1rem; margin-bottom: 0.75rem; }
        .card h3 { color: #f0f6fc; }
        .card .value { color: #7ee787; font-family: monospace; margin: 0.25rem 0; }
        .card .desc { color: #8b949e; font-size: 0.9rem; }
        .card .meta-row { color: #8b949e; font-size: 0.85rem; margin-top: 0.5rem; }
        .summary-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 1rem; margin-bottom: 2rem; }
        .summary-box { background: #161b22; border-radius: 6px; padding: 1rem; text-align: center; }
        .summary-box .num { font-size: 2rem; font-weight: bold; }
        .summary-box .label { color: #8b949e; font-size: 0.85rem; }
        .bg-critical .num { color: #f85149; }
        .bg-high .num { color: #d29922; }
        .bg-medium .num { color: #d29922; }
        .bg-low .num { color: #58a6ff; }
        .bg-info .num { color: #8b949e; }
    </style>
</head>
<body>
    <h1>DORA Scan Report</h1>
    <div class="meta">
        <strong>Target:</strong> {{ target }}<br>
        <strong>Start:</strong> {{ start_time }}<br>
        {% if end_time %}<strong>End:</strong> {{ end_time }}<br>{% endif %}
        <strong>Total Findings:</strong> {{ total }}
    </div>

    <h2>Summary</h2>
    <div class="summary-grid">
        {% for sev, count in by_severity.items() %}
        <div class="summary-box bg-{{ sev }}">
            <div class="num">{{ count }}</div>
            <div class="label">{{ sev }}</div>
        </div>
        {% endfor %}
    </div>

    <h2>Findings</h2>
    {% for f in findings %}
    <div class="card severity-{{ f.severity.value }}">
        <h3>{{ f.severity.value.upper() }}: {{ f.name }}</h3>
        <div class="value">{{ f.value }}</div>
        {% if f.description %}<div class="desc">{{ f.description }}</div>{% endif %}
        <div class="meta-row">
            Type: {{ f.type.value }} | Source: {{ f.source }}
            {% if f.evidence %} | Evidence: {{ f.evidence }}{% endif %}
        </div>
    </div>
    {% endfor %}
</body>
</html>
        """)
        html = template.render(
            target=result.target.raw,
            start_time=result.start_time.isoformat(),
            end_time=result.end_time.isoformat() if result.end_time else None,
            total=len(result.findings),
            by_severity={k: len(v) for k, v in result.by_severity().items()},
            findings=result.findings,
        )
        path.write_text(html)
        console.print(f"[green]HTML report saved: {path}[/]")
    except ImportError:
        console.print("[yellow]jinja2 not installed, falling back to JSON[/]")
        export_json(result, path.with_suffix(".json"))
