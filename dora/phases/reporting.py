from __future__ import annotations

from datetime import datetime
from pathlib import Path
from typing import Optional

from dora.config import DORAConfig
from dora.models import ScanResult
from dora.utils.output import (
    console,
    export_html,
    export_json,
    export_markdown,
    print_findings_table,
    print_summary,
    print_finding,
    print_findings_table as print_findings_table2,
)


def generate_report(
    result: ScanResult,
    config: DORAConfig,
    output_path: Optional[Path] = None,
):
    result.end_time = datetime.utcnow()

    fmt = config.output_format
    out_dir = config.output_dir
    out_dir.mkdir(parents=True, exist_ok=True)

    safe_name = result.target.raw.replace("://", "_").replace("/", "_").replace(".", "_")
    timestamp = result.start_time.strftime("%Y%m%d_%H%M%S")
    base_name = f"{safe_name}_{timestamp}"

    if output_path:
        _save_report(result, output_path, fmt)
    else:
        if fmt == "json" or fmt == "all":
            export_json(result, out_dir / f"{base_name}.json")
        if fmt == "md" or fmt == "markdown" or fmt == "all":
            export_markdown(result, out_dir / f"{base_name}.md")
        if fmt == "html" or fmt == "all":
            export_html(result, out_dir / f"{base_name}.html")

    print_summary(result)

    by_severity = result.by_severity()
    for sev in ["critical", "high", "medium"]:
        items = by_severity.get(sev, [])
        if items:
            print_findings_table(items, title=f"{sev.upper()} Severity Findings")

    console.print(f"\n[green]Report saved to {out_dir.resolve()}[/]")


def _save_report(result: ScanResult, path: Path, fmt: str):
    ext = path.suffix.lower()
    if ext == ".json" or fmt == "json":
        export_json(result, path)
    elif ext in (".md", ".markdown") or fmt in ("md", "markdown"):
        export_markdown(result, path)
    elif ext == ".html" or fmt == "html":
        export_html(result, path)
    else:
        export_json(result, path)
