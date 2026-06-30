from __future__ import annotations

import asyncio
import warnings
from datetime import datetime
from typing import Optional

from rich.console import Console

from dora import __version__
from dora.config import DORAConfig
from dora.models import Finding, ScanResult, Target
from dora.targets import parse_targets
from dora.phases.passive import run_passive_phase
from dora.phases.active import run_active_phase
from dora.phases.fuzzing import run_fuzzing_phase
from dora.phases.js_mining import run_js_mining_phase
from dora.phases.vuln_check import run_vuln_check_phase
from dora.phases.reporting import generate_report
from dora.utils.output import print_summary
from dora.utils.log import logger

console = Console()

PHASE_MAP = {
    "passive": ("Passive Reconnaissance", run_passive_phase),
    "active": ("Active Reconnaissance", run_active_phase),
    "fuzzing": ("Directory & Parameter Fuzzing", run_fuzzing_phase),
    "js": ("JavaScript & Secret Mining", run_js_mining_phase),
    "vuln": ("Vulnerability Checking", run_vuln_check_phase),
}

ALL_PHASES = list(PHASE_MAP.keys())

PHASE_DEPENDENCIES = {
    "active": ["passive"],
    "fuzzing": ["active"],
    "js": ["active"],
    "vuln": ["active"],
}


def deduplicate_findings(findings: list[Finding]) -> list[Finding]:
    seen: set[tuple[str, str, str]] = set()
    deduped: list[Finding] = []
    for f in findings:
        key = (f.type.value, f.value, f.name)
        if key not in seen:
            seen.add(key)
            deduped.append(f)
    return deduped


class DORAEngine:
    def __init__(self, config: DORAConfig):
        self.config = config
        self.results: list[ScanResult] = []

    def resolve_phases(self, requested: Optional[list[str]]) -> list[str]:
        if not requested or "all" in requested:
            return list(ALL_PHASES)

        resolved = []
        for phase in requested:
            if phase in PHASE_MAP:
                deps = PHASE_DEPENDENCIES.get(phase, [])
                for d in deps:
                    if d not in resolved and d not in requested:
                        resolved.append(d)
                if phase not in resolved:
                    resolved.append(phase)
            elif phase == "subdomain":
                resolved.append("passive")
            elif phase == "dirs":
                resolved.append("fuzzing")
            elif phase == "secrets":
                resolved.append("js")
            else:
                console.print(f"[yellow]Warning: Unknown phase '{phase}', skipping[/]")
        return resolved

    async def run(
        self,
        targets_raw: list[str],
        phases: Optional[list[str]] = None,
        output_path: Optional[str] = None,
        no_report: bool = False,
    ) -> list[ScanResult]:
        targets = parse_targets(targets_raw)
        resolved = self.resolve_phases(phases)
        phase_timeout = self.config.phase_timeout

        console.print(f"[bold cyan]DORA[/] [white]v{__version__} - Reconnaissance Engine[/]")
        console.print(f"[dim]Targets:[/] {', '.join(t.raw for t in targets)}")
        console.print(f"[dim]Phases:[/] {', '.join(resolved)}")
        console.print()

        warnings.filterwarnings("ignore", message="coroutine '.*' was never awaited")
        findings: list[Finding] = []

        for phase_key in resolved:
            if phase_key not in PHASE_MAP:
                continue
            name, runner = PHASE_MAP[phase_key]
            console.print(f"[bold]>> Phase:[/] {name}")
            try:
                if phase_timeout > 0:
                    await asyncio.wait_for(
                        runner(targets, self.config, findings),
                        timeout=phase_timeout,
                    )
                else:
                    await runner(targets, self.config, findings)
                n = len(findings)
                console.print(f"  [green]OK ({n} total findings)[/]")
            except asyncio.TimeoutError:
                console.print(f"  [red]X Phase timed out after {phase_timeout}s[/]")
                logger.warning("Phase %s timed out after %ss", name, phase_timeout)
            except Exception as e:
                console.print(f"  [red]X Error in {name}: {e}[/]")
                logger.error("Error in phase %s: %s", name, e, exc_info=True)
            console.print()

        before = len(findings)
        findings[:] = deduplicate_findings(findings)
        after = len(findings)
        if before != after:
            console.print(f"  [dim]Deduplicated: {before} → {after} findings[/]")

        pips = []
        for target in targets:
            result = ScanResult(target=target, findings=findings, phases_executed=resolved)
            self.results.append(result)

            if not no_report:
                generate_report(result, self.config)

            pips.append(result)

        print_summary(pips[0]) if pips else None

        return pips
