from __future__ import annotations

import asyncio
import io
import queue
import sys
import threading
import tkinter as tk
from tkinter import ttk
from datetime import datetime
from typing import Callable, Optional

from dora import __version__
from pathlib import Path
from datetime import datetime

from dora import __version__
from dora.config import DORAConfig
from dora.engine import DORAEngine, PHASE_MAP
from dora.models import Finding, ScanResult, Severity
from dora.utils.output import export_markdown

BG_BLACK = "#0a0a0a"
BG_DARK = "#111111"
BG_MID = "#1a1a1a"
BG_INPUT = "#0d1b0d"
FG_GREEN = "#00ff41"
FG_CYAN = "#00e5ff"
FG_RED = "#ff1744"
FG_YELLOW = "#ffea00"
FG_ORANGE = "#ff9100"
FG_WHITE = "#c0c0c0"
FG_DIM = "#555555"
FG_BLUE = "#00b0ff"
SELECT_BG = "#003300"
ACTIVE_BG = "#004400"
PANEL_BG = "#0d0d0d"

FONT = "Consolas"
FONT_SIZES = {"huge": 14, "big": 12, "normal": 10, "small": 9, "tiny": 8}

SEVERITY_COLORS = {
    Severity.CRITICAL: FG_RED,
    Severity.HIGH: FG_ORANGE,
    Severity.MEDIUM: FG_YELLOW,
    Severity.LOW: FG_BLUE,
    Severity.INFO: FG_GREEN,
}


def _style(style: ttk.Style):
    style.theme_use("clam")
    root_bg = BG_BLACK

    style.configure(".", background=root_bg, foreground=FG_WHITE, font=(FONT, FONT_SIZES["normal"]))
    style.configure("TFrame", background=root_bg)
    style.configure("TLabel", background=root_bg, foreground=FG_WHITE, font=(FONT, FONT_SIZES["normal"]))
    style.configure("Heading.TLabel", foreground=FG_CYAN, font=(FONT, FONT_SIZES["big"], "bold"))
    style.configure("Emphasis.TLabel", foreground=FG_GREEN)
    style.configure("Dim.TLabel", foreground=FG_DIM, font=(FONT, FONT_SIZES["tiny"]))
    style.configure("TLabelframe", background=root_bg, bordercolor=FG_DIM, foreground=FG_CYAN)
    style.configure("TLabelframe.Label", background=root_bg, foreground=FG_CYAN, font=(FONT, FONT_SIZES["small"]))

    style.configure("TButton", background=BG_DARK, foreground=FG_GREEN, bordercolor=BG_DARK, font=(FONT, FONT_SIZES["normal"]), padding=(12, 3))
    style.map("TButton", background=[("active", SELECT_BG), ("pressed", ACTIVE_BG)], foreground=[("active", FG_CYAN)])
    style.configure("Danger.TButton", foreground=FG_RED)
    style.map("Danger.TButton", foreground=[("active", FG_RED)], background=[("active", "#330000")])

    style.configure("TCheckbutton", background=root_bg, foreground=FG_WHITE, font=(FONT, FONT_SIZES["normal"]))
    style.map("TCheckbutton", background=[("active", root_bg)], foreground=[("active", FG_GREEN)])
    style.configure("TRadiobutton", background=root_bg, foreground=FG_WHITE, font=(FONT, FONT_SIZES["normal"]))
    style.map("TRadiobutton", background=[("active", root_bg)], foreground=[("active", FG_GREEN)])

    style.configure("TEntry", fieldbackground=BG_INPUT, foreground=FG_GREEN, bordercolor=BG_MID, insertcolor=FG_GREEN, font=(FONT, FONT_SIZES["normal"]))
    style.map("TEntry", bordercolor=[("focus", FG_CYAN)])

    style.configure("TNotebook", background=root_bg, bordercolor=BG_MID)
    style.configure("TNotebook.Tab", background=BG_DARK, foreground=FG_DIM, font=(FONT, FONT_SIZES["small"]), padding=(14, 4))
    style.map("TNotebook.Tab", background=[("selected", root_bg), ("active", BG_MID)], foreground=[("selected", FG_CYAN)])

    style.configure("TProgressbar", background=FG_GREEN, troughcolor=BG_DARK, bordercolor=BG_MID, lightcolor=FG_GREEN, darkcolor=FG_GREEN)

    style.configure("Treeview", background=BG_DARK, foreground=FG_WHITE, fieldbackground=BG_DARK, bordercolor=BG_MID, font=(FONT, FONT_SIZES["small"]), rowheight=24)
    style.configure("Treeview.Heading", background=BG_MID, foreground=FG_CYAN, font=(FONT, FONT_SIZES["small"], "bold"))
    style.map("Treeview", background=[("selected", SELECT_BG)], foreground=[("selected", FG_GREEN)])

    style.configure("TScale", background=root_bg, troughcolor=BG_DARK, slidercolor=FG_GREEN)
    style.map("TScale", background=[("active", root_bg)])


class TextHandler(io.StringIO):
    def __init__(self, callback: Callable[[str], None]):
        super().__init__()
        self.callback = callback

    def write(self, text: str):
        if text and text.strip():
            self.callback(text)
        super().write(text)

    def flush(self):
        pass


class FindingsTable(ttk.Frame):
    def __init__(self, parent, **kwargs):
        super().__init__(parent, **kwargs)
        self.columns = ("severity", "type", "name", "value", "source")
        self.tree = ttk.Treeview(self, columns=self.columns, show="headings", select="browse")

        widths = {"severity": 90, "type": 120, "name": 180, "value": 300, "source": 140}
        labels = {"severity": "Severity", "type": "Type", "name": "Name", "value": "Value", "source": "Source"}

        for col in self.columns:
            self.tree.heading(col, text=labels[col])
            self.tree.column(col, width=widths[col], anchor="w")

        vsb = ttk.Scrollbar(self, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=vsb.set)

        self.tree.grid(row=0, column=0, sticky="nsew")
        vsb.grid(row=0, column=1, sticky="ns")
        self.grid_rowconfigure(0, weight=1)
        self.grid_columnconfigure(0, weight=1)

        self._tag_map = {}

    def set_findings(self, findings: list[Finding]) -> None:
        for item in self.tree.get_children():
            self.tree.delete(item)
        self._tag_map.clear()

        for f in findings:
            color = SEVERITY_COLORS.get(f.severity, FG_WHITE)
            tag = f"sev_{f.severity.value}"
            if tag not in self._tag_map:
                self.tree.tag_configure(tag, foreground=color)
                self._tag_map[tag] = True

            self.tree.insert("", "end",
                values=(f.severity.value.upper(), f.type.value, f.name, f.value, f.source),
                tags=(tag,))

    def clear(self) -> None:
        for item in self.tree.get_children():
            self.tree.delete(item)


class DORAGUI:
    def __init__(self, root: tk.Tk):
        self.root = root
        self.root.title(f"DORA v{__version__}")
        self.root.geometry("1200x800")
        self.root.configure(bg=BG_BLACK)
        self.root.minsize(900, 600)

        self.scan_running = False
        self._cancel_event = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self._findings: list[Finding] = []
        self._log_queue: queue.Queue[tuple[str, str]] = queue.Queue()

        _style(ttk.Style())
        self._build_ui()
        self._poll_log()

        self.root.protocol("WM_DELETE_WINDOW", self._on_close)

        self._echo("[ SYSTEM ] DORA GUI initialized. Ready.", "cyan")

    # ── UI ──────────────────────────────────────────────────────────

    def _build_ui(self):
        self._build_header()
        self._build_controls()
        self._build_output()
        self._build_status()

        self.root.grid_rowconfigure(2, weight=1)
        self.root.grid_columnconfigure(0, weight=1)

    def _build_header(self):
        banner = ttk.Frame(self.root)
        banner.grid(row=0, column=0, sticky="ew", padx=12, pady=(8, 2))
        banner.grid_columnconfigure(1, weight=1)

        logo_lines = [
            "██████╗  ██████╗ ██████╗  █████╗",
            "██╔══██╗██╔═══██╗██╔══██╗██╔══██╗",
            "██║  ██║██║   ██║██████╔╝███████║",
            "██║  ██║██║   ██║██╔══██╗██╔══██║",
            "██████╔╝╚██████╔╝██║  ██║██║  ██║",
            "╚═════╝  ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝",
        ]
        logo = tk.Text(banner, width=34, height=6, bg=BG_BLACK, fg=FG_GREEN,
                       font=(FONT, FONT_SIZES["tiny"]), relief="flat", highlightthickness=0,
                       padx=0, pady=0, cursor="arrow")
        logo.insert("1.0", "\n".join(logo_lines))
        logo.configure(state="disabled")
        logo.grid(row=0, column=0, rowspan=2)

        title = ttk.Label(banner, text="Automated Reconnaissance & Pentesting Assistant",
                          style="Heading.TLabel")
        title.grid(row=0, column=1, sticky="w", padx=(14, 0), pady=(4, 0))

        ver = ttk.Label(banner, text=f"v{__version__}  |  [ passive · active · fuzzing · js · vuln ]",
                        style="Dim.TLabel")
        ver.grid(row=1, column=1, sticky="w", padx=(14, 0))

        sep = ttk.Separator(self.root, orient="horizontal")
        sep.grid(row=0, column=0, sticky="ew", padx=8, pady=(52, 0))

    def _build_controls(self):
        ctrl = ttk.LabelFrame(self.root, text=" CONTROL PANEL ", padding=(10, 6))
        ctrl.grid(row=1, column=0, sticky="ew", padx=12, pady=(6, 4))
        ctrl.grid_columnconfigure(1, weight=1)
        ctrl.grid_columnconfigure(3, weight=1)

        row = 0
        ttk.Label(ctrl, text="Target:").grid(row=row, column=0, sticky="w", padx=(0, 6))
        self.target_entry = ttk.Entry(ctrl)
        self.target_entry.grid(row=row, column=1, sticky="ew", padx=(0, 6))
        self.target_entry.insert(0, "example.com")
        self.target_entry.bind("<Return>", lambda e: self._run_scan())

        self.scan_btn = ttk.Button(ctrl, text="⚡ SCAN", command=self._run_scan)
        self.scan_btn.grid(row=row, column=2, padx=(0, 4))

        self.quick_btn = ttk.Button(ctrl, text="⚡ QUICK", command=self._run_quick)
        self.quick_btn.grid(row=row, column=3, padx=(0, 4))

        self.stop_btn = ttk.Button(ctrl, text="■ STOP", style="Danger.TButton", command=self._stop_scan)
        self.stop_btn.grid(row=row, column=4, padx=(0, 2))
        self.stop_btn.configure(state="disabled")

        ttk.Button(ctrl, text="Clear", command=self._clear_output).grid(row=row, column=5)

        row = 1
        ttk.Label(ctrl, text="Phases:").grid(row=row, column=0, sticky="w", padx=(0, 6))
        phases_frame = ttk.Frame(ctrl)
        phases_frame.grid(row=row, column=1, columnspan=2, sticky="w", pady=2)

        self.phase_vars = {}
        phase_labels = {
            "passive": "Passive",
            "active": "Active",
            "fuzzing": "Fuzzing",
            "js": "JS Mining",
            "vuln": "Vuln Check",
        }
        for i, (key, label) in enumerate(phase_labels.items()):
            var = tk.BooleanVar(value=True)
            self.phase_vars[key] = var
            cb = ttk.Checkbutton(phases_frame, text=label, variable=var)
            cb.grid(row=0, column=i, padx=(0, 10))

        row = 2
        ttk.Label(ctrl, text="Output:").grid(row=row, column=0, sticky="w", padx=(0, 6))
        self.format_var = tk.StringVar(value="html")
        fmt_frame = ttk.Frame(ctrl)
        fmt_frame.grid(row=row, column=1, sticky="w", pady=2)
        for i, fmt in enumerate(["html", "json", "md", "all"]):
            ttk.Radiobutton(fmt_frame, text=fmt.upper(), variable=self.format_var, value=fmt).grid(row=0, column=i, padx=(0, 8))

        ttk.Label(ctrl, text="Threads:").grid(row=row, column=2, sticky="e", padx=(10, 4))
        self.threads_var = tk.IntVar(value=20)
        self.threads_spin = ttk.Spinbox(ctrl, from_=1, to=100, textvariable=self.threads_var, width=5)
        self.threads_spin.grid(row=row, column=3, sticky="w", padx=(0, 10))

        ttk.Label(ctrl, text="Timeout:").grid(row=row, column=4, sticky="e", padx=(10, 4))
        self.timeout_var = tk.IntVar(value=10)
        self.timeout_spin = ttk.Spinbox(ctrl, from_=1, to=120, textvariable=self.timeout_var, width=5)
        self.timeout_spin.grid(row=row, column=5, sticky="w")

    def _build_output(self):
        out = ttk.Frame(self.root)
        out.grid(row=2, column=0, sticky="nsew", padx=12, pady=(2, 4))
        out.grid_rowconfigure(0, weight=1)
        out.grid_columnconfigure(0, weight=1)

        nb = ttk.Notebook(out)
        nb.grid(row=0, column=0, sticky="nsew")

        console_frame = ttk.Frame(nb)
        nb.add(console_frame, text="  Console  ")
        console_frame.grid_rowconfigure(0, weight=1)
        console_frame.grid_columnconfigure(0, weight=1)

        self.console = tk.Text(console_frame, bg=BG_BLACK, fg=FG_GREEN,
                               font=(FONT, FONT_SIZES["normal"]), relief="flat",
                               highlightthickness=0, insertbackground=FG_GREEN,
                               padx=8, pady=6, wrap="word", state="disabled",
                               cursor="arrow")
        self.console.grid(row=0, column=0, sticky="nsew")

        console_scroll = ttk.Scrollbar(console_frame, orient="vertical", command=self.console.yview)
        console_scroll.grid(row=0, column=1, sticky="ns")
        self.console.configure(yscrollcommand=console_scroll.set)

        self.console.tag_configure("green", foreground=FG_GREEN)
        self.console.tag_configure("cyan", foreground=FG_CYAN)
        self.console.tag_configure("red", foreground=FG_RED)
        self.console.tag_configure("yellow", foreground=FG_YELLOW)
        self.console.tag_configure("orange", foreground=FG_ORANGE)
        self.console.tag_configure("dim", foreground=FG_DIM)
        self.console.tag_configure("white", foreground=FG_WHITE)
        self.console.tag_configure("bold", font=(FONT, FONT_SIZES["normal"], "bold"))

        findings_frame = ttk.Frame(nb)
        nb.add(findings_frame, text="  Findings  ")
        findings_frame.grid_rowconfigure(0, weight=1)
        findings_frame.grid_columnconfigure(0, weight=1)

        self.findings_table = FindingsTable(findings_frame)
        self.findings_table.grid(row=0, column=0, sticky="nsew")

        findings_controls = ttk.Frame(findings_frame)
        findings_controls.grid(row=1, column=0, sticky="ew", pady=(4, 0))
        ttk.Label(findings_controls, text="Findings:", style="Emphasis.TLabel").pack(side="left")
        self.finding_count_label = ttk.Label(findings_controls, text="0")
        self.finding_count_label.pack(side="left", padx=(4, 0))

        self.notebook = nb

        progress_frame = ttk.Frame(self.root)
        progress_frame.grid(row=3, column=0, sticky="ew", padx=12, pady=(0, 4))
        progress_frame.grid_columnconfigure(0, weight=1)
        self.progress = ttk.Progressbar(progress_frame, mode="indeterminate")
        self.progress.grid(row=0, column=0, sticky="ew")
        self.progress_label = ttk.Label(progress_frame, text="", style="Dim.TLabel")
        self.progress_label.grid(row=0, column=0)

    def _build_status(self):
        status = ttk.Frame(self.root, style="TFrame")
        status.grid(row=4, column=0, sticky="ew", padx=12, pady=(0, 6))
        status.grid_columnconfigure(1, weight=1)

        self.status_light = tk.Canvas(status, width=10, height=10, bg=BG_BLACK, highlightthickness=0)
        self.status_light.grid(row=0, column=0, padx=(0, 6))
        self._dot = self.status_light.create_oval(1, 1, 9, 9, fill=FG_DIM, outline="")

        self.status_label = ttk.Label(status, text="Ready", style="Dim.TLabel")
        self.status_label.grid(row=0, column=1, sticky="w")

        self.target_label = ttk.Label(status, text="Target: —", style="Dim.TLabel")
        self.target_label.grid(row=0, column=2, sticky="e", padx=(0, 14))

        self.footer_findings = ttk.Label(status, text="Findings: 0", style="Dim.TLabel")
        self.footer_findings.grid(row=0, column=3, sticky="e")

    # ── Logging ─────────────────────────────────────────────────────

    def _echo(self, text: str, tag: str = "green") -> None:
        self.console.configure(state="normal")
        ts = datetime.now().strftime("%H:%M:%S")
        self.console.insert("end", f"[{ts}] ", "dim")
        self.console.insert("end", text + "\n", tag)
        self.console.see("end")
        self.console.configure(state="disabled")

    def _log_to_gui(self, text: str, tag: str = "green") -> None:
        self._log_queue.put((text, tag))

    def _poll_log(self) -> None:
        while not self._log_queue.empty():
            try:
                text, tag = self._log_queue.get_nowait()
                self._echo(text, tag)
            except queue.Empty:
                break
        self.root.after(50, self._poll_log)

    def _set_status(self, text: str, color: str = FG_DIM) -> None:
        self.status_label.configure(text=text)
        self.status_light.itemconfigure(self._dot, fill=color)

    def _update_finding_count(self):
        n = len(self._findings)
        self.finding_count_label.configure(text=str(n))
        self.footer_findings.configure(text=f"Findings: {n}")
        self.findings_table.set_findings(self._findings)

    def _clear_output(self):
        self.console.configure(state="normal")
        self.console.delete("1.0", "end")
        self.console.configure(state="disabled")
        self._findings.clear()
        self.findings_table.clear()
        self._update_finding_count()

    # ── Scan control ────────────────────────────────────────────────

    def _set_scanning(self, active: bool):
        self.scan_running = active
        state = "disabled" if active else "normal"
        self.scan_btn.configure(state=state)
        self.quick_btn.configure(state=state)
        self.stop_btn.configure(state="normal" if active else "disabled")
        self.target_entry.configure(state=state)

        if active:
            self.progress.start(15)
            self._set_status("Scanning...", FG_GREEN)
        else:
            self.progress.stop()
            self._set_status("Ready", FG_DIM)

    def _run_scan(self):
        if self.scan_running:
            return
        target = self.target_entry.get().strip()
        if not target:
            self._echo("[!] Please enter a target.", "red")
            return

        selected = [k for k, v in self.phase_vars.items() if v.get()]
        if not selected:
            self._echo("[!] Select at least one phase.", "red")
            return

        self._findings.clear()
        self.findings_table.clear()
        self._update_finding_count()
        self._cancel_event.clear()
        self._set_scanning(True)
        self._echo(f"[>] Starting scan: {target}", "cyan")
        self._echo(f"[>] Phases: {', '.join(selected)}", "cyan")
        self._echo(f"[>] Format: {self.format_var.get()}", "cyan")
        self.target_label.configure(text=f"Target: {target}")

        cfg = {
            "targets": [target],
            "phases": selected,
            "format": self.format_var.get(),
            "threads": self.threads_var.get(),
            "timeout": self.timeout_var.get(),
        }

        self._thread = threading.Thread(target=self._scan_worker, args=(cfg,), daemon=True)
        self._thread.start()

    def _run_quick(self):
        if self.scan_running:
            return
        for var in self.phase_vars.values():
            var.set(True)
        self._run_scan()

    def _stop_scan(self):
        if self.scan_running:
            self._cancel_event.set()
            self._echo("[!] Cancelling scan...", "yellow")
            self._set_status("Cancelling...", FG_YELLOW)

    # ── Worker ──────────────────────────────────────────────────────

    def _scan_worker(self, cfg: dict):
        handler = TextHandler(lambda t: self._log_to_gui(t.rstrip(), "green"))
        old_stdout = sys.stdout
        sys.stdout = handler

        async def _run():
            config = DORAConfig()
            config._data.setdefault("output", {})["format"] = cfg["format"]
            config._data.setdefault("scan", {})["threads"] = cfg["threads"]
            config._data.setdefault("scan", {})["timeout"] = cfg["timeout"]

            engine = DORAEngine(config)
            findings: list[Finding] = []
            resolved = engine.resolve_phases(cfg["phases"])

            for phase_key in resolved:
                if self._cancel_event.is_set():
                    self._log_to_gui("[!] Scan cancelled by user.", "yellow")
                    return
                if phase_key not in PHASE_MAP:
                    continue
                name, runner = PHASE_MAP[phase_key]
                self._log_to_gui(f"[*] Phase: {name}", "cyan")
                try:
                    from dora.targets import parse_targets
                    targets = parse_targets(cfg["targets"])
                    await runner(targets, config, findings)
                    self._log_to_gui(f"    OK — {len(findings)} total findings", "green")
                except Exception as e:
                    self._log_to_gui(f"    ERROR: {e}", "red")

                self.root.after(0, self._update_findings_from, findings)

            if not self._cancel_event.is_set():
                from dora.phases.reporting import generate_report as _cli_report
                for target in parse_targets(cfg["targets"]):
                    result = ScanResult(target=target, findings=findings, phases_executed=resolved)
                    result.end_time = datetime.utcnow()

                    safe_name = target.raw.replace("://", "_").replace("/", "_").replace(".", "_")
                    ts = result.start_time.strftime("%Y%m%d_%H%M%S")
                    md_path = Path("reports") / f"{safe_name}_{ts}.md"

                    try:
                        md_path.parent.mkdir(parents=True, exist_ok=True)
                        export_markdown(result, md_path)
                        self._log_to_gui(f"[+] Saved: {md_path}", "cyan")
                    except Exception as e:
                        self._log_to_gui(f"[!] MD report error: {e}", "red")

                    try:
                        _cli_report(result, config)
                    except Exception as e:
                        self._log_to_gui(f"[!] CLI report error: {e}", "red")

            self._log_to_gui(f"[✓] Scan complete — {len(findings)} findings", "green")

        try:
            asyncio.run(_run())
        except Exception as e:
            self._log_to_gui(f"[X] Fatal: {e}", "red")
        finally:
            sys.stdout = old_stdout
            self.root.after(0, self._set_scanning, False)

    def _update_findings_from(self, findings: list[Finding]):
        self._findings = list(findings)
        self._update_finding_count()

    def _on_close(self):
        if self.scan_running:
            self._cancel_event.set()
        self.root.destroy()


def main():
    root = tk.Tk()
    DORAGUI(root)
    root.mainloop()


if __name__ == "__main__":
    main()
