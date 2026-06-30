from __future__ import annotations

import asyncio
import io
import os
import queue
import subprocess
import sys
import threading
import time
import tkinter as tk
from tkinter import ttk
from datetime import datetime
from pathlib import Path
from typing import Callable, Optional

from dora import __version__
from dora.config import DORAConfig
from dora.engine import DORAEngine, PHASE_MAP, deduplicate_findings
from dora.models import Finding, ScanResult, Severity
from dora.utils.output import export_markdown, export_json

BG_ROOT = "#1e1e2e"
BG_PANEL = "#181825"
BG_CARD = "#11111b"
BG_INPUT = "#1e1e2e"
BG_HEADER = "#11111b"

FG_TEXT = "#cdd6f4"
FG_SUBTEXT = "#a6adc8"
FG_DIM = "#585b70"
FG_GREEN = "#a6e3a1"
FG_CYAN = "#89b4fa"
FG_RED = "#f38ba8"
FG_YELLOW = "#f9e2af"
FG_ORANGE = "#fab387"
FG_BLUE = "#89b4fa"
FG_WHITE = "#cdd6f4"
FG_PEACH = "#fab387"
FG_MAUVE = "#cba6f7"

SELECT_BG = "#313244"
ACTIVE_BG = "#45475a"
BORDER_COLOR = "#313244"

FONT = "Segoe UI"
FONT_MONO = "Consolas"
FONT_SIZES = {"huge": 16, "big": 13, "normal": 10, "small": 9, "tiny": 8}

SEVERITY_COLORS = {
    Severity.CRITICAL: FG_RED,
    Severity.HIGH: FG_ORANGE,
    Severity.MEDIUM: FG_YELLOW,
    Severity.LOW: FG_BLUE,
    Severity.INFO: FG_GREEN,
}

SEVERITY_ORDER = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]


def _style(style: ttk.Style):
    style.theme_use("clam")

    style.configure(".", background=BG_ROOT, foreground=FG_TEXT, font=(FONT, FONT_SIZES["normal"]))
    style.configure("TFrame", background=BG_ROOT)
    style.configure("TLabel", background=BG_ROOT, foreground=FG_TEXT, font=(FONT, FONT_SIZES["normal"]))
    style.configure("Heading.TLabel", foreground=FG_CYAN, font=(FONT, FONT_SIZES["big"], "bold"))
    style.configure("Emphasis.TLabel", foreground=FG_GREEN, font=(FONT, FONT_SIZES["normal"]))
    style.configure("Dim.TLabel", foreground=FG_DIM, font=(FONT, FONT_SIZES["small"]))
    style.configure("SeverityCount.TLabel", foreground=FG_TEXT, font=(FONT, FONT_SIZES["small"], "bold"))
    style.configure("TLabelframe", background=BG_PANEL, bordercolor=BORDER_COLOR, foreground=FG_CYAN, relief="flat")
    style.configure("TLabelframe.Label", background=BG_PANEL, foreground=FG_CYAN, font=(FONT, FONT_SIZES["small"], "bold"))

    style.configure("TButton", background=BG_CARD, foreground=FG_TEXT, bordercolor=BORDER_COLOR,
                    font=(FONT, FONT_SIZES["normal"]), padding=(14, 4), relief="flat")
    style.map("TButton", background=[("active", SELECT_BG), ("pressed", ACTIVE_BG)],
              foreground=[("active", FG_CYAN)])
    style.configure("Primary.TButton", foreground=FG_GREEN, font=(FONT, FONT_SIZES["normal"], "bold"))
    style.map("Primary.TButton", foreground=[("active", FG_WHITE)], background=[("active", "#2e4a2e")])
    style.configure("Danger.TButton", foreground=FG_RED)
    style.map("Danger.TButton", foreground=[("active", FG_RED)], background=[("active", "#4a2e2e")])
    style.configure("Action.TButton", foreground=FG_PEACH, font=(FONT, FONT_SIZES["small"]))
    style.map("Action.TButton", foreground=[("active", FG_WHITE)])

    style.configure("TCheckbutton", background=BG_ROOT, foreground=FG_TEXT, font=(FONT, FONT_SIZES["normal"]))
    style.map("TCheckbutton", background=[("active", BG_ROOT)], foreground=[("active", FG_GREEN)])
    style.configure("TRadiobutton", background=BG_ROOT, foreground=FG_TEXT, font=(FONT, FONT_SIZES["normal"]))
    style.map("TRadiobutton", background=[("active", BG_ROOT)], foreground=[("active", FG_GREEN)])

    style.configure("TEntry", fieldbackground=BG_INPUT, foreground=FG_TEXT, bordercolor=BORDER_COLOR,
                    insertcolor=FG_CYAN, font=(FONT, FONT_SIZES["normal"]), padding=(6, 2))
    style.map("TEntry", bordercolor=[("focus", FG_CYAN)])

    style.configure("TSpinbox", fieldbackground=BG_INPUT, foreground=FG_TEXT, bordercolor=BORDER_COLOR,
                    insertcolor=FG_CYAN, font=(FONT, FONT_SIZES["normal"]), padding=(2, 2))
    style.map("TSpinbox", bordercolor=[("focus", FG_CYAN)])

    style.configure("TNotebook", background=BG_ROOT, bordercolor=BORDER_COLOR)
    style.configure("TNotebook.Tab", background=BG_PANEL, foreground=FG_DIM,
                    font=(FONT, FONT_SIZES["small"]), padding=(18, 6))
    style.map("TNotebook.Tab", background=[("selected", BG_ROOT), ("active", SELECT_BG)],
              foreground=[("selected", FG_CYAN)])

    style.configure("TProgressbar", background=FG_GREEN, troughcolor=BG_PANEL, bordercolor=BORDER_COLOR,
                    lightcolor=FG_GREEN, darkcolor=FG_GREEN)

    style.configure("Treeview", background=BG_CARD, foreground=FG_TEXT, fieldbackground=BG_CARD,
                    bordercolor=BORDER_COLOR, font=(FONT, FONT_SIZES["small"]), rowheight=26)
    style.configure("Treeview.Heading", background=BG_PANEL, foreground=FG_CYAN,
                    font=(FONT, FONT_SIZES["small"], "bold"), relief="flat")
    style.map("Treeview", background=[("selected", SELECT_BG)], foreground=[("selected", FG_CYAN)])

    style.configure("TScale", background=BG_ROOT, troughcolor=BG_PANEL, slidercolor=FG_GREEN)
    style.map("TScale", background=[("active", BG_ROOT)])

    style.configure("TCombobox", fieldbackground=BG_INPUT, foreground=FG_TEXT, bordercolor=BORDER_COLOR,
                    font=(FONT, FONT_SIZES["normal"]), padding=(4, 2))
    style.map("TCombobox", bordercolor=[("focus", FG_CYAN)], fieldbackground=[("readonly", BG_INPUT)])

    style.configure("Filter.TCombobox", fieldbackground=BG_CARD, foreground=FG_TEXT, bordercolor=BORDER_COLOR,
                    font=(FONT, FONT_SIZES["small"]), padding=(2, 2))


class TextHandler(io.StringIO):
    def __init__(self, callback: Callable[[str], None]):
        super().__init__()
        self.callback = callback

    def write(self, text: str):
        stripped = text.rstrip()
        if stripped:
            self.callback(stripped)
        super().write(text)

    def flush(self):
        pass


class FindingsTable(ttk.Frame):
    def __init__(self, parent, **kwargs):
        super().__init__(parent, **kwargs)
        self.columns = ("severity", "type", "name", "value", "source")
        self.tree = ttk.Treeview(self, columns=self.columns, show="headings", select="browse")

        widths = {"severity": 85, "type": 115, "name": 175, "value": 320, "source": 130}
        labels = {"severity": "Severity", "type": "Type", "name": "Name", "value": "Value", "source": "Source"}

        for col in self.columns:
            self.tree.heading(col, text=labels[col])
            self.tree.column(col, width=widths[col], anchor="w", minwidth=50)

        vsb = ttk.Scrollbar(self, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=vsb.set)

        self.tree.grid(row=0, column=0, sticky="nsew")
        vsb.grid(row=0, column=1, sticky="ns")
        self.grid_rowconfigure(0, weight=1)
        self.grid_columnconfigure(0, weight=1)

        self._all_findings: list[Finding] = []
        self._tag_map = {}
        self._severity_filter = "all"
        self._search_text = ""

    def set_findings(self, findings: list[Finding]) -> None:
        self._all_findings = list(findings)
        self._apply_filter()

    def set_severity_filter(self, severity: str) -> None:
        self._severity_filter = severity
        self._apply_filter()

    def set_search_text(self, text: str) -> None:
        self._search_text = text.lower()
        self._apply_filter()

    def _apply_filter(self) -> None:
        for item in self.tree.get_children():
            self.tree.delete(item)
        self._tag_map.clear()

        for f in self._all_findings:
            if self._severity_filter != "all" and f.severity.value != self._severity_filter:
                continue
            if self._search_text:
                haystack = f"{f.name} {f.value} {f.description} {f.evidence} {f.type.value}".lower()
                if self._search_text not in haystack:
                    continue
            color = SEVERITY_COLORS.get(f.severity, FG_WHITE)
            tag = f"sev_{f.severity.value}"
            if tag not in self._tag_map:
                self.tree.tag_configure(tag, foreground=color)
                self._tag_map[tag] = True
            self.tree.insert("", "end",
                             values=(f.severity.value.upper(), f.type.value, f.name, f.value, f.source),
                             tags=(tag,))

    def clear(self) -> None:
        self._all_findings.clear()
        for item in self.tree.get_children():
            self.tree.delete(item)

    def get_selected_finding(self) -> Optional[Finding]:
        sel = self.tree.selection()
        if not sel:
            return None
        idx = self.tree.index(sel[0])
        filtered = [f for f in self._all_findings
                    if (self._severity_filter == "all" or f.severity.value == self._severity_filter)
                    and (not self._search_text or self._search_text in
                         f"{f.name} {f.value} {f.description} {f.evidence} {f.type.value}".lower())]
        if 0 <= idx < len(filtered):
            return filtered[idx]
        return None


class DORAGUI:
    def __init__(self, root: tk.Tk):
        self.root = root
        self.root.title(f"DORA v{__version__} — Reconnaissance Engine")
        self.root.configure(bg=BG_ROOT)
        self.root.minsize(1000, 680)

        _center_window(self.root, 1250, 820)

        self.scan_running = False
        self._cancel_event = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self._findings: list[Finding] = []
        self._log_queue: queue.Queue[tuple[str, str]] = queue.Queue()
        self._scan_start_time: float = 0.0
        self._last_report_dir: Optional[Path] = None
        self._timer_running = False

        _style(ttk.Style())
        self._build_ui()
        self._poll_log()

        self.root.protocol("WM_DELETE_WINDOW", self._on_close)
        self._echo("DORA GUI initialized — enter a target and click Scan", "dim")

    # ── Layout ────────────────────────────────────────────────────────

    def _build_ui(self):
        self._build_header()
        self._build_controls()
        self._build_output()
        self._build_status()

        self.root.grid_rowconfigure(2, weight=1)
        self.root.grid_columnconfigure(0, weight=1)

    def _build_header(self):
        banner = ttk.Frame(self.root)
        banner.grid(row=0, column=0, sticky="ew", padx=14, pady=(10, 2))
        banner.grid_columnconfigure(1, weight=1)

        logo_text = "◈ DORA ◈"
        logo = ttk.Label(banner, text=logo_text, font=(FONT_MONO, FONT_SIZES["huge"], "bold"),
                         foreground=FG_CYAN, background=BG_ROOT)
        logo.grid(row=0, column=0, padx=(0, 14))

        info = ttk.Frame(banner)
        info.grid(row=0, column=1, sticky="w")
        ttk.Label(info, text="Automated Reconnaissance & Pentesting Assistant",
                  style="Heading.TLabel").pack(anchor="w")
        ttk.Label(info, text=f"v{__version__}  ·  passive  ·  active  ·  fuzzing  ·  js  ·  vuln",
                  style="Dim.TLabel").pack(anchor="w")

        sep = ttk.Separator(self.root, orient="horizontal")
        sep.grid(row=0, column=0, sticky="ew", padx=8, pady=(54, 0))

    def _build_controls(self):
        ctrl = ttk.LabelFrame(self.root, text="  Scan Configuration  ", padding=(12, 8))
        ctrl.grid(row=1, column=0, sticky="ew", padx=14, pady=(6, 4))
        ctrl.grid_columnconfigure(1, weight=3)
        ctrl.grid_columnconfigure(3, weight=1)

        # ── Row 0: Target + actions ──
        ttk.Label(ctrl, text="Target:").grid(row=0, column=0, sticky="w", padx=(0, 6))
        self.target_entry = ttk.Entry(ctrl)
        self.target_entry.grid(row=0, column=1, sticky="ew", padx=(0, 8), ipady=2)
        self.target_entry.insert(0, "example.com")
        self.target_entry.bind("<Return>", lambda e: self._run_scan())
        _tooltip(self.target_entry, "Domain, IP address, or URL to scan")

        self.scan_btn = ttk.Button(ctrl, text="▶ Scan", style="Primary.TButton", command=self._run_scan)
        self.scan_btn.grid(row=0, column=2, padx=(0, 4))
        _tooltip(self.scan_btn, "Start scan with selected phases")

        self.quick_btn = ttk.Button(ctrl, text="▶▶ Quick", style="Primary.TButton", command=self._run_quick)
        self.quick_btn.grid(row=0, column=3, padx=(0, 4))
        _tooltip(self.quick_btn, "Run all phases with default settings")

        self.stop_btn = ttk.Button(ctrl, text="■ Stop", style="Danger.TButton", command=self._stop_scan)
        self.stop_btn.grid(row=0, column=4, padx=(0, 4))
        self.stop_btn.configure(state="disabled")
        _tooltip(self.stop_btn, "Cancel the running scan")

        ttk.Button(ctrl, text="Clear", command=self._clear_output).grid(row=0, column=5, padx=(0, 2))
        ttk.Button(ctrl, text="Reports", style="Action.TButton", command=self._open_reports).grid(row=0, column=6, padx=(0, 2))
        _tooltip(self.stop_btn, "Cancel the running scan")

        # ── Row 1: Phases + Options ──
        phases_frame = ttk.Frame(ctrl)
        phases_frame.grid(row=1, column=0, columnspan=7, sticky="ew", pady=(6, 2))
        ttk.Label(phases_frame, text="Phases:", style="Dim.TLabel").pack(side="left", padx=(0, 8))

        self.phase_vars = {}
        phase_labels = {
            "passive": "Passive",
            "active": "Active",
            "fuzzing": "Fuzzing",
            "js": "JS Mining",
            "vuln": "Vuln Check",
        }
        for key, label in phase_labels.items():
            var = tk.BooleanVar(value=True)
            self.phase_vars[key] = var
            cb = ttk.Checkbutton(phases_frame, text=label, variable=var)
            cb.pack(side="left", padx=(0, 12))
            _tooltip(cb, f"Run {label} phase")

        ttk.Separator(phases_frame, orient="vertical").pack(side="left", fill="y", padx=8, pady=2)
        ttk.Label(phases_frame, text="Output:", style="Dim.TLabel").pack(side="left", padx=(0, 6))
        self.format_var = tk.StringVar(value="html")
        fmt_combo = ttk.Combobox(phases_frame, textvariable=self.format_var, values=["html", "json", "md", "all"],
                                 state="readonly", width=6)
        fmt_combo.pack(side="left")
        _tooltip(fmt_combo, "Report output format")

        ttk.Label(phases_frame, text="Threads:", style="Dim.TLabel").pack(side="left", padx=(14, 4))
        self.threads_var = tk.IntVar(value=20)
        threads_spin = ttk.Spinbox(phases_frame, from_=1, to=100, textvariable=self.threads_var, width=5)
        threads_spin.pack(side="left")
        _tooltip(threads_spin, "Concurrent scan threads (higher = faster)")

        ttk.Label(phases_frame, text="Timeout:", style="Dim.TLabel").pack(side="left", padx=(14, 4))
        self.timeout_var = tk.IntVar(value=10)
        timeout_spin = ttk.Spinbox(phases_frame, from_=1, to=120, textvariable=self.timeout_var, width=5)
        timeout_spin.pack(side="left")
        _tooltip(timeout_spin, "Request timeout in seconds")

    def _build_output(self):
        out = ttk.Frame(self.root)
        out.grid(row=2, column=0, sticky="nsew", padx=14, pady=(2, 4))
        out.grid_rowconfigure(0, weight=1)
        out.grid_columnconfigure(0, weight=1)

        nb = ttk.Notebook(out)
        nb.grid(row=0, column=0, sticky="nsew")

        # ── Console tab ──
        console_frame = ttk.Frame(nb)
        nb.add(console_frame, text="  Console  ")
        console_frame.grid_rowconfigure(0, weight=1)
        console_frame.grid_columnconfigure(0, weight=1)

        self.console = tk.Text(console_frame, bg=BG_CARD, fg=FG_TEXT,
                               font=(FONT_MONO, FONT_SIZES["small"]), relief="flat",
                               highlightthickness=0, insertbackground=FG_CYAN,
                               padx=10, pady=6, wrap="word", state="disabled",
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
        self.console.tag_configure("bold", font=(FONT_MONO, FONT_SIZES["small"], "bold"))
        self.console.tag_configure("header", foreground=FG_MAUVE, font=(FONT_MONO, FONT_SIZES["small"], "bold"))

        # ── Findings tab ──
        findings_frame = ttk.Frame(nb)
        nb.add(findings_frame, text="  Findings  ")
        findings_frame.grid_rowconfigure(1, weight=1)
        findings_frame.grid_columnconfigure(0, weight=1)

        filter_bar = ttk.Frame(findings_frame)
        filter_bar.grid(row=0, column=0, sticky="ew", pady=(4, 4))
        filter_bar.grid_columnconfigure(2, weight=1)

        ttk.Label(filter_bar, text="Filter:", style="Dim.TLabel").grid(row=0, column=0, padx=(0, 4))
        self.filter_var = tk.StringVar(value="all")
        self.filter_combo = ttk.Combobox(filter_bar, textvariable=self.filter_var,
                                         values=["all", "critical", "high", "medium", "low", "info"],
                                         state="readonly", width=10, style="Filter.TCombobox")
        self.filter_combo.grid(row=0, column=1, padx=(0, 10))
        self.filter_combo.bind("<<ComboboxSelected>>", lambda e: self._apply_filter())
        _tooltip(self.filter_combo, "Filter findings by severity")

        ttk.Label(filter_bar, text="Search:", style="Dim.TLabel").grid(row=0, column=2, padx=(0, 4), sticky="e")
        self.search_var = tk.StringVar()
        self.search_var.trace("w", lambda *a: self._apply_filter())
        search_entry = ttk.Entry(filter_bar, textvariable=self.search_var, width=22)
        search_entry.grid(row=0, column=3, padx=(0, 10))
        _tooltip(search_entry, "Search across finding name, value, description, and type")

        self.finding_count_label = ttk.Label(filter_bar, text="0 total", style="SeverityCount.TLabel")
        self.finding_count_label.grid(row=0, column=4, padx=(0, 8))

        self.severity_labels: dict[str, ttk.Label] = {}
        for i, sev in enumerate(SEVERITY_ORDER):
            lbl = ttk.Label(filter_bar, text="0", style="Dim.TLabel", foreground=SEVERITY_COLORS[sev])
            lbl.grid(row=0, column=5 + i, padx=(0, 4))
            self.severity_labels[sev.value] = lbl
            ttk.Label(filter_bar, text=sev.value[:4].upper(), style="Dim.TLabel",
                      foreground=SEVERITY_COLORS[sev]).grid(row=0, column=5 + i, padx=(0, 0), sticky="w")
            filter_bar.grid_columnconfigure(5 + i, minsize=10)

        action_frame = ttk.Frame(findings_frame)
        action_frame.grid(row=2, column=0, sticky="ew", pady=(4, 0))

        ttk.Button(action_frame, text="Copy Selected", style="Action.TButton",
                   command=self._copy_selected_finding).pack(side="left", padx=(0, 6))
        _tooltip(self.stop_btn, "Cancel the running scan")
        ttk.Button(action_frame, text="Export JSON", style="Action.TButton",
                   command=self._export_findings_json).pack(side="left", padx=(0, 6))
        ttk.Button(action_frame, text="Open Reports", style="Action.TButton",
                   command=self._open_reports).pack(side="left")

        self.findings_table = FindingsTable(findings_frame)
        self.findings_table.grid(row=1, column=0, sticky="nsew", pady=(0, 2))

        self.tree_double_click_binding = self.findings_table.tree.bind("<Double-1>", self._on_finding_double_click)

        # ── Progress bar ──
        progress_frame = ttk.Frame(self.root)
        progress_frame.grid(row=3, column=0, sticky="ew", padx=14, pady=(0, 4))
        progress_frame.grid_columnconfigure(0, weight=1)
        self.progress = ttk.Progressbar(progress_frame, mode="determinate")
        self.progress.grid(row=0, column=0, sticky="ew")
        self.progress_label = ttk.Label(progress_frame, text="", style="Dim.TLabel", background=BG_PANEL)
        self.progress_label.place(relx=0.5, rely=0.5, anchor="center")

        self.notebook = nb

    def _build_status(self):
        status = ttk.Frame(self.root)
        status.grid(row=4, column=0, sticky="ew", padx=14, pady=(0, 8))
        status.grid_columnconfigure(1, weight=1)

        self.status_light = tk.Canvas(status, width=10, height=10, bg=BG_ROOT, highlightthickness=0)
        self.status_light.grid(row=0, column=0, padx=(0, 6))
        self._dot = self.status_light.create_oval(1, 1, 9, 9, fill=FG_DIM, outline="")

        self.status_label = ttk.Label(status, text="Ready", style="Dim.TLabel")
        self.status_label.grid(row=0, column=1, sticky="w")

        self.timer_label = ttk.Label(status, text="", style="Dim.TLabel")
        self.timer_label.grid(row=0, column=2, padx=(0, 14))

        self.target_label = ttk.Label(status, text="", style="Dim.TLabel")
        self.target_label.grid(row=0, column=3, padx=(0, 14))

        self.footer_findings = ttk.Label(status, text="", style="Dim.TLabel")
        self.footer_findings.grid(row=0, column=4)

    # ── Logging ───────────────────────────────────────────────────────

    def _echo(self, text: str, tag: str = "green") -> None:
        self.console.configure(state="normal")
        ts = datetime.now().strftime("%H:%M:%S")
        self.console.insert("end", f" {ts} ", "dim")
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

    def _update_timer(self):
        if not self.scan_running:
            self.timer_label.configure(text="")
            self._timer_running = False
            return
        elapsed = time.time() - self._scan_start_time
        self.timer_label.configure(text=f"⏱ {elapsed:.0f}s")
        self.root.after(500, self._update_timer)

    def _update_finding_count(self):
        n = len(self._findings)
        self.footer_findings.configure(text=f"Findings: {n}")
        self.findings_table.set_findings(self._findings)

        by_sev = {}
        for f in self._findings:
            by_sev[f.severity.value] = by_sev.get(f.severity.value, 0) + 1

        total_display = 0
        for sev in SEVERITY_ORDER:
            count = by_sev.get(sev.value, 0)
            total_display += count
            self.severity_labels[sev.value].configure(text=str(count))

        self.finding_count_label.configure(text=f"{total_display} total")

    def _apply_filter(self):
        sev = self.filter_var.get()
        txt = self.search_var.get()
        self.findings_table.set_severity_filter(sev)
        self.findings_table.set_search_text(txt)

    def _clear_output(self):
        self.console.configure(state="normal")
        self.console.delete("1.0", "end")
        self.console.configure(state="disabled")
        self._findings.clear()
        self.findings_table.clear()
        self._update_finding_count()

    # ── Scan control ──────────────────────────────────────────────────

    def _set_scanning(self, active: bool, phases_count: int = 0):
        self.scan_running = active
        state = "disabled" if active else "normal"
        self.scan_btn.configure(state=state)
        self.quick_btn.configure(state=state)
        self.stop_btn.configure(state="normal" if active else "disabled")
        self.target_entry.configure(state=state)

        if active:
            self.progress["value"] = 0
            self.progress["maximum"] = max(phases_count, 1)
            self.progress_label.configure(text="Starting...")
            self._set_status("Scanning...", FG_GREEN)
            self._scan_start_time = time.time()
            if not self._timer_running:
                self._timer_running = True
                self._update_timer()
        else:
            self.progress["value"] = self.progress["maximum"]
            self.progress_label.configure(text="Done")
            self._set_status("Ready", FG_DIM)
            self.timer_label.configure(text="")
            self._timer_running = False

    def _run_scan(self):
        if self.scan_running:
            return
        target = self.target_entry.get().strip()
        if not target:
            self._echo("⚠ Please enter a target.", "red")
            return

        selected = [k for k, v in self.phase_vars.items() if v.get()]
        if not selected:
            self._echo("⚠ Select at least one phase.", "red")
            return

        config = DORAConfig()
        config._data.setdefault("scan", {})["threads"] = self.threads_var.get()
        config._data.setdefault("scan", {})["timeout"] = self.timeout_var.get()
        warnings = config.validate()
        for w in warnings:
            self._echo(f"  ⚠ {w}", "yellow")

        self._findings.clear()
        self.findings_table.clear()
        self._update_finding_count()
        self._cancel_event.clear()
        self._set_scanning(True, len(selected))
        self._echo(f"▶ Starting scan: [bold]{target}[/]", "header")
        self._echo(f"  Phases: {', '.join(selected)}", "cyan")
        self._echo(f"  Output: {self.format_var.get().upper()}", "cyan")
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
            self._echo("■ Cancelling scan...", "yellow")
            self._set_status("Cancelling...", FG_YELLOW)

    # ── Findings actions ──────────────────────────────────────────────

    def _on_finding_double_click(self, event):
        finding = self.findings_table.get_selected_finding()
        if finding:
            self._show_finding_detail(finding)

    def _show_finding_detail(self, finding: Finding):
        win = tk.Toplevel(self.root)
        win.title(f"Finding: {finding.name}")
        win.configure(bg=BG_CARD)
        win.geometry("600x400")
        _center_window(win, 600, 400, parent=self.root)

        text = tk.Text(win, bg=BG_CARD, fg=FG_TEXT, font=(FONT_MONO, FONT_SIZES["small"]),
                       relief="flat", highlightthickness=0, padx=12, pady=10, wrap="word")
        text.pack(fill="both", expand=True)

        tags = {
            "header": (FG_CYAN, "bold"),
            "label": (FG_DIM, ""),
            "value": (FG_TEXT, ""),
            "severity": (SEVERITY_COLORS.get(finding.severity, FG_WHITE), "bold"),
        }
        for name, (fg, weight) in tags.items():
            text.tag_configure(name, foreground=fg, font=(FONT_MONO, FONT_SIZES["small"], weight) if weight else
                               (FONT_MONO, FONT_SIZES["small"]))

        lines = [
            ("header", f"  {finding.severity.value.upper()} — {finding.name}\n\n"),
            ("label", "Type:\t\t"), ("value", f"{finding.type.value}\n"),
            ("label", "Severity:\t"), ("severity", f"{finding.severity.value.upper()}\n"),
            ("label", "Value:\t\t"), ("value", f"{finding.value}\n"),
            ("label", "Source:\t\t"), ("value", f"{finding.source}\n"),
            ("label", "Evidence:\t"), ("value", f"{finding.evidence or '—'}\n"),
            ("label", "Description:\t"), ("value", f"{finding.description or '—'}\n"),
        ]
        if finding.extra:
            lines.append(("label", "\nExtra Data:\n"))
            for k, v in finding.extra.items():
                lines.append(("label", f"  {k}:\t\t"))
                lines.append(("value", f"{v}\n"))

        for tag_name, content in lines:
            text.insert("end", content, tag_name)
        text.configure(state="disabled")

    def _copy_selected_finding(self):
        finding = self.findings_table.get_selected_finding()
        if not finding:
            self._echo("  ⚠ No finding selected to copy", "yellow")
            return
        text = f"[{finding.severity.value.upper()}] {finding.name}: {finding.value}"
        self.root.clipboard_clear()
        self.root.clipboard_append(text)
        self._echo(f"  ✓ Copied: {text[:60]}...", "green")

    def _export_findings_json(self):
        if not self._findings:
            self._echo("  ⚠ No findings to export", "yellow")
            return
        from datetime import datetime
        safe = self.target_entry.get().strip().replace(".", "_")
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        out_dir = Path("reports")
        out_dir.mkdir(parents=True, exist_ok=True)
        path = out_dir / f"findings_{safe}_{ts}.json"
        try:
            data = [f.to_dict() for f in self._findings]
            import json
            path.write_text(json.dumps(data, indent=2, default=str))
            self._echo(f"  ✓ Exported {len(data)} findings to {path}", "green")
            self._last_report_dir = out_dir
        except Exception as e:
            self._echo(f"  ✗ Export error: {e}", "red")

    def _open_reports(self):
        path = self._last_report_dir or Path("reports")
        if not path.exists():
            path.mkdir(parents=True, exist_ok=True)
        try:
            os.startfile(str(path.resolve()))
        except Exception:
            subprocess.Popen(["explorer", str(path.resolve())])

    # ── Worker ────────────────────────────────────────────────────────

    def _scan_worker(self, cfg: dict):
        handler = TextHandler(lambda t: self._log_to_gui(t, "green"))
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

            for idx, phase_key in enumerate(resolved):
                if self._cancel_event.is_set():
                    self._log_to_gui("■ Scan cancelled.", "yellow")
                    return
                if phase_key not in PHASE_MAP:
                    continue
                phase_name, runner = PHASE_MAP[phase_key]
                self._log_to_gui(f"  ── {phase_name} ──", "header")
                self.root.after(0, self._update_progress, idx + 1, f"Running: {phase_name}")
                try:
                    from dora.targets import parse_targets
                    targets = parse_targets(cfg["targets"])
                    await runner(targets, config, findings)
                    self._log_to_gui(f"  ✓ {len(findings)} total findings", "green")
                except Exception as e:
                    self._log_to_gui(f"  ✗ Error: {e}", "red")

                self.root.after(0, self._update_findings_from, findings)

            if not self._cancel_event.is_set():
                findings[:] = deduplicate_findings(findings)
                self._log_to_gui(f"  ◆ Deduplicated: {len(findings)} final findings", "cyan")
                self.root.after(0, self._update_findings_from, findings)

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
                        self._log_to_gui(f"  📄 Saved: {md_path}", "cyan")
                    except Exception as e:
                        self._log_to_gui(f"  ⚠ MD report error: {e}", "red")

                    try:
                        _cli_report(result, config)
                        self._last_report_dir = config.output_dir.resolve()
                    except Exception as e:
                        self._log_to_gui(f"  ⚠ Report error: {e}", "red")

                self._log_to_gui(f"\n  ✓ Scan complete — {len(findings)} findings", "header")
            else:
                self._log_to_gui("■ Scan cancelled.", "yellow")

        try:
            asyncio.run(_run())
        except Exception as e:
            self._log_to_gui(f"✗ Fatal error: {e}", "red")
        finally:
            sys.stdout = old_stdout
            self.root.after(0, self._set_scanning, False)

    def _update_progress(self, value: int, label: str):
        self.progress["value"] = value
        self.progress_label.configure(text=label)

    def _update_findings_from(self, findings: list[Finding]):
        self._findings = list(findings)
        self._update_finding_count()

    def _on_close(self):
        if self.scan_running:
            self._cancel_event.set()
        self.root.destroy()


def _tooltip(widget: tk.Widget, text: str):
    tip_window = None

    def show(event):
        nonlocal tip_window
        if tip_window:
            return
        x = event.x_root + 14
        y = event.y_root + 10
        tip_window = tk.Toplevel(widget)
        tip_window.wm_overrideredirect(True)
        tip_window.wm_geometry(f"+{x}+{y}")
        tip_window.configure(bg="#2a2a3c")
        lbl = tk.Label(tip_window, text=text, background="#2a2a3c", foreground=FG_TEXT,
                       font=(FONT, FONT_SIZES["tiny"]), padx=8, pady=4, wraplength=280)
        lbl.pack()

    def hide(event):
        nonlocal tip_window
        if tip_window:
            tip_window.destroy()
            tip_window = None

    widget.bind("<Enter>", show, add="+")
    widget.bind("<Leave>", hide, add="+")


def _center_window(win: tk.Tk | tk.Toplevel, w: int, h: int, parent: Optional[tk.Tk] = None):
    sw = win.winfo_screenwidth()
    sh = win.winfo_screenheight()
    if parent:
        px = parent.winfo_x()
        py = parent.winfo_y()
        pw = parent.winfo_width()
        ph = parent.winfo_height()
        x = px + (pw - w) // 2
        y = py + (ph - h) // 2
    else:
        x = (sw - w) // 2
        y = (sh - h) // 2
    win.geometry(f"{w}x{h}+{x}+{y}")


def main():
    root = tk.Tk()
    DORAGUI(root)
    root.mainloop()


if __name__ == "__main__":
    main()
