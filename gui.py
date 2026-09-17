from __future__ import annotations

import queue
import threading
import tkinter as tk
from pathlib import Path
from tkinter import ttk, filedialog, messagebox
import webbrowser

from config import Settings, SCAN_PROFILES, DEFAULT_PROFILE, DEFAULT_REPORTS_DIR
from env_check import run_environment_check
from validate import validate_target
from nmap_scan import scan_target, HostInfo
from exploits import load_exploit_index, correlate_all_services, ExploitMatch
from report import generate_report, generate_html_report, _security_observations

APP_NAME = "NetSploitXZ"
APP_TAGLINE = "Network Reconnaissance & Exploit Discovery"

# ---------------------------------------------------------------------
# color / style constants, one place to tweak the look of the whole app.
# dark, restrained "kali-style" security-tool palette: near-black
# background, slightly lighter charcoal panels, a muted green/cyan
# accent, and status colors reserved for High/Medium/Low/Info meaning.
# ---------------------------------------------------------------------
BG_DARK = "#12141a"
BG_PANEL = "#1a1d26"
BG_PANEL_ALT = "#20232e"        # alternating row / slightly raised panel tone
BG_INPUT = "#1e212b"
BORDER = "#2c3040"
FG_TEXT = "#d7dbe4"
FG_MUTED = "#7c8494"
ACCENT = "#3ddc97"              # muted green accent (primary)
ACCENT_DARK = "#2bb87f"
ACCENT_CYAN = "#4fd1c5"         # secondary accent for subtitles/info
COLOR_HIGH = "#ff5c5c"
COLOR_MEDIUM = "#ffb454"
COLOR_LOW = "#5cc8ff"
COLOR_INFO = "#8b93a7"
FONT_NORMAL = ("Segoe UI", 10)
FONT_HEADER = ("Segoe UI", 15, "bold")
FONT_SUBHEADER = ("Segoe UI", 9)
FONT_SECTION = ("Segoe UI", 10, "bold")
FONT_MONO = ("Consolas", 10)
FONT_MONO_SMALL = ("Consolas", 9)

# sort indicator glyphs used on clickable treeview column headers
_SORT_ASC = " \u25b2"
_SORT_DESC = " \u25bc"


class ScanProgressBar(tk.Canvas):
    # small self-contained "marquee" progress indicator: a single bar
    # that sweeps left to right and wraps around, redrawn on a timer.
    # used instead of ttk's built-in indeterminate Progressbar, whose
    # default look on most themes is a short block bouncing back and
    # forth rather than a smooth continuous sweep.

    def __init__(self, parent, height: int = 6, **kwargs):
        super().__init__(parent, height=height, bg=BG_PANEL, highlightthickness=0, **kwargs)
        self._height = height
        self._running = False
        self._pos = 0.0
        self._after_id = None
        self.bind("<Configure>", lambda event: self._redraw())

    def start(self):
        if self._running:
            return
        self._running = True
        self._pos = 0.0
        self._tick()

    def stop(self):
        self._running = False
        if self._after_id is not None:
            self.after_cancel(self._after_id)
            self._after_id = None
        self.delete("all")

    def _tick(self):
        if not self._running:
            return
        width = self.winfo_width() or 1
        bar_width = max(60, width // 5)
        self._pos += 6
        if self._pos > width:
            self._pos = -bar_width
        self._redraw(bar_width)
        self._after_id = self.after(20, self._tick)

    def _redraw(self, bar_width: int | None = None):
        self.delete("all")
        width = self.winfo_width() or 1
        self.create_rectangle(0, 0, width, self._height, fill=BG_PANEL, outline="")
        if self._running:
            bar_width = bar_width or max(60, width // 5)
            self.create_rectangle(self._pos, 0, self._pos + bar_width, self._height, fill=ACCENT, outline="")


class ReconApp:
    def __init__(self, root: tk.Tk):
        self.root = root
        self.root.title(f"{APP_NAME} — {APP_TAGLINE}")
        self.root.geometry("1050x720")
        self.root.minsize(880, 560)
        self.root.configure(bg=BG_DARK)

        self.settings = Settings.load()
        self.result_queue: "queue.Queue" = queue.Queue()
        self.current_host: HostInfo | None = None
        self.current_matches: list[ExploitMatch] = []
        self.current_profile: str = self.settings.last_profile or DEFAULT_PROFILE
        self.current_exploitdb_available = True
        self.current_errors: list[str] = []
        self.scan_in_progress = False
        self.cancel_event: threading.Event | None = None

        # per-treeview sort state/config, keyed by id(tree). purely a gui
        # presentation concern, never touches the underlying data objects
        # (ServiceInfo / ExploitMatch) or the scores/confidence they carry.
        self._sort_state: dict[int, dict] = {}
        self._sort_config: dict[int, dict] = {}
        self._tree_headings: dict[int, dict] = {}

        self._build_style()
        self._build_layout()
        self._refresh_environment_panel()

    # -------------------------------------------------------------
    # styling
    # -------------------------------------------------------------
    def _build_style(self):
        style = ttk.Style()
        # 'clam' is the only built-in ttk theme that reliably accepts
        # custom colors across platforms (windows' default theme ignores
        # background overrides on several widgets)
        style.theme_use("clam")

        style.configure(".", background=BG_DARK, foreground=FG_TEXT, font=FONT_NORMAL)
        style.configure("TFrame", background=BG_DARK)
        style.configure("Panel.TFrame", background=BG_PANEL)
        style.configure("TLabel", background=BG_DARK, foreground=FG_TEXT, font=FONT_NORMAL)
        style.configure("Header.TLabel", background=BG_DARK, foreground=ACCENT, font=FONT_HEADER)
        style.configure("Tagline.TLabel", background=BG_DARK, foreground=ACCENT_CYAN, font=FONT_SUBHEADER)
        style.configure("Muted.TLabel", background=BG_DARK, foreground=FG_MUTED, font=FONT_NORMAL)
        style.configure("Panel.TLabel", background=BG_PANEL, foreground=FG_TEXT, font=FONT_NORMAL)
        style.configure("Section.TLabel", background=BG_DARK, foreground=FG_TEXT, font=FONT_SECTION)
        style.configure("StatusCard.TLabel", background=BG_PANEL_ALT, foreground=FG_TEXT, font=FONT_NORMAL)

        style.configure("TEntry", fieldbackground=BG_INPUT, foreground=FG_TEXT, insertcolor=ACCENT,
                         bordercolor=BORDER, lightcolor=BORDER, darkcolor=BORDER)
        style.configure("TCombobox", fieldbackground=BG_INPUT, foreground=FG_TEXT, background=BG_INPUT,
                         arrowcolor=FG_TEXT, selectbackground=BG_INPUT, selectforeground=FG_TEXT)
        # 'clam' otherwise swaps in a light system color for the "readonly"
        # state specifically (our profile dropdown uses state="readonly"),
        # which made the text unreadable against the dark theme
        style.map(
            "TCombobox",
            fieldbackground=[("readonly", BG_INPUT), ("disabled", BG_PANEL)],
            foreground=[("readonly", FG_TEXT), ("disabled", FG_MUTED)],
            background=[("readonly", BG_INPUT), ("active", BG_INPUT)],
            selectbackground=[("readonly", BG_INPUT)],
            selectforeground=[("readonly", FG_TEXT)],
            arrowcolor=[("readonly", FG_TEXT), ("active", ACCENT)],
        )
        # the dropdown popup list is a plain tk Listbox, not a ttk widget,
        # so it isn't touched by ttk styles at all, set it directly or it
        # renders with the system's default (light) colors
        self.root.option_add("*TCombobox*Listbox.background", BG_INPUT)
        self.root.option_add("*TCombobox*Listbox.foreground", FG_TEXT)
        self.root.option_add("*TCombobox*Listbox.selectBackground", ACCENT_DARK)
        self.root.option_add("*TCombobox*Listbox.selectForeground", "#0b0b12")
        self.root.option_add("*TCombobox*Listbox.font", FONT_NORMAL)

        style.configure(
            "Accent.TButton",
            background=ACCENT,
            foreground="#0b0b12",
            font=("Segoe UI", 10, "bold"),
            padding=8,
            borderwidth=0,
        )
        style.map("Accent.TButton", background=[("active", ACCENT_DARK), ("disabled", "#555566")])

        style.configure(
            "Secondary.TButton",
            background=BG_PANEL,
            foreground=FG_TEXT,
            padding=6,
            borderwidth=1,
        )
        style.map("Secondary.TButton", background=[("active", "#33334a")])

        style.configure(
            "Cancel.TButton",
            background="#3a2530",
            foreground=COLOR_HIGH,
            padding=6,
            borderwidth=1,
        )
        style.map("Cancel.TButton", background=[("active", "#4a2c38"), ("disabled", "#33334a")])

        style.configure("TNotebook", background=BG_DARK, borderwidth=0)
        style.configure("TNotebook.Tab", background=BG_PANEL, foreground=FG_MUTED,
                         padding=(14, 7), font=("Segoe UI", 9, "bold"))
        style.map("TNotebook.Tab", background=[("selected", BG_PANEL_ALT)], foreground=[("selected", ACCENT)])

        style.configure(
            "Treeview",
            background=BG_PANEL,
            fieldbackground=BG_PANEL,
            foreground=FG_TEXT,
            rowheight=24,
            borderwidth=0,
            font=FONT_MONO_SMALL,
        )
        style.configure("Treeview.Heading", background="#242837", foreground=ACCENT_CYAN,
                         font=("Segoe UI", 9, "bold"), relief="flat", padding=(4, 4))
        style.map("Treeview.Heading", background=[("active", "#2c3145")])
        style.map("Treeview", background=[("selected", ACCENT_DARK)], foreground=[("selected", "#0b0b12")])

        style.configure("StatusCard.TFrame", background=BG_PANEL_ALT, relief="flat", borderwidth=1)

        style.configure("Filter.TEntry", fieldbackground=BG_INPUT, foreground=FG_TEXT, insertcolor=ACCENT)

    # -------------------------------------------------------------
    # layout
    # -------------------------------------------------------------
    def _build_layout(self):
        outer = ttk.Frame(self.root, padding=14)
        outer.pack(fill="both", expand=True)

        self._build_top_bar(outer)
        self._build_env_strip(outer)
        self._build_progress_strip(outer)

        # the footer (disclaimer, status line, export buttons) is packed
        # with side="bottom" before the notebook, in bottom-to-top order.
        # this reserves its space from the bottom of the window first,
        # regardless of how much room the notebook's content wants.
        # packing it after an expand=True notebook meant that on shorter
        # screens the notebook silently claimed all available height and
        # the footer (including the export buttons) got pushed off-window
        # and never drawn at all.
        self._build_status_bar(outer)
        self._build_bottom_bar(outer)

        self._build_notebook(outer)

    def _build_top_bar(self, parent):
        # title on its own row, controls on the row below, so the controls
        # never get squeezed against the title text at narrower window
        # widths, and the target field is the one thing that stretches/
        # shrinks so the buttons next to it are never clipped
        bar = ttk.Frame(parent)
        bar.pack(fill="x", pady=(0, 10))
        bar.grid_columnconfigure(0, weight=1)

        title_row = ttk.Frame(bar)
        title_row.grid(row=0, column=0, sticky="w", pady=(0, 2))
        ttk.Label(title_row, text=APP_NAME, style="Header.TLabel").pack(side="left")
        ttk.Label(title_row, text=f"  {APP_TAGLINE}", style="Tagline.TLabel").pack(side="left", padx=(2, 0), pady=(5, 0))

        controls = ttk.Frame(bar)
        controls.grid(row=1, column=0, sticky="ew", pady=(8, 0))
        controls.grid_columnconfigure(1, weight=1)  # the target entry absorbs extra/lost width

        ttk.Label(controls, text="Target:").grid(row=0, column=0, padx=(0, 4), sticky="w")
        self.target_var = tk.StringVar()
        target_entry = ttk.Entry(controls, textvariable=self.target_var)
        target_entry.grid(row=0, column=1, padx=(0, 10), sticky="ew")
        target_entry.bind("<Return>", lambda e: self._on_start_scan())

        ttk.Label(controls, text="Profile:").grid(row=0, column=2, padx=(0, 4), sticky="w")
        self.profile_var = tk.StringVar(value=self.current_profile)
        profile_box = ttk.Combobox(
            controls, textvariable=self.profile_var, values=list(SCAN_PROFILES.keys()),
            state="readonly", width=13,
        )
        profile_box.grid(row=0, column=3, padx=(0, 10), sticky="e")

        self.start_button = ttk.Button(controls, text="START SCAN", style="Accent.TButton", command=self._on_start_scan)
        self.start_button.grid(row=0, column=4, padx=(0, 6), sticky="e")

        self.cancel_button = ttk.Button(
            controls, text="CANCEL SCAN", style="Cancel.TButton", command=self._on_cancel_scan, state="disabled"
        )
        self.cancel_button.grid(row=0, column=5, sticky="e")

    def _build_env_strip(self, parent):
        # laid out as a 2x2 grid of status labels (rather than one long
        # row) plus the csv button, so this strip stays a fixed, modest
        # width and doesn't get clipped at the window's minimum size
        self.env_frame = ttk.Frame(parent, style="Panel.TFrame", padding=8)
        self.env_frame.pack(fill="x", pady=(0, 10))
        self.env_frame.grid_columnconfigure(0, weight=1)

        status_grid = ttk.Frame(self.env_frame, style="Panel.TFrame")
        status_grid.grid(row=0, column=0, sticky="w")

        self.env_labels: dict[str, ttk.Label] = {}
        for i, name in enumerate(("Python", "Nmap", "Privileges", "Exploit-DB")):
            row, col = divmod(i, 2)
            lbl = ttk.Label(status_grid, text=f"{name}: checking...", style="Panel.TLabel",
                             wraplength=200, justify="left")
            lbl.grid(row=row, column=col, padx=(0, 24), pady=2, sticky="w")
            self.env_labels[name] = lbl

        set_csv_btn = ttk.Button(
            self.env_frame, text="Set Exploit-DB CSV...", style="Secondary.TButton",
            command=self._on_set_exploitdb_path,
        )
        set_csv_btn.grid(row=0, column=1, padx=(12, 0), sticky="ne")

    def _build_progress_strip(self, parent):
        # a small custom canvas "marquee" bar instead of ttk's default
        # indeterminate Progressbar. ttk's default indeterminate style
        # renders as a short block bouncing back and forth, which reads
        # as choppy; this sweeps one continuous direction and wraps,
        # which looks like a normal loading indicator.
        self.progress_frame = ttk.Frame(parent)
        self.progress_bar = ScanProgressBar(self.progress_frame, height=6)
        self.progress_bar.pack(fill="x")
        # not packed into parent yet, shown/hidden in _set_scanning_state()

    def _build_notebook(self, parent):
        self.notebook = ttk.Notebook(parent)
        self.notebook.pack(fill="both", expand=True, pady=(0, 10))

        self.tab_host = ttk.Frame(self.notebook, padding=12)
        self.tab_ports = ttk.Frame(self.notebook, padding=12)
        self.tab_findings = ttk.Frame(self.notebook, padding=12)
        self.tab_exploits = ttk.Frame(self.notebook, padding=12)

        self.notebook.add(self.tab_host, text="Host Info")
        self.notebook.add(self.tab_ports, text="Ports & Services")
        self.notebook.add(self.tab_findings, text="Security Findings")
        self.notebook.add(self.tab_exploits, text="Exploit Discovery")

        self._build_host_tab()
        self._build_ports_tab()
        self._build_findings_tab()
        self._build_exploits_tab()

    def _build_host_tab(self):
        container = ttk.Frame(self.tab_host)
        container.pack(fill="both", expand=True)
        self.host_text = tk.Text(
            container, bg=BG_PANEL, fg=FG_TEXT, font=FONT_MONO,
            relief="flat", wrap="word", padx=10, pady=10,
        )
        scrollbar = ttk.Scrollbar(container, orient="vertical", command=self.host_text.yview)
        self.host_text.configure(yscrollcommand=scrollbar.set)
        scrollbar.pack(side="right", fill="y")
        self.host_text.pack(side="left", fill="both", expand=True)
        self.host_text.configure(state="disabled")

    # -------------------------------------------------------------
    # generic treeview column sorting (gui presentation only, never
    # touches ExploitMatch/ServiceInfo data or how scores/confidence
    # are calculated; it only reorders what's already displayed)
    # -------------------------------------------------------------
    def _register_sortable_columns(self, tree: ttk.Treeview, columns_config: dict):
        # columns_config: {col_id: (heading_text, numeric, order_map_or_None)}
        # wires each heading to toggle-sort on click and remembers the base
        # heading text so a sort indicator (▲/▼) can be appended/removed
        self._sort_config[id(tree)] = columns_config
        self._tree_headings[id(tree)] = {col: text for col, (text, _n, _o) in columns_config.items()}
        for col, (text, numeric, order_map) in columns_config.items():
            tree.heading(col, text=text, command=lambda c=col: self._on_sort_column(tree, c))

    def _on_sort_column(self, tree: ttk.Treeview, col: str):
        state = self._sort_state.setdefault(id(tree), {"col": None, "reverse": False})
        reverse = (not state["reverse"]) if state["col"] == col else False
        _text, numeric, order_map = self._sort_config[id(tree)][col]
        self._do_sort(tree, col, reverse, numeric, order_map)

    def _apply_default_sort(self, tree: ttk.Treeview, col: str, reverse: bool):
        _text, numeric, order_map = self._sort_config[id(tree)][col]
        self._do_sort(tree, col, reverse, numeric, order_map)

    def _do_sort(self, tree: ttk.Treeview, col: str, reverse: bool, numeric: bool, order_map: dict | None):
        def keyfunc(item):
            value = tree.set(item, col)
            if order_map is not None:
                return order_map.get(value, len(order_map) + 1)
            if numeric:
                try:
                    return float(value)
                except (TypeError, ValueError):
                    return float("-inf")
            return value.lower()

        items = list(tree.get_children(""))
        items.sort(key=keyfunc, reverse=reverse)
        for index, item in enumerate(items):
            tree.move(item, "", index)

        self._sort_state[id(tree)] = {"col": col, "reverse": reverse}
        headings = self._tree_headings[id(tree)]
        for c, base_text in headings.items():
            if c == col:
                tree.heading(c, text=base_text + (_SORT_DESC if reverse else _SORT_ASC))
            else:
                tree.heading(c, text=base_text)

    def _build_ports_tab(self):
        # fixed heights here are deliberately modest (rather than tall
        # enough to always avoid scrolling) so this tab, and therefore
        # the whole window, keeps working on shorter screens. every
        # scrollable widget below has its own scrollbar, so nothing
        # becomes inaccessible just because it doesn't all fit at once.
        tree_frame = ttk.Frame(self.tab_ports)
        tree_frame.pack(fill="both", expand=True, side="top")

        columns = ("port", "protocol", "state", "service", "product_version", "conf")
        self.ports_tree = ttk.Treeview(tree_frame, columns=columns, show="headings", height=6)
        headings = {
            "port": "Port", "protocol": "Proto", "state": "State", "service": "Service",
            "product_version": "Product / Version", "conf": "Nmap Conf.",
        }
        widths = {"port": 55, "protocol": 55, "state": 70, "service": 90, "product_version": 340, "conf": 70}
        for col in columns:
            self.ports_tree.column(col, width=widths[col], anchor="w")
        self._register_sortable_columns(self.ports_tree, {
            "port": (headings["port"], True, None),
            "protocol": (headings["protocol"], False, None),
            "state": (headings["state"], False, None),
            "service": (headings["service"], False, None),
            "product_version": (headings["product_version"], False, None),
            "conf": (headings["conf"], True, None),
        })
        tree_scrollbar = ttk.Scrollbar(tree_frame, orient="vertical", command=self.ports_tree.yview)
        self.ports_tree.configure(yscrollcommand=tree_scrollbar.set)
        tree_scrollbar.pack(side="right", fill="y")
        self.ports_tree.pack(side="left", fill="both", expand=True)
        self.ports_tree.bind("<<TreeviewSelect>>", self._on_port_select)

        # details panel shown when a port is selected: service fields + CPE
        detail_frame = ttk.Frame(self.tab_ports)
        detail_frame.pack(fill="x", side="top", pady=(8, 0))
        self.port_detail_text = tk.Text(
            detail_frame, bg=BG_PANEL, fg=FG_TEXT, font=FONT_MONO, height=5,
            relief="flat", wrap="word", padx=10, pady=8,
        )
        detail_scrollbar = ttk.Scrollbar(detail_frame, orient="vertical", command=self.port_detail_text.yview)
        self.port_detail_text.configure(yscrollcommand=detail_scrollbar.set)
        detail_scrollbar.pack(side="right", fill="y")
        self.port_detail_text.pack(side="left", fill="x", expand=True)
        self.port_detail_text.configure(state="disabled")

        script_frame = ttk.Frame(self.tab_ports)
        script_frame.pack(fill="x", side="bottom", pady=(8, 0))
        self.script_text = tk.Text(
            script_frame, bg=BG_PANEL, fg=FG_MUTED, font=FONT_MONO, height=4,
            relief="flat", wrap="word", padx=10, pady=8,
        )
        script_scrollbar = ttk.Scrollbar(script_frame, orient="vertical", command=self.script_text.yview)
        self.script_text.configure(yscrollcommand=script_scrollbar.set)
        script_scrollbar.pack(side="right", fill="y")
        self.script_text.pack(side="left", fill="x", expand=True)
        self.script_text.configure(state="disabled")

    def _build_findings_tab(self):
        filter_bar = ttk.Frame(self.tab_findings)
        filter_bar.pack(fill="x", side="top", pady=(0, 6))
        ttk.Label(filter_bar, text="Severity:").pack(side="left", padx=(0, 6))
        self.findings_filter_var = tk.StringVar(value="ALL")
        for level in ("ALL", "HIGH", "MEDIUM", "LOW", "INFO"):
            ttk.Radiobutton(
                filter_bar, text=level, value=level, variable=self.findings_filter_var,
                command=self._apply_findings_filter,
            ).pack(side="left", padx=(0, 8))

        container = ttk.Frame(self.tab_findings)
        container.pack(fill="both", expand=True)
        self.findings_text = tk.Text(
            container, bg=BG_PANEL, fg=FG_TEXT, font=FONT_MONO,
            relief="flat", wrap="word", padx=10, pady=10,
        )
        scrollbar = ttk.Scrollbar(container, orient="vertical", command=self.findings_text.yview)
        self.findings_text.configure(yscrollcommand=scrollbar.set)
        scrollbar.pack(side="right", fill="y")
        self.findings_text.pack(side="left", fill="both", expand=True)
        self.findings_text.configure(state="disabled")

    def _build_exploits_tab(self):
        filter_bar = ttk.Frame(self.tab_exploits)
        filter_bar.pack(fill="x", side="top", pady=(0, 6))
        ttk.Label(filter_bar, text="Filter exploits:").pack(side="left", padx=(0, 6))
        self.exploit_filter_var = tk.StringVar()
        filter_entry = ttk.Entry(filter_bar, textvariable=self.exploit_filter_var, style="Filter.TEntry")
        filter_entry.pack(side="left", fill="x", expand=True)
        self.exploit_filter_var.trace_add("write", lambda *_: self._apply_exploit_filter())

        tree_frame = ttk.Frame(self.tab_exploits)
        tree_frame.pack(fill="both", expand=True, side="top")

        columns = ("port", "edb_id", "title", "confidence", "score")
        self.exploit_tree = ttk.Treeview(tree_frame, columns=columns, show="headings", height=6)
        headings = {"port": "Port", "edb_id": "EDB-ID", "title": "Title", "confidence": "Confidence", "score": "Score"}
        widths = {"port": 50, "edb_id": 70, "title": 420, "confidence": 90, "score": 60}
        for col in columns:
            self.exploit_tree.column(col, width=widths[col], anchor="w")
        self._register_sortable_columns(self.exploit_tree, {
            "port": (headings["port"], True, None),
            "edb_id": (headings["edb_id"], True, None),
            "title": (headings["title"], False, None),
            "confidence": (headings["confidence"], False, {"High": 0, "Medium": 1, "Low": 2}),
            "score": (headings["score"], True, None),
        })
        tree_scrollbar = ttk.Scrollbar(tree_frame, orient="vertical", command=self.exploit_tree.yview)
        self.exploit_tree.configure(yscrollcommand=tree_scrollbar.set)
        tree_scrollbar.pack(side="right", fill="y")
        self.exploit_tree.pack(side="left", fill="both", expand=True)
        self.exploit_tree.tag_configure("High", foreground=COLOR_HIGH)
        self.exploit_tree.tag_configure("Medium", foreground=COLOR_MEDIUM)
        self.exploit_tree.tag_configure("Low", foreground=COLOR_LOW)
        self.exploit_tree.bind("<<TreeviewSelect>>", self._on_exploit_select)

        detail_frame = ttk.Frame(self.tab_exploits, style="Panel.TFrame", padding=10)
        detail_frame.pack(fill="x", side="bottom", pady=(8, 0))

        self.exploit_detail_var = tk.StringVar(value="Select an exploit above to see details.")
        exploit_detail_label = ttk.Label(
            detail_frame, textvariable=self.exploit_detail_var, style="Panel.TLabel", justify="left"
        )
        exploit_detail_label.pack(side="left", fill="x", expand=True)
        # rewrap the text to the label's actual current width instead of a
        # fixed guess, so it reads correctly at any window size
        exploit_detail_label.bind(
            "<Configure>", lambda event: exploit_detail_label.configure(wraplength=max(200, event.width - 10))
        )
        self.open_exploit_btn = ttk.Button(
            detail_frame, text="Open Exploit-DB", style="Accent.TButton",
            command=self._on_open_exploit, state="disabled",
        )
        self.open_exploit_btn.pack(side="right")
        self._selected_exploit_url: str | None = None

    def _build_bottom_bar(self, parent):
        bar = ttk.Frame(parent)
        bar.pack(side="bottom", fill="x", pady=(4, 4))

        self.export_html_button = ttk.Button(
            bar, text="Export HTML Report", style="Accent.TButton",
            command=lambda: self._on_export_report("html"), state="disabled",
        )
        self.export_html_button.pack(side="right", padx=(6, 0))

        self.export_txt_button = ttk.Button(
            bar, text="Export TXT Report", style="Secondary.TButton",
            command=lambda: self._on_export_report("txt"), state="disabled",
        )
        self.export_txt_button.pack(side="right")

    def _build_status_bar(self, parent):
        self.status_var = tk.StringVar(value="Ready.")
        status = ttk.Label(parent, textvariable=self.status_var, style="Muted.TLabel")
        status.pack(side="bottom", fill="x")

    # -------------------------------------------------------------
    # environment panel
    # -------------------------------------------------------------
    def _refresh_environment_panel(self):
        report = run_environment_check()
        name_map = {
            "Python": report.python,
            "Nmap": report.nmap,
            "Privileges": report.privileges,
            "Exploit-DB": report.exploitdb,
        }
        for label_key, comp in name_map.items():
            symbol = "\u2713" if comp.available else ("\u26a0" if label_key == "Privileges" else "\u2717")
            color = ACCENT if comp.available else (FG_MUTED if label_key == "Privileges" else COLOR_HIGH)
            self.env_labels[label_key].configure(text=f"{symbol} {comp.name}: {comp.detail}", foreground=color)
        self._env_report = report
        if not report.can_scan:
            self.status_var.set("Nmap not found — install it and restart before scanning.")

    def _on_set_exploitdb_path(self):
        path = filedialog.askopenfilename(
            title="Select exploitdb files_exploits.csv",
            filetypes=[("CSV files", "*.csv"), ("All files", "*.*")],
        )
        if path:
            self.settings.exploitdb_csv_path = path
            self.settings.save()
            self._refresh_environment_panel()
            self.status_var.set(f"Exploit-DB CSV set to: {path}")

    # -------------------------------------------------------------
    # scan lifecycle
    # -------------------------------------------------------------
    def _on_start_scan(self):
        if self.scan_in_progress:
            return

        raw_target = self.target_var.get()
        target, error = validate_target(raw_target)
        if error:
            messagebox.showerror("Invalid target", error)
            return

        if not self._env_report.can_scan:
            messagebox.showerror("Nmap unavailable", self._env_report.nmap.impact_if_missing)
            return

        profile_name = self.profile_var.get() or DEFAULT_PROFILE

        if profile_name == "Comprehensive":
            proceed = messagebox.askyesno(
                "Comprehensive Scan",
                "This scan performs TCP and UDP scanning, OS detection,\n"
                "and default Nmap scripts and may take a long time.\n\n"
                "Continue?",
            )
            if not proceed:
                return

        self.settings.last_profile = profile_name
        self.settings.save()

        self._clear_results()
        self.cancel_event = threading.Event()
        self._set_scanning_state(True)
        self.status_var.set(f"Scanning {target} ({profile_name})... this may take a while.")

        worker = threading.Thread(
            target=self._run_scan_worker, args=(target, profile_name, self.cancel_event), daemon=True
        )
        worker.start()
        self.root.after(200, self._poll_queue)

    def _on_cancel_scan(self):
        if self.scan_in_progress and self.cancel_event is not None:
            self.cancel_event.set()
            self.status_var.set("Cancelling scan...")
            self.cancel_button.configure(state="disabled")

    def _set_scanning_state(self, scanning: bool):
        self.scan_in_progress = scanning
        self.start_button.configure(state="disabled" if scanning else "normal")
        self.cancel_button.configure(state="normal" if scanning else "disabled")
        if scanning:
            self.progress_frame.pack(fill="x", pady=(0, 10), before=self.notebook)
            self.progress_bar.start()
        else:
            self.progress_bar.stop()
            self.progress_frame.pack_forget()

    def _run_scan_worker(self, target: str, profile_name: str, cancel_event: threading.Event):
        # runs entirely in a background thread, never touches tkinter
        # widgets directly. wrapped in a broad try/except: if anything
        # unexpected raises here, the thread must still report back on
        # result_queue, otherwise _poll_queue would wait forever for an
        # item that never arrives and the GUI would look stuck on
        # "Scanning..." with no error and no way to recover except
        # restarting the app.
        try:
            errors: list[str] = []
            host, err = scan_target(target, profile_name, cancel_event=cancel_event)
            if err:
                kind = "cancelled" if "cancelled by user" in err.lower() else "error"
                self.result_queue.put((kind, err))
                return

            matches: list[ExploitMatch] = []
            exploitdb_available = self._env_report.can_discover_exploits
            if exploitdb_available:
                entries, load_err, _skipped = load_exploit_index(self.settings.exploitdb_csv_path)
                if load_err:
                    exploitdb_available = False
                    errors.append(load_err)
                else:
                    matches = correlate_all_services(host.services, entries)

            self.result_queue.put(("done", (host, matches, exploitdb_available, errors, profile_name)))
        except Exception as exc:  # noqa: BLE001 -- last-resort safety net, see comment above
            self.result_queue.put(("error", f"Unexpected error during scan: {exc}"))

    def _poll_queue(self):
        try:
            kind, payload = self.result_queue.get_nowait()
        except queue.Empty:
            if self.scan_in_progress:
                self.root.after(200, self._poll_queue)
            return

        self._set_scanning_state(False)
        self.cancel_event = None

        if kind == "cancelled":
            self.status_var.set("Scan cancelled by user.")
            return

        if kind == "error":
            self.status_var.set(f"Scan failed: {payload}")
            messagebox.showerror("Scan failed", payload)
            return

        host, matches, exploitdb_available, errors, profile_name = payload
        self.current_host = host
        self.current_matches = matches
        self.current_profile = profile_name
        self.current_exploitdb_available = exploitdb_available
        self.current_errors = errors

        self._render_results()
        self.export_html_button.configure(state="normal")
        self.export_txt_button.configure(state="normal")
        self.status_var.set(f"Scan complete for {host.ip_address or host.target_input}.")

    # -------------------------------------------------------------
    # rendering results
    # -------------------------------------------------------------
    def _clear_results(self):
        for tree in (self.ports_tree, self.exploit_tree):
            for row in tree.get_children():
                tree.delete(row)
        for widget in (self.host_text, self.findings_text, self.script_text, self.port_detail_text):
            widget.configure(state="normal")
            widget.delete("1.0", "end")
            widget.configure(state="disabled")
        self.exploit_detail_var.set("Select an exploit above to see details.")
        self.open_exploit_btn.configure(state="disabled")
        self._current_findings = []
        self._exploit_by_row = {}
        self.exploit_filter_var.set("")
        self.findings_filter_var.set("ALL")

    def _render_results(self):
        host = self.current_host
        self._clear_results()

        # --- Host Info tab ---
        lines = [
            f"Target input : {host.target_input}",
            f"IP address   : {host.ip_address or 'unknown'}",
            f"Hostname     : {host.hostname or 'unknown'}",
            f"Status       : {host.state}",
            f"OS guess     : {host.os_guess or 'unknown'}" + (f" (accuracy {host.os_accuracy}%)" if host.os_accuracy else ""),
        ]
        if host.mac_address:
            lines.append(f"MAC address  : {host.mac_address}" + (f" ({host.mac_vendor})" if host.mac_vendor else ""))
        if host.uptime_seconds:
            lines.append(f"Uptime       : {host.uptime_seconds}s (last boot: {host.last_boot})")
        if host.distance_hops:
            lines.append(f"Network hops : {host.distance_hops}")
        if host.scan_started:
            lines.append("")
            lines.append(f"Scan started : {host.scan_started}")
            lines.append(f"Completed    : {host.scan_completed}  (duration {host.scan_duration_seconds:.0f}s)")
        if host.nmap_command:
            lines.append(f"Nmap options : {host.nmap_command}")
        if host.warnings:
            lines.append("")
            lines.append("Notes:")
            lines.extend(f"  - {w}" for w in host.warnings)
        if host.host_scripts:
            lines.append("")
            lines.append("Host script output:")
            for s in host.host_scripts:
                lines.append(f"  [{s.script_id}] {s.output.strip()}")
        self._set_text(self.host_text, "\n".join(lines))

        # --- Ports & Services tab ---
        self._service_by_row = {}
        for s in host.services:
            product_version = f"{s.product} {s.version}".strip() or "-"
            row_id = self.ports_tree.insert(
                "", "end", values=(s.port, s.protocol, s.state, s.service_name or "-", product_version, s.conf or "-")
            )
            self._service_by_row[row_id] = s
        # default presentation order: port ascending (display ordering
        # choice only, Nmap's own results are untouched)
        self._apply_default_sort(self.ports_tree, "port", reverse=False)

        # --- Security Findings tab ---
        self._current_findings = _security_observations(host)
        self.findings_filter_var.set("ALL")
        self._apply_findings_filter()

        # --- Exploit Discovery tab ---
        if not self.current_exploitdb_available:
            self.exploit_detail_var.set("Exploit-DB index unavailable for this scan — set a valid CSV path above.")
        elif not self.current_matches:
            self.exploit_detail_var.set("No potentially applicable exploits found for the detected services.")
        self.exploit_filter_var.set("")
        self._apply_exploit_filter()

    def _apply_exploit_filter(self):
        # gui-only filter over the already-computed self.current_matches.
        # never mutates ExploitMatch data, only changes which rows are
        # currently shown in the treeview.
        for row in self.exploit_tree.get_children():
            self.exploit_tree.delete(row)
        self._exploit_by_row = {}

        query = self.exploit_filter_var.get().strip().lower()
        for m in self.current_matches:
            haystack = " ".join([
                m.edb_id, m.title, m.matched_product, m.matched_version,
                m.platform, m.exploit_type,
            ]).lower()
            if query and query not in haystack:
                continue
            row_id = self.exploit_tree.insert(
                "", "end",
                values=(m.matched_service_port, m.edb_id, m.title, m.confidence, m.score),
                tags=(m.confidence,),
            )
            self._exploit_by_row[row_id] = m

        # default presentation order: score highest to lowest (display
        # ordering only, the scores themselves come from exploits.py)
        self._apply_default_sort(self.exploit_tree, "score", reverse=True)

    def _apply_findings_filter(self):
        # gui-only severity filter over the already-computed findings list
        severity = self.findings_filter_var.get()
        findings = getattr(self, "_current_findings", [])
        if severity == "ALL":
            shown = findings
        else:
            shown = [f for f in findings if f.strip().upper().startswith(f"[{severity}]")]
        self._set_text(self.findings_text, "\n\n".join(shown) if shown else "No findings match this filter.")

    def _set_text(self, widget: tk.Text, content: str):
        widget.configure(state="normal")
        widget.delete("1.0", "end")
        widget.insert("1.0", content)
        widget.configure(state="disabled")

    def _on_port_select(self, event):
        selection = self.ports_tree.selection()
        if not selection:
            return
        service = self._service_by_row.get(selection[0])
        if service is None:
            return

        detail_lines = [
            f"Service:          {service.service_name or 'unknown'}",
            f"Product:          {service.product or '-'}",
            f"Version:          {service.version or '-'}",
            f"Extra info:       {service.extra_info or '-'}",
            f"Tunnel:           {service.tunnel or '-'}",
            f"Detection method: {service.method or '-'}",
            f"Nmap confidence:  {service.conf or '-'}",
        ]
        if service.cpe:
            detail_lines.append("")
            detail_lines.append("CPE:")
            detail_lines.extend(f"  {c}" for c in service.cpe)
        self._set_text(self.port_detail_text, "\n".join(detail_lines))

        scripts = service.scripts
        text = "\n".join(f"[{s.script_id}] {s.output.strip()}" for s in scripts) or "No script output for this port."
        self._set_text(self.script_text, text)

    def _on_exploit_select(self, event):
        selection = self.exploit_tree.selection()
        if not selection:
            return
        match = self._exploit_by_row.get(selection[0])
        if not match:
            return
        detail = (
            f"EDB-ID: {match.edb_id}   Type: {match.exploit_type or 'unknown'}   "
            f"Platform: {match.platform or 'unknown'}   Confidence: {match.confidence} (score {match.score})\n"
            f"Matched against: {match.matched_product} {match.matched_version} (port {match.matched_service_port})\n"
            f"{match.title}"
        )
        self.exploit_detail_var.set(detail)
        self._selected_exploit_url = match.url
        self.open_exploit_btn.configure(state="normal")

    def _on_open_exploit(self):
        if self._selected_exploit_url:
            webbrowser.open(self._selected_exploit_url)

    # -------------------------------------------------------------
    # export
    # -------------------------------------------------------------
    def _on_export_report(self, fmt: str):
        if not self.current_host:
            return

        if fmt == "html":
            report_text = generate_html_report(
                self.current_host, self.current_matches, scan_profile=self.current_profile,
                exploitdb_available=self.current_exploitdb_available, errors=self.current_errors,
            )
            extension = ".html"
            filetypes = [("HTML file", "*.html")]
        else:
            report_text = generate_report(
                self.current_host, self.current_matches, scan_profile=self.current_profile,
                exploitdb_available=self.current_exploitdb_available, errors=self.current_errors,
            )
            extension = ".txt"
            filetypes = [("Text file", "*.txt")]

        DEFAULT_REPORTS_DIR.mkdir(parents=True, exist_ok=True)
        target_slug = (self.current_host.ip_address or "target").replace(".", "_").replace(":", "_")
        default_name = f"recon_report_{target_slug}{extension}"

        save_path = filedialog.asksaveasfilename(
            title="Export report as...",
            initialdir=str(DEFAULT_REPORTS_DIR),
            initialfile=default_name,
            defaultextension=extension,
            filetypes=filetypes,
        )
        if not save_path:
            return

        try:
            Path(save_path).write_text(report_text, encoding="utf-8")
        except OSError as exc:
            messagebox.showerror("Export failed", f"Could not save report: {exc}")
            return

        self.status_var.set(f"Report saved to {save_path}")
        messagebox.showinfo("Report exported", f"Report saved to:\n{save_path}")


def launch_app():
    root = tk.Tk()
    ReconApp(root)
    root.mainloop()
