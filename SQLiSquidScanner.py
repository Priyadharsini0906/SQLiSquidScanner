import os
import sys
import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext
import threading
import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse, urlunparse
from fpdf import FPDF
import subprocess
import time
import math
from datetime import datetime
from collections import deque

# ─────────────────────────────────────────────
#  Color palette  (Squid Game: dark + teal/cyan)
# ─────────────────────────────────────────────
DARK_BG        = "#0d0d0d"
PANEL_BG       = "#141414"
CARD_BG        = "#1a1a1a"
ACCENT_TEAL    = "#00c9b1"    # primary accent
ACCENT_PINK    = "#e91e8c"    # secondary / danger highlight
TEXT_PRIMARY   = "#e8e8e8"
TEXT_SECONDARY = "#888888"
BORDER_COLOR   = "#2a2a2a"
ENTRY_BG       = "#1f1f1f"
VULN_RED       = "#ff4c4c"
SAFE_GREEN     = "#00d084"

# ─────────────────────────────────────────────
#  Helpers
# ─────────────────────────────────────────────
def normalize_url(url):
    parsed = urlparse(url)
    normalized = urlunparse((parsed.scheme, parsed.netloc, parsed.path.rstrip('/'), '', '', ''))
    return normalized.lower()


# ─────────────────────────────────────────────
#  Main Application
# ─────────────────────────────────────────────
class SQLiScannerApp:
    def __init__(self, root):
        self.root = root
        self.root.title("🦑 SQLi Squid Scanner")
        self.root.geometry("1400x750")
        self.root.configure(bg=DARK_BG)
        self.root.resizable(True, True)

        # ── ttk styles ──────────────────────────────────────
        self._setup_styles()

        # ── Root layout ──────────────────────────────────────
        # Outer frame fills the window
        outer = tk.Frame(self.root, bg=DARK_BG)
        outer.pack(fill="both", expand=True, padx=0, pady=0)

        # Header bar
        self._build_header(outer)

        # Content area (left sidebar + main panel)
        content = tk.Frame(outer, bg=DARK_BG)
        content.pack(fill="both", expand=True, padx=16, pady=(0, 12))

        self._build_sidebar(content)
        self._build_main_panel(content)

        # ── State ────────────────────────────────────────────
        self.payloads = ["' OR '1'='1", "admin'--", "' OR 1=1--", "' OR 'a'='a"]
        self.results = []
        self.scanning = False
        self.vulnerable_urls = set()

        # kick off status bar pulse
        self._pulse_status()

    # ═══════════════════════════════════════════
    #  STYLES
    # ═══════════════════════════════════════════
    def _setup_styles(self):
        self.style = ttk.Style()
        self.style.theme_use("default")

        # Treeview
        self.style.configure(
            "SQ.Treeview",
            background=CARD_BG,
            foreground=TEXT_PRIMARY,
            fieldbackground=CARD_BG,
            rowheight=28,
            borderwidth=0,
            font=("Consolas", 10),
        )
        self.style.configure(
            "SQ.Treeview.Heading",
            background=PANEL_BG,
            foreground=ACCENT_TEAL,
            font=("Segoe UI", 10, "bold"),
            borderwidth=0,
            relief="flat",
        )
        self.style.map("SQ.Treeview",
            background=[("selected", "#1e3a3a")],
            foreground=[("selected", ACCENT_TEAL)],
        )
        self.style.layout("SQ.Treeview", [('Treeview.treearea', {'sticky': 'nswe'})])

        # Progressbar
        self.style.configure(
            "SQ.Horizontal.TProgressbar",
            troughcolor=CARD_BG,
            background=ACCENT_TEAL,
            borderwidth=0,
            thickness=6,
        )

    # ═══════════════════════════════════════════
    #  HEADER
    # ═══════════════════════════════════════════
    def _build_header(self, parent):
        hdr = tk.Frame(parent, bg=PANEL_BG, height=64)
        hdr.pack(fill="x", padx=0, pady=0)
        hdr.pack_propagate(False)

        # Accent stripe on left
        stripe = tk.Frame(hdr, bg=ACCENT_TEAL, width=4)
        stripe.pack(side="left", fill="y")

        # Squid Game shapes (canvas icon)
        icon_canvas = tk.Canvas(hdr, width=48, height=48, bg=PANEL_BG,
                                highlightthickness=0)
        icon_canvas.pack(side="left", padx=(12, 6), pady=8)
        self._draw_squid_icon(icon_canvas, 24, 24, 18)

        # Title
        title_frame = tk.Frame(hdr, bg=PANEL_BG)
        title_frame.pack(side="left", padx=4)
        tk.Label(title_frame, text="SQLi Squid Scanner",
                 font=("Segoe UI", 18, "bold"),
                 bg=PANEL_BG, fg=TEXT_PRIMARY).pack(anchor="w")
        tk.Label(title_frame, text="Advanced SQL Injection Scanner with Crawling",
                 font=("Segoe UI", 9),
                 bg=PANEL_BG, fg=TEXT_SECONDARY).pack(anchor="w")

        # Right: status pill
        right = tk.Frame(hdr, bg=PANEL_BG)
        right.pack(side="right", padx=16)
        self.status_dot = tk.Canvas(right, width=10, height=10, bg=PANEL_BG,
                                    highlightthickness=0)
        self.status_dot.pack(side="left", padx=(0, 6))
        self._dot_id = self.status_dot.create_oval(1, 1, 9, 9, fill=TEXT_SECONDARY, outline="")
        self.status_lbl = tk.Label(right, text="Idle",
                                   font=("Segoe UI", 9),
                                   bg=PANEL_BG, fg=TEXT_SECONDARY)
        self.status_lbl.pack(side="left")

        # Divider
        tk.Frame(parent, bg=BORDER_COLOR, height=1).pack(fill="x")

    def _draw_squid_icon(self, canvas, cx, cy, r):
        """Draw the three Squid Game shapes as a tiny icon."""
        # Circle
        canvas.create_oval(cx + r - 8, cy - r, cx + r + 8, cy + r - 16,
                           outline=ACCENT_TEAL, width=2, fill="")
        # Triangle
        pts = [cx - r - 10, cy + r - 6, cx - r + 2, cy - r + 8, cx - r + 14, cy + r - 6]
        canvas.create_polygon(pts, outline=ACCENT_PINK, width=2, fill="")
        # Square
        canvas.create_rectangle(cx - 8, cy - 4, cx + 8, cy + 12,
                                outline=TEXT_PRIMARY, width=2, fill="")

    # ═══════════════════════════════════════════
    #  SIDEBAR
    # ═══════════════════════════════════════════
    def _build_sidebar(self, parent):
        sidebar = tk.Frame(parent, bg=PANEL_BG, width=220)
        sidebar.pack(side="left", fill="y", padx=(0, 12), pady=12)
        sidebar.pack_propagate(False)

        tk.Label(sidebar, text="ACTIONS",
                 font=("Segoe UI", 8, "bold"),
                 bg=PANEL_BG, fg=TEXT_SECONDARY).pack(anchor="w", padx=14, pady=(14, 4))

        self._sidebar_btn(sidebar, "📂  Load Payloads", self.load_payloads, ACCENT_TEAL)
        self._sidebar_btn(sidebar, "🚀  Start Scan",     self.start_scan_thread, ACCENT_TEAL)

        tk.Frame(sidebar, bg=BORDER_COLOR, height=1).pack(fill="x", padx=10, pady=8)
        tk.Label(sidebar, text="RESULTS",
                 font=("Segoe UI", 8, "bold"),
                 bg=PANEL_BG, fg=TEXT_SECONDARY).pack(anchor="w", padx=14, pady=(0, 4))

        self._sidebar_btn(sidebar, "📄  Export to PDF",     self.export_to_pdf,   ACCENT_PINK)
        self._sidebar_btn(sidebar, "🧠  Database Details",  self.show_db_details, ACCENT_PINK)

        tk.Frame(sidebar, bg=BORDER_COLOR, height=1).pack(fill="x", padx=10, pady=8)

        # Stats panel
        stats_card = tk.Frame(sidebar, bg=CARD_BG, bd=0)
        stats_card.pack(fill="x", padx=10, pady=4)
        tk.Label(stats_card, text="SCAN STATS",
                 font=("Segoe UI", 8, "bold"),
                 bg=CARD_BG, fg=TEXT_SECONDARY).pack(anchor="w", padx=10, pady=(10, 4))

        self.stat_total_lbl = self._stat_row(stats_card, "Total Tested", "0")
        self.stat_vuln_lbl  = self._stat_row(stats_card, "Vulnerable",   "0", VULN_RED)
        self.stat_safe_lbl  = self._stat_row(stats_card, "Safe",          "0", SAFE_GREEN)
        tk.Frame(stats_card, bg=CARD_BG, height=6).pack()

    def _sidebar_btn(self, parent, text, cmd, accent):
        btn = tk.Frame(parent, bg=PANEL_BG, cursor="hand2")
        btn.pack(fill="x", padx=10, pady=2)

        stripe = tk.Frame(btn, bg=accent, width=3)
        stripe.pack(side="left", fill="y")

        inner = tk.Frame(btn, bg=PANEL_BG, pady=8, padx=10)
        inner.pack(side="left", fill="both", expand=True)

        lbl = tk.Label(inner, text=text, font=("Segoe UI", 10, "bold"),
                       bg=PANEL_BG, fg=TEXT_PRIMARY, anchor="w")
        lbl.pack(fill="x")

        def _enter(e):
            btn.configure(bg=CARD_BG)
            inner.configure(bg=CARD_BG)
            lbl.configure(bg=CARD_BG, fg=accent)
        def _leave(e):
            btn.configure(bg=PANEL_BG)
            inner.configure(bg=PANEL_BG)
            lbl.configure(bg=PANEL_BG, fg=TEXT_PRIMARY)
        def _click(e):
            cmd()

        for w in (btn, stripe, inner, lbl):
            w.bind("<Enter>", _enter)
            w.bind("<Leave>", _leave)
        for w in (btn, inner, lbl):
            w.bind("<Button-1>", _click)

    def _stat_row(self, parent, label, value, color=TEXT_PRIMARY):
        row = tk.Frame(parent, bg=CARD_BG)
        row.pack(fill="x", padx=10, pady=2)
        tk.Label(row, text=label, font=("Segoe UI", 9), bg=CARD_BG,
                 fg=TEXT_SECONDARY).pack(side="left")
        val_lbl = tk.Label(row, text=value, font=("Segoe UI", 9, "bold"),
                           bg=CARD_BG, fg=color)
        val_lbl.pack(side="right")
        return val_lbl

    # ═══════════════════════════════════════════
    #  MAIN PANEL
    # ═══════════════════════════════════════════
    def _build_main_panel(self, parent):
        main = tk.Frame(parent, bg=DARK_BG)
        main.pack(side="left", fill="both", expand=True)

        # ── URL input card ───────────────────────────────────
        url_card = tk.Frame(main, bg=CARD_BG, bd=0)
        url_card.pack(fill="x", pady=(12, 0))

        tk.Label(url_card, text="TARGET URL",
                 font=("Segoe UI", 8, "bold"),
                 bg=CARD_BG, fg=TEXT_SECONDARY).pack(anchor="w", padx=14, pady=(10, 2))

        url_row = tk.Frame(url_card, bg=CARD_BG)
        url_row.pack(fill="x", padx=14, pady=(0, 12))

        # URL entry with accent border
        entry_wrap = tk.Frame(url_row, bg=ACCENT_TEAL, bd=0)
        entry_wrap.pack(side="left", fill="x", expand=True, padx=(0, 10))
        inner_wrap = tk.Frame(entry_wrap, bg=ENTRY_BG, bd=0)
        inner_wrap.pack(fill="both", expand=True, padx=1, pady=1)

        self.url_entry = tk.Entry(inner_wrap, font=("Consolas", 11),
                                  bg=ENTRY_BG, fg=TEXT_PRIMARY,
                                  insertbackground=ACCENT_TEAL,
                                  bd=0, highlightthickness=0,
                                  relief="flat")
        self.url_entry.pack(fill="x", padx=10, pady=8, expand=True)
        self.url_entry.insert(0, "https://")

        # Placeholder behaviour
        def _focus_in(e):
            if self.url_entry.get() == "https://":
                self.url_entry.delete(0, "end")
        def _focus_out(e):
            if not self.url_entry.get().strip():
                self.url_entry.insert(0, "https://")
        self.url_entry.bind("<FocusIn>",  _focus_in)
        self.url_entry.bind("<FocusOut>", _focus_out)

        # Scan button inline
        scan_btn = self._flat_btn(url_row, "▶  SCAN", self.start_scan_thread, ACCENT_TEAL)
        scan_btn.pack(side="left")

        # ── Progress bar ─────────────────────────────────────
        prog_frame = tk.Frame(main, bg=DARK_BG)
        prog_frame.pack(fill="x", pady=(8, 0))

        self.progress_lbl = tk.Label(prog_frame, text="",
                                     font=("Segoe UI", 8),
                                     bg=DARK_BG, fg=TEXT_SECONDARY)
        self.progress_lbl.pack(anchor="w")

        self.progress = ttk.Progressbar(prog_frame, orient="horizontal",
                                        mode="determinate",
                                        style="SQ.Horizontal.TProgressbar")
        self.progress.pack(fill="x", pady=(2, 0))

        # ── Results table card ───────────────────────────────
        table_card = tk.Frame(main, bg=CARD_BG, bd=0)
        table_card.pack(fill="both", expand=True, pady=(10, 0))

        hdr_row = tk.Frame(table_card, bg=CARD_BG)
        hdr_row.pack(fill="x", padx=14, pady=(10, 6))
        tk.Label(hdr_row, text="SCAN RESULTS",
                 font=("Segoe UI", 9, "bold"),
                 bg=CARD_BG, fg=TEXT_SECONDARY).pack(side="left")

        self.result_count_lbl = tk.Label(hdr_row, text="0 entries",
                                         font=("Segoe UI", 9),
                                         bg=CARD_BG, fg=TEXT_SECONDARY)
        self.result_count_lbl.pack(side="right")

        # Treeview + scrollbar
        tree_wrap = tk.Frame(table_card, bg=CARD_BG)
        tree_wrap.pack(fill="both", expand=True, padx=4, pady=(0, 8))

        columns = ("Payload", "Action URL", "Vulnerable", "Error Type",
                   "SQLi Type", "Status Code/Error", "Database")
        self.tree = ttk.Treeview(tree_wrap, columns=columns,
                                 show="headings", height=20,
                                 style="SQ.Treeview")

        self.tree.tag_configure("vulnerable", foreground=VULN_RED)
        self.tree.tag_configure("safe",       foreground=SAFE_GREEN)

        col_widths = {
            "Payload": 160, "Action URL": 260, "Vulnerable": 80,
            "Error Type": 140, "SQLi Type": 120,
            "Status Code/Error": 140, "Database": 100,
        }
        for col in columns:
            self.tree.heading(col, text=col)
            self.tree.column(col, width=col_widths.get(col, 140), anchor="w", stretch=False)

        vsb = ttk.Scrollbar(tree_wrap, orient="vertical",   command=self.tree.yview)
        hsb = ttk.Scrollbar(tree_wrap, orient="horizontal",  command=self.tree.xview)
        self.tree.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)

        self.tree.grid(row=0, column=0, sticky="nsew")
        vsb.grid(row=0, column=1, sticky="ns")
        hsb.grid(row=1, column=0, sticky="ew")
        tree_wrap.grid_rowconfigure(0, weight=1)
        tree_wrap.grid_columnconfigure(0, weight=1)

        self.tree.bind("<Double-1>", self.on_double_click)

        # Tooltip
        self.tooltip = tk.Label(self.root, text="",
                                background=CARD_BG, fg=ACCENT_TEAL,
                                font=("Segoe UI", 9),
                                padx=8, pady=4,
                                relief="flat", bd=0,
                                wraplength=500)
        self.tree.bind("<Motion>", self.on_hover)
        self.tree.bind("<Leave>",  lambda e: self.tooltip.place_forget())

    def _flat_btn(self, parent, text, cmd, color):
        btn = tk.Frame(parent, bg=color, cursor="hand2", bd=0)
        lbl = tk.Label(btn, text=text, font=("Segoe UI", 10, "bold"),
                       bg=color, fg=DARK_BG, padx=16, pady=8)
        lbl.pack()

        def _enter(e):
            btn.configure(bg="#00b39d")
            lbl.configure(bg="#00b39d")
        def _leave(e):
            btn.configure(bg=color)
            lbl.configure(bg=color)
        def _click(e):
            cmd()

        for w in (btn, lbl):
            w.bind("<Enter>",    _enter)
            w.bind("<Leave>",    _leave)
            w.bind("<Button-1>", _click)
        return btn

    # ═══════════════════════════════════════════
    #  STATUS / PULSE
    # ═══════════════════════════════════════════
    def _pulse_status(self):
        if self.scanning:
            color = ACCENT_TEAL if int(time.time() * 2) % 2 == 0 else PANEL_BG
            self.status_dot.itemconfig(self._dot_id, fill=color)
        else:
            self.status_dot.itemconfig(self._dot_id, fill=TEXT_SECONDARY)
        self.root.after(500, self._pulse_status)

    def _set_status(self, text, scanning=False):
        self.scanning = scanning
        self.status_lbl.config(text=text, fg=ACCENT_TEAL if scanning else TEXT_SECONDARY)

    def _update_stats(self):
        total = len(self.results)
        vuln  = sum(1 for r in self.results if r[2] == "Yes")
        safe  = total - vuln
        self.stat_total_lbl.config(text=str(total))
        self.stat_vuln_lbl.config(text=str(vuln))
        self.stat_safe_lbl.config(text=str(safe))
        self.result_count_lbl.config(text=f"{total} entries")

    # ═══════════════════════════════════════════
    #  CORE LOGIC (original, unchanged)
    # ═══════════════════════════════════════════
    # ─────────────────────────────────────────
    #  PAYLOADS
    # ─────────────────────────────────────────
    def load_payloads(self):
        file_path = filedialog.askopenfilename(
            title="Select Payload File", filetypes=[("Text Files", "*.txt")])
        if file_path:
            try:
                with open(file_path, "r", encoding="utf-8") as f:
                    self.payloads = [l.strip() for l in f if l.strip()]
                messagebox.showinfo("Success", f"Loaded {len(self.payloads)} payloads.")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to load payloads: {str(e)}")

    # ─────────────────────────────────────────
    #  PDF EXPORT  (styled)
    # ─────────────────────────────────────────
    def export_to_pdf(self):
        if not self.results:
            messagebox.showwarning("No Results", "Run a scan first — no results to export.")
            return
        file_path = filedialog.asksaveasfilename(
            defaultextension=".pdf",
            filetypes=[("PDF files", "*.pdf")],
            title="Save Scan Report as PDF")
        if not file_path:
            return

        try:
            pdf = FPDF()
            pdf.set_auto_page_break(auto=True, margin=18)
            pdf.add_page()

            # ── Header banner ──────────────────────────────
            pdf.set_fill_color(13, 13, 13)       # dark bg
            pdf.rect(0, 0, 210, 28, 'F')
            pdf.set_font("Arial", style="B", size=16)
            pdf.set_text_color(0, 201, 177)       # teal
            pdf.set_xy(10, 8)
            pdf.cell(0, 12, "SQLi Squid Scanner  |  Scan Report", ln=1)

            pdf.set_font("Arial", size=8)
            pdf.set_text_color(136, 136, 136)
            pdf.set_xy(10, 20)
            scan_url = self.url_entry.get().strip()
            pdf.cell(0, 6, f"Target: {scan_url}    Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", ln=1)
            pdf.ln(4)

            # ── Summary box ────────────────────────────────
            total = len(self.results)
            vuln  = sum(1 for r in self.results if r[2] == "Yes")
            safe  = total - vuln

            pdf.set_fill_color(26, 26, 26)
            pdf.set_draw_color(42, 42, 42)
            pdf.rect(10, pdf.get_y(), 190, 20, 'FD')

            pdf.set_xy(14, pdf.get_y() + 4)
            pdf.set_font("Arial", style="B", size=10)
            pdf.set_text_color(232, 232, 232)
            pdf.cell(55, 6, f"Total Tested: {total}")
            pdf.set_text_color(255, 76, 76)
            pdf.cell(60, 6, f"Vulnerable: {vuln}")
            pdf.set_text_color(0, 208, 132)
            pdf.cell(60, 6, f"Safe: {safe}")
            pdf.ln(20)

            # ── Column definitions ─────────────────────────
            headers    = ["Payload", "Action URL", "Vuln?", "Error Type", "SQLi Type", "Status"]
            col_widths = [32, 62, 18, 34, 30, 24]

            def draw_table_header():
                pdf.set_fill_color(20, 20, 20)
                pdf.set_draw_color(42, 42, 42)
                pdf.set_font("Arial", style="B", size=8)
                pdf.set_text_color(0, 201, 177)   # teal headings
                for i, h in enumerate(headers):
                    pdf.cell(col_widths[i], 8, h, border=1, fill=True)
                pdf.ln()

            draw_table_header()

            # ── Rows ───────────────────────────────────────
            pdf.set_font("Arial", size=7)
            for row in self.results:
                is_vuln = str(row[2]) == "Yes"

                # Compute wrapped lines per cell
                wrapped = []
                max_lines = 1
                for i, item in enumerate(row[:len(col_widths)]):
                    lines = pdf.multi_cell(col_widths[i], 4, str(item),
                                           border=0, split_only=True)
                    wrapped.append(lines)
                    max_lines = max(max_lines, len(lines))

                row_h = max_lines * 4 + 2
                if pdf.get_y() + row_h > 272:
                    pdf.add_page()
                    draw_table_header()

                y0 = pdf.get_y()
                x0 = 10.0

                # Row fill
                if is_vuln:
                    pdf.set_fill_color(60, 10, 10)
                    pdf.set_text_color(255, 120, 120)
                else:
                    pdf.set_fill_color(10, 30, 20)
                    pdf.set_text_color(100, 220, 160)

                pdf.set_draw_color(42, 42, 42)
                for i, col_w in enumerate(col_widths):
                    cell_txt = wrapped[i][0] if wrapped[i] else ""
                    pdf.set_xy(x0, y0)
                    pdf.cell(col_w, row_h, cell_txt, border=1, fill=True)
                    x0 += col_w

                pdf.set_y(y0 + row_h)

            # ── Footer ─────────────────────────────────────
            pdf.set_y(-15)
            pdf.set_font("Arial", style="I", size=7)
            pdf.set_text_color(80, 80, 80)
            pdf.cell(0, 6, f"Page {pdf.page_no()}  |  SQLi Squid Scanner", align="C")

            pdf.output(file_path)
            messagebox.showinfo("Exported", f"Report saved:\n{file_path}")
        except Exception as e:
            messagebox.showerror("Export Failed", str(e))

    # ─────────────────────────────────────────
    #  SQLMAP INTEGRATION
    # ─────────────────────────────────────────
    def _get_sqlmap_path(self):
        """Resolve sqlmap.py path; return None if missing."""
        script_dir  = os.path.dirname(os.path.abspath(__file__))
        local_path  = os.path.join(script_dir, "sqlmap-master", "sqlmap-master", "sqlmap.py")
        if os.path.isfile(local_path):
            return local_path
        # Fallback: look for system sqlmap
        for candidate in ["sqlmap", "sqlmap.py"]:
            try:
                result = subprocess.run([candidate, "--version"],
                                        capture_output=True, text=True, timeout=4)
                if result.returncode == 0:
                    return candidate
            except Exception:
                pass
        return None

    def open_sqlmap_window(self, url, mode="dbs"):
        """Open a live SQLMap output terminal window."""
        sqlmap_path = self._get_sqlmap_path()
        if not sqlmap_path:
            messagebox.showerror(
                "SQLMap Not Found",
                "Could not find sqlmap.py.\n"
                "Expected at: sqlmap-master/sqlmap-master/sqlmap.py")
            return

        # ── Window setup ──────────────────────────────────
        win = tk.Toplevel(self.root)
        win.title(f"SQLMap  |  {url[:60]}")
        win.geometry("900x580")
        win.configure(bg=DARK_BG)
        win.resizable(True, True)

        # Header
        hdr = tk.Frame(win, bg=PANEL_BG)
        hdr.pack(fill="x")
        tk.Frame(hdr, bg=ACCENT_TEAL, width=4).pack(side="left", fill="y")
        info = tk.Frame(hdr, bg=PANEL_BG)
        info.pack(side="left", padx=10, pady=8)
        tk.Label(info, text="🧠  SQLMap Live Terminal",
                 font=("Segoe UI", 12, "bold"),
                 bg=PANEL_BG, fg=TEXT_PRIMARY).pack(anchor="w")
        tk.Label(info, text=url,
                 font=("Consolas", 8),
                 bg=PANEL_BG, fg=TEXT_SECONDARY).pack(anchor="w")
        tk.Frame(win, bg=BORDER_COLOR, height=1).pack(fill="x")

        # Mode buttons
        btn_row = tk.Frame(win, bg=DARK_BG)
        btn_row.pack(fill="x", padx=10, pady=6)
        tk.Label(btn_row, text="Run:",
                 font=("Segoe UI", 9),
                 bg=DARK_BG, fg=TEXT_SECONDARY).pack(side="left", padx=(0, 8))

        self._active_proc = None

        def _run_mode(m):
            """Kill any running proc, clear output, start new sqlmap."""
            if self._active_proc and self._active_proc.poll() is None:
                self._active_proc.kill()
            out_box.configure(state="normal")
            out_box.delete("1.0", "end")
            threading.Thread(
                target=_stream_sqlmap, args=(m,), daemon=True).start()

        modes = [
            ("List Databases",   "dbs"),
            ("List Tables",      "tables"),
            ("Dump Data",        "dump"),
            ("OS Shell",         "os-shell"),
        ]
        for label, m in modes:
            color = ACCENT_TEAL if m == mode else "#2a2a2a"
            fg    = DARK_BG    if m == mode else TEXT_SECONDARY
            f = tk.Frame(btn_row, bg=color, cursor="hand2")
            f.pack(side="left", padx=3)
            l = tk.Label(f, text=label, font=("Segoe UI", 8, "bold"),
                         bg=color, fg=fg, padx=10, pady=5)
            l.pack()
            cap_m = m
            def _enter(e, fr=f, lbl=l, c=color):
                fr.configure(bg="#00b39d" if c == ACCENT_TEAL else "#3a3a3a")
                lbl.configure(bg="#00b39d" if c == ACCENT_TEAL else "#3a3a3a")
            def _leave(e, fr=f, lbl=l, c=color):
                fr.configure(bg=c); lbl.configure(bg=c)
            for w in (f, l):
                w.bind("<Enter>", _enter)
                w.bind("<Leave>", _leave)
                w.bind("<Button-1>", lambda e, cm=cap_m: _run_mode(cm))

        # Kill button
        def _kill():
            if self._active_proc and self._active_proc.poll() is None:
                self._active_proc.kill()
                _append("\n[KILLED]\n", "error")
        kf = tk.Frame(btn_row, bg=ACCENT_PINK, cursor="hand2")
        kf.pack(side="right", padx=3)
        kl = tk.Label(kf, text="■  Kill", font=("Segoe UI", 8, "bold"),
                      bg=ACCENT_PINK, fg="white", padx=10, pady=5)
        kl.pack()
        for w in (kf, kl):
            w.bind("<Button-1>", lambda e: _kill())

        # Terminal output box
        out_box = scrolledtext.ScrolledText(
            win,
            font=("Consolas", 9),
            bg="#0a0a0a", fg=TEXT_PRIMARY,
            insertbackground=ACCENT_TEAL,
            relief="flat", bd=0,
            state="disabled")
        out_box.pack(fill="both", expand=True, padx=6, pady=(4, 6))

        # Colour tags
        out_box.tag_configure("teal",   foreground=ACCENT_TEAL)
        out_box.tag_configure("pink",   foreground=ACCENT_PINK)
        out_box.tag_configure("green",  foreground=SAFE_GREEN)
        out_box.tag_configure("error",  foreground=VULN_RED)
        out_box.tag_configure("normal", foreground=TEXT_PRIMARY)
        out_box.tag_configure("dim",    foreground=TEXT_SECONDARY)

        def _append(text, tag="normal"):
            out_box.configure(state="normal")
            out_box.insert("end", text, tag)
            out_box.see("end")
            out_box.configure(state="disabled")

        def _classify(line):
            l = line.lower()
            if any(x in l for x in ["[*]", "[info]"]):
                return "teal"
            if any(x in l for x in ["[warning]", "[critical]"]):
                return "pink"
            if any(x in l for x in ["vulnerable", "injectable", "database:"]):
                return "green"
            if any(x in l for x in ["error", "traceback", "exception"]):
                return "error"
            if line.startswith("["):
                return "dim"
            return "normal"

        def _stream_sqlmap(run_mode):
            """Run sqlmap and stream output into the terminal box."""
            flag_map = {
                "dbs":      ["--dbs"],
                "tables":   ["--tables"],
                "dump":     ["--dump",   "--batch"],
                "os-shell": ["--os-shell"],
            }
            flags = flag_map.get(run_mode, ["--dbs"])
            cmd = [sys.executable, sqlmap_path, "-u", url, "--batch"] + flags

            _append(f"$ {' '.join(cmd)}\n\n", "dim")
            try:
                proc = subprocess.Popen(
                    cmd,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                    text=True,
                    bufsize=1,
                    encoding="utf-8",
                    errors="replace",
                )
                self._active_proc = proc
                for line in proc.stdout:
                    tag = _classify(line)
                    win.after(0, lambda t=line, tg=tag: _append(t, tg))
                proc.wait()
                win.after(0, lambda: _append(
                    f"\n[Process exited with code {proc.returncode}]\n", "dim"))
            except Exception as exc:
                win.after(0, lambda: _append(f"\n[ERROR] {exc}\n", "error"))

        # Auto-start with requested mode
        threading.Thread(target=_stream_sqlmap, args=(mode,), daemon=True).start()

    def show_db_details(self):
        selected = self.tree.focus()
        if not selected:
            messagebox.showwarning("No Selection",
                "Select a row in the results table, then click Database Details.")
            return
        values = self.tree.item(selected, "values")
        url    = values[1]
        self.open_sqlmap_window(url, mode="dbs")

    def on_double_click(self, event):
        self.show_db_details()

    def run_sqlmap(self, url):
        """Auto-trigger SQLMap in background when vulnerability detected during scan."""
        sqlmap_path = self._get_sqlmap_path()
        if not sqlmap_path:
            return
        try:
            subprocess.Popen(
                [sys.executable, sqlmap_path, "-u", url, "--batch", "--dbs"],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
        except Exception as e:
            print(f"[SQLMap background] {e}")

    def start_scan_thread(self):
        if self.scanning:
            messagebox.showinfo("Scan Running", "A scan is already in progress.")
            return
        threading.Thread(target=self.start_scan, daemon=True).start()

    # ─────────────────────────────────────────
    #  CRAWLER  (fixed — all same-domain pages)
    # ─────────────────────────────────────────
    # Extensions that never contain HTML forms
    _SKIP_EXT = {".jpg",".jpeg",".png",".gif",".svg",".webp",
                 ".css",".js",".ico",".woff",".woff2",".ttf",
                 ".eot",".pdf",".zip",".gz",".tar",".mp4",".mp3"}

    def _is_crawlable(self, url, base_netloc):
        """Return True if the URL is worth crawling."""
        try:
            p = urlparse(url)
        except Exception:
            return False
        if p.scheme not in ("http", "https"):
            return False
        if p.netloc != base_netloc:
            return False          # stay on the same host
        ext = os.path.splitext(p.path)[1].lower()
        if ext in self._SKIP_EXT:
            return False
        return True

    def crawl_site(self, base_url, max_pages=50):
        """BFS crawl — visits every HTML page on the same domain."""
        base_netloc   = urlparse(base_url).netloc
        visited_norm  = set()
        queue         = deque([base_url])
        queued_norm   = {normalize_url(base_url)}
        session       = requests.Session()
        session.headers.update({"User-Agent": "Mozilla/5.0 SQLiSquidScanner/1.0"})

        while queue and len(visited_norm) < max_pages:
            url      = queue.popleft()
            norm     = normalize_url(url)
            if norm in visited_norm:
                continue
            visited_norm.add(norm)

            self.root.after(0, lambda u=url: self.progress_lbl.config(
                text=f"Crawling [{len(visited_norm)}/{max_pages}]: {u[:80]}"))

            try:
                resp = session.get(url, timeout=10, allow_redirects=True)
                if "text/html" not in resp.headers.get("Content-Type", ""):
                    continue
                soup = BeautifulSoup(resp.text, "html.parser")
                for tag in soup.find_all("a", href=True):
                    href      = tag["href"].strip()
                    # skip anchors, javascript, mailto
                    if href.startswith(("#", "javascript:", "mailto:", "tel:")):
                        continue
                    full      = urljoin(url, href)
                    full_norm = normalize_url(full)
                    if (full_norm not in visited_norm
                            and full_norm not in queued_norm
                            and self._is_crawlable(full, base_netloc)):
                        queue.append(full)
                        queued_norm.add(full_norm)
            except Exception:
                continue

        self.root.after(0, lambda: self.progress_lbl.config(
            text=f"Crawl done — {len(visited_norm)} pages found. Testing forms…"))
        return visited_norm

    def start_scan(self):
        url = self.url_entry.get().strip()
        if not url or url == "https://":
            messagebox.showerror("Error", "Please enter a target URL.")
            return
        if not url.startswith("http://") and not url.startswith("https://"):
            url = "http://" + url

        self._set_status("Scanning…", scanning=True)
        self.results.clear()
        self.vulnerable_urls.clear()
        self.tree.delete(*self.tree.get_children())
        self.progress["value"] = 0
        self._update_stats()

        self.root.after(0, lambda: self.progress_lbl.config(text="Crawling site…"))
        crawled_links = self.crawl_site(url)
        total_payloads = len(self.payloads)
        self.progress["maximum"] = max(total_payloads * len(crawled_links), 1)

        done = 0
        for page_url in crawled_links:
            forms = self.find_forms(page_url)
            if not forms:
                continue
            for form in forms:
                form_details = self.extract_form_details(form, page_url)
                action_url   = form_details["action"]
                for payload in self.payloads:
                    if not self.scanning:
                        break
                    data = {}
                    for inp in form_details["inputs"]:
                        if inp["type"] in ["text", "password", "search", "email", "url"]:
                            data[inp["name"]] = payload
                        else:
                            data[inp["name"]] = inp["value"]
                    try:
                        if form_details["method"] == "post":
                            response = requests.post(action_url, data=data, timeout=10)
                        else:
                            response = requests.get(action_url, params=data, timeout=10)

                        if self.is_sql_injection(response.text):
                            vulnerable = "Yes"
                            error_category, sqli_type, db_type = self.extract_error_info(response.text)
                            if action_url not in self.vulnerable_urls:
                                self.vulnerable_urls.add(action_url)
                                threading.Thread(target=self.run_sqlmap, args=(action_url,), daemon=True).start()
                        else:
                            vulnerable = "No"
                            error_category, sqli_type, db_type = "-", "-", "-"

                        result = (payload, action_url, vulnerable,
                                  error_category, sqli_type, response.status_code, db_type)
                    except Exception as e:
                        result = (payload, action_url, "No", "Network Error", "-", str(e), "-")

                    self.results.append(result)
                    done += 1

                    def _insert(res=result, d=done):
                        tag = "vulnerable" if res[2] == "Yes" else "safe"
                        self.tree.insert("", "end", values=res, tags=(tag,))
                        self.tree.yview_moveto(1.0)
                        self.progress["value"] = d
                        pct = int(d / max(self.progress["maximum"], 1) * 100)
                        self.progress_lbl.config(text=f"Testing payloads… {pct}%")
                        self._update_stats()

                    self.root.after(0, _insert)

        self.scanning = False
        self._set_status("Idle")
        vuln_count = sum(1 for r in self.results if r[2] == "Yes")
        self.root.after(0, lambda: self.progress_lbl.config(
            text=f"Scan complete — {len(self.results)} tested, {vuln_count} vulnerable"))
        messagebox.showinfo(
            "Scan Complete",
            f"Scan complete!\n\nTotal payloads tested: {total_payloads}\n"
            f"Vulnerabilities found: {vuln_count}")

    def on_hover(self, event):
        item   = self.tree.identify_row(event.y)
        column = self.tree.identify_column(event.x)
        if item and column == "#2":
            url_value = self.tree.item(item, "values")[1]
            self.tooltip.place(
                x=event.x_root - self.root.winfo_rootx() + 20,
                y=event.y_root - self.root.winfo_rooty() + 20)
            self.tooltip.config(text=url_value)
        else:
            self.tooltip.place_forget()

    def find_forms(self, url):
        try:
            res  = requests.get(url, timeout=10)
            soup = BeautifulSoup(res.text, "html.parser")
            return soup.find_all("form")
        except:
            return []

    def extract_form_details(self, form, page_url):
        action = form.attrs.get("action") or page_url
        if action != page_url:
            action = urljoin(page_url, action)
        method = form.attrs.get("method", "get").lower()
        inputs = []
        for input_tag in form.find_all("input"):
            input_type  = input_tag.attrs.get("type", "text").lower()
            input_name  = input_tag.attrs.get("name")
            input_value = input_tag.attrs.get("value", "")
            if input_name:
                inputs.append({"type": input_type, "name": input_name, "value": input_value})
        return {"action": action, "method": method, "inputs": inputs}

    def is_sql_injection(self, response_text):
        errors = [
            "you have an error in your sql syntax;",
            "warning: mysql",
            "unclosed quotation mark after the character string",
            "quoted string not properly terminated",
            "syntax error",
            "mysql_fetch_array()",
            "mysql_num_rows()",
            "mysql_fetch_assoc()",
            "mysql_query()",
            "pg_query()",
            "pg_fetch_array()",
            "syntax error in query",
            "sqlstate",
        ]
        lower_text = response_text.lower()
        return any(error in lower_text for error in errors)

    def extract_error_info(self, response_text):
        if "mysql" in response_text.lower():
            return ("MySQL Error", "Boolean-based", "MySQL")
        elif "syntax error" in response_text.lower() or "sql syntax" in response_text.lower():
            return ("Syntax Error", "Error-based", "-")
        elif "unclosed quotation" in response_text.lower():
            return ("Unclosed Quotation", "Error-based", "-")
        elif "pg_query" in response_text.lower():
            return ("PostgreSQL Error", "Boolean-based", "PostgreSQL")
        else:
            return ("Unknown", "-", "-")


# ─────────────────────────────────────────────
#  SPLASH SCREEN  (Squid Game intro)
# ─────────────────────────────────────────────
class SplashScreen:
    """
    Full-screen Squid Game themed splash.
    Shows the three shapes with a slow draw-in animation,
    then fades to a YES / NO prompt before launching the main app.
    """
    SHAPES_COLOR  = "#ffffff"
    ACCENT_TEAL   = "#00c9b1"
    ACCENT_PINK   = "#e91e8c"
    BG            = "#0d0d0d"

    def __init__(self, root, on_proceed):
        self.root       = root
        self.on_proceed = on_proceed
        self._build()

    def _build(self):
        self.splash = tk.Toplevel(self.root)
        self.splash.attributes("-fullscreen", True)
        self.splash.configure(bg=self.BG)
        self.splash.overrideredirect(True)
        self.splash.lift()
        self.splash.focus_force()

        self.canvas = tk.Canvas(self.splash, bg=self.BG, highlightthickness=0)
        self.canvas.pack(fill="both", expand=True)

        self.w = self.splash.winfo_screenwidth()
        self.h = self.splash.winfo_screenheight()
        cx, cy = self.w // 2, self.h // 2

        # ── Background grid lines ────────────────────────────
        for gx in range(0, self.w, 80):
            self.canvas.create_line(gx, 0, gx, self.h,
                                    fill="#161616", width=1)
        for gy in range(0, self.h, 80):
            self.canvas.create_line(0, gy, self.w, gy,
                                    fill="#161616", width=1)

        # ── Shapes ──────────────────────────────────────────
        sz = 90   # shape half-size

        # Circle  (right)
        self._circle = self.canvas.create_oval(
            cx + 160, cy - sz,
            cx + 160 + sz * 2, cy + sz,
            outline=self.ACCENT_TEAL, width=5, fill="")

        # Triangle (center)
        tp = [cx, cy - sz - 10,
              cx - sz, cy + sz,
              cx + sz, cy + sz]
        self._triangle = self.canvas.create_polygon(tp, outline=self.SHAPES_COLOR,
                                                     width=5, fill="")

        # Square  (left)
        self._square = self.canvas.create_rectangle(
            cx - 160 - sz * 2, cy - sz,
            cx - 160, cy + sz,
            outline=self.ACCENT_PINK, width=5, fill="")

        # ── Title text ───────────────────────────────────────
        self._title = self.canvas.create_text(
            cx, cy + sz + 70,
            text="SQLi SQUID SCANNER",
            fill=self.SHAPES_COLOR,
            font=("Segoe UI", 32, "bold"),
            state="hidden")

        self._subtitle = self.canvas.create_text(
            cx, cy + sz + 115,
            text="Advanced SQL Injection Scanner with Crawling",
            fill="#555555",
            font=("Segoe UI", 13),
            state="hidden")

        self._loading = self.canvas.create_text(
            cx, cy + sz + 155,
            text="",
            fill=self.ACCENT_TEAL,
            font=("Segoe UI", 11),
            state="hidden")

        # ── Number badge ──────────────────────────────────────
        self.canvas.create_text(
            cx, cy - sz - 60,
            text="456",
            fill="#222222",
            font=("Segoe UI", 48, "bold"))

        # Start animation thread
        threading.Thread(target=self._animate, daemon=True).start()

    def _animate(self):
        """Animate shapes floating in, then show loading bar, then prompt."""
        cx, cy = self.w // 2, self.h // 2
        steps  = 40

        # Float in from off-screen
        for i in range(steps):
            t = i / steps
            ease = 1 - (1 - t) ** 3   # ease-out cubic

            tri_off  = int((1 - ease) * 200)
            sq_off   = int((1 - ease) * -300)
            circ_off = int((1 - ease) * 300)

            sz = 90
            # triangle floats up
            tp = [cx, cy - sz - 10 + tri_off,
                  cx - sz, cy + sz + tri_off,
                  cx + sz, cy + sz + tri_off]
            self.canvas.coords(self._triangle, *tp)

            # square slides right
            self.canvas.coords(self._square,
                cx - 160 - sz * 2 + sq_off, cy - sz,
                cx - 160 + sq_off, cy + sz)

            # circle slides left
            self.canvas.coords(self._circle,
                cx + 160 + circ_off, cy - sz,
                cx + 160 + sz * 2 + circ_off, cy + sz)

            time.sleep(0.025)

        # Show title
        self.canvas.itemconfig(self._title,    state="normal")
        self.canvas.itemconfig(self._subtitle, state="normal")
        self.canvas.itemconfig(self._loading,  state="normal")

        # Loading dots
        dots_seq = ["Loading .", "Loading . .", "Loading . . .", "Loading . . . ."]
        for _ in range(3):
            for d in dots_seq:
                self.canvas.itemconfig(self._loading, text=d)
                time.sleep(0.25)

        # Show prompt after animation
        self.splash.after(0, self._show_prompt)

    def _show_prompt(self):
        cx, cy = self.w // 2, self.h // 2

        # Dim overlay
        overlay = tk.Frame(self.splash, bg="#0d0d0d")
        overlay.place(relx=0, rely=0, relwidth=1, relheight=1)
        overlay.lower()

        # Prompt card
        card_w, card_h = 460, 220
        card_x = (self.w - card_w) // 2
        card_y = (self.h - card_h) // 2

        card = tk.Frame(self.splash, bg="#141414", bd=0)
        card.place(x=card_x, y=card_y, width=card_w, height=card_h)

        # Accent top stripe
        tk.Frame(card, bg=self.ACCENT_TEAL, height=3).pack(fill="x")

        tk.Label(card, text="🦑  Ready to Hunt?",
                 font=("Segoe UI", 18, "bold"),
                 bg="#141414", fg="#e8e8e8").pack(pady=(24, 6))
        tk.Label(card,
                 text="Start the SQL Injection scanner?",
                 font=("Segoe UI", 11),
                 bg="#141414", fg="#888888").pack()

        btn_row = tk.Frame(card, bg="#141414")
        btn_row.pack(pady=24)

        # YES
        yes_frame = tk.Frame(btn_row, bg=self.ACCENT_TEAL, cursor="hand2")
        yes_frame.grid(row=0, column=0, padx=12)
        yes_lbl = tk.Label(yes_frame, text="   YES — Enter   ",
                           font=("Segoe UI", 11, "bold"),
                           bg=self.ACCENT_TEAL, fg="#0d0d0d", pady=8)
        yes_lbl.pack()

        # NO
        no_frame = tk.Frame(btn_row, bg="#2a2a2a", cursor="hand2")
        no_frame.grid(row=0, column=1, padx=12)
        no_lbl = tk.Label(no_frame, text="   NO — Exit   ",
                          font=("Segoe UI", 11, "bold"),
                          bg="#2a2a2a", fg="#888888", pady=8)
        no_lbl.pack()

        def _yes(e=None):
            self.splash.destroy()
            self.on_proceed()

        def _no(e=None):
            self.splash.destroy()
            self.root.quit()

        def _yes_enter(e):
            yes_frame.configure(bg="#00b39d"); yes_lbl.configure(bg="#00b39d")
        def _yes_leave(e):
            yes_frame.configure(bg=self.ACCENT_TEAL); yes_lbl.configure(bg=self.ACCENT_TEAL)
        def _no_enter(e):
            no_frame.configure(bg="#3a3a3a"); no_lbl.configure(bg="#3a3a3a")
        def _no_leave(e):
            no_frame.configure(bg="#2a2a2a"); no_lbl.configure(bg="#2a2a2a")

        for w in (yes_frame, yes_lbl):
            w.bind("<Button-1>", _yes)
            w.bind("<Enter>", _yes_enter)
            w.bind("<Leave>", _yes_leave)
        for w in (no_frame, no_lbl):
            w.bind("<Button-1>", _no)
            w.bind("<Enter>", _no_enter)
            w.bind("<Leave>", _no_leave)


# ─────────────────────────────────────────────
#  Entry point
# ─────────────────────────────────────────────
def main():
    root = tk.Tk()
    app  = SQLiScannerApp(root)
    root.withdraw()

    def show_app():
        root.deiconify()
        root.lift()
        root.focus_force()

    SplashScreen(root, show_app)
    root.mainloop()


if __name__ == "__main__":
    main()
