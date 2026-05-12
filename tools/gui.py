"""
GUI Dashboard for Web Security Scanner
Built with Tkinter — dark theme, real-time progress, interactive results
"""

import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox, filedialog
import threading
import datetime
import webbrowser
import os
from scanner import WebScanner, Vulnerability, ScanResult
from report import ReportGenerator


class ScannerGUI:
    """Tkinter-based GUI dashboard for the Web Security Scanner."""

    # Color scheme — dark hacker theme
    COLORS = {
        "bg": "#0f0f1a",
        "bg2": "#1a1a2e",
        "fg": "#e0e0e0",
        "accent": "#00d4ff",
        "success": "#28a745",
        "danger": "#dc3545",
        "warning": "#fd7e14",
        "info": "#17a2b8",
        "border": "#2a2a4a",
        "hover": "#16213e",
        "text_muted": "#8892b0",
    }

    def __init__(self):
        self.root = tk.Tk()
        self.root.title("Web Security Scanner — Pentest Tool v1.0")
        self.root.geometry("1100x750")
        self.root.configure(bg=self.COLORS["bg"])
        self.root.minsize(900, 600)

        # Set icon if available (optional)
        try:
            self.root.iconbitmap(default="")
        except:
            pass

        self.scanner = None
        self.scan_result = None
        self.scan_thread = None
        self.is_scanning = False

        self._build_ui()

    def _build_ui(self):
        """Build the complete GUI layout."""
        # Style configuration
        style = ttk.Style()
        style.theme_use("clam")

        # Configure custom styles
        style.configure("TFrame", background=self.COLORS["bg"])
        style.configure("Header.TLabel", foreground=self.COLORS["accent"],
                       background=self.COLORS["bg"], font=("Segoe UI", 16, "bold"))
        style.configure("Subheader.TLabel", foreground=self.COLORS["text_muted"],
                       background=self.COLORS["bg"], font=("Segoe UI", 10))
        style.configure("Status.TLabel", foreground=self.COLORS["fg"],
                       background=self.COLORS["bg"], font=("Segoe UI", 10))
        style.configure("Value.TLabel", foreground=self.COLORS["accent"],
                       background=self.COLORS["bg2"], font=("Segoe UI", 18, "bold"))

        # ─── HEADER ────────────────────────────────────────────
        header_frame = tk.Frame(self.root, bg=self.COLORS["bg2"],
                               highlightbackground=self.COLORS["border"],
                               highlightthickness=1)
        header_frame.pack(fill=tk.X, padx=15, pady=(15, 5))

        tk.Label(header_frame, text="🔍  Web Security Scanner",
                fg=self.COLORS["accent"], bg=self.COLORS["bg2"],
                font=("Segoe UI", 18, "bold")).pack(side=tk.LEFT, padx=20, pady=15)

        tk.Label(header_frame, text="SQLi · XSS · CSRF · Crawler · Reports",
                fg=self.COLORS["text_muted"], bg=self.COLORS["bg2"],
                font=("Segoe UI", 10)).pack(side=tk.LEFT, padx=5, pady=15)

        # Status indicator
        self.status_indicator = tk.Canvas(header_frame, width=16, height=16,
                                         bg=self.COLORS["bg2"], highlightthickness=0)
        self.status_indicator.pack(side=tk.RIGHT, padx=(5, 15), pady=15)
        self._set_status_indicator("idle")

        self.status_label = tk.Label(header_frame, text="Ready",
                                    fg=self.COLORS["text_muted"], bg=self.COLORS["bg2"],
                                    font=("Segoe UI", 10))
        self.status_label.pack(side=tk.RIGHT, pady=15)

        # ─── MAIN CONTENT ──────────────────────────────────────
        main_frame = tk.Frame(self.root, bg=self.COLORS["bg"])
        main_frame.pack(fill=tk.BOTH, expand=True, padx=15, pady=10)

        # Left panel — controls
        left_panel = tk.Frame(main_frame, bg=self.COLORS["bg2"],
                             highlightbackground=self.COLORS["border"],
                             highlightthickness=1, width=320)
        left_panel.pack(side=tk.LEFT, fill=tk.Y, padx=(0, 10))
        left_panel.pack_propagate(False)

        # Right panel — results
        right_panel = tk.Frame(main_frame, bg=self.COLORS["bg2"],
                              highlightbackground=self.COLORS["border"],
                              highlightthickness=1)
        right_panel.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True)

        # ─── LEFT PANEL — CONTROLS ────────────────────────────
        pad_opts = {"padx": 15, "pady": (15, 5)}

        tk.Label(left_panel, text="Target Configuration",
                fg=self.COLORS["accent"], bg=self.COLORS["bg2"],
                font=("Segoe UI", 12, "bold")).pack(**pad_opts, anchor=tk.W)

        tk.Label(left_panel, text="Target URL:",
                fg=self.COLORS["fg"], bg=self.COLORS["bg2"],
                font=("Segoe UI", 9)).pack(padx=15, anchor=tk.W)

        self.url_entry = tk.Entry(left_panel, bg="#16213e", fg=self.COLORS["fg"],
                                 insertbackground=self.COLORS["accent"],
                                 relief=tk.FLAT, font=("Consolas", 11),
                                 highlightbackground=self.COLORS["border"],
                                 highlightthickness=1)
        self.url_entry.pack(padx=15, pady=(0, 10), fill=tk.X, ipady=5)
        self.url_entry.insert(0, "https://example.com")

        # Scan depth
        depth_frame = tk.Frame(left_panel, bg=self.COLORS["bg2"])
        depth_frame.pack(padx=15, pady=5, fill=tk.X)

        tk.Label(depth_frame, text="Crawl Depth:",
                fg=self.COLORS["fg"], bg=self.COLORS["bg2"],
                font=("Segoe UI", 9)).pack(side=tk.LEFT)

        self.depth_var = tk.IntVar(value=2)
        depth_spin = tk.Spinbox(depth_frame, from_=1, to=5, textvariable=self.depth_var,
                               width=5, bg="#16213e", fg=self.COLORS["fg"],
                               buttonbackground=self.COLORS["bg2"],
                               relief=tk.FLAT, highlightbackground=self.COLORS["border"],
                               font=("Segoe UI", 10))
        depth_spin.pack(side=tk.RIGHT)

        # Threads
        thread_frame = tk.Frame(left_panel, bg=self.COLORS["bg2"])
        thread_frame.pack(padx=15, pady=5, fill=tk.X)

        tk.Label(thread_frame, text="Threads:",
                fg=self.COLORS["fg"], bg=self.COLORS["bg2"],
                font=("Segoe UI", 9)).pack(side=tk.LEFT)

        self.threads_var = tk.IntVar(value=5)
        thread_spin = tk.Spinbox(thread_frame, from_=1, to=20, textvariable=self.threads_var,
                                width=5, bg="#16213e", fg=self.COLORS["fg"],
                                buttonbackground=self.COLORS["bg2"],
                                relief=tk.FLAT, highlightbackground=self.COLORS["border"],
                                font=("Segoe UI", 10))
        thread_spin.pack(side=tk.RIGHT)

        # Separator
        ttk.Separator(left_panel, orient=tk.HORIZONTAL).pack(fill=tk.X, padx=15, pady=10)

        # Scan options
        tk.Label(left_panel, text="Scan Modules",
                fg=self.COLORS["accent"], bg=self.COLORS["bg2"],
                font=("Segoe UI", 12, "bold")).pack(padx=15, pady=(0, 5), anchor=tk.W)

        self.sqli_var = tk.BooleanVar(value=True)
        self.xss_var = tk.BooleanVar(value=True)
        self.csrf_var = tk.BooleanVar(value=True)

        for var, text, color in [
            (self.sqli_var, "SQL Injection Detection", self.COLORS["danger"]),
            (self.xss_var, "XSS Detection", self.COLORS["warning"]),
            (self.csrf_var, "CSRF Testing", self.COLORS["info"]),
        ]:
            cb = tk.Checkbutton(left_panel, text=text, variable=var,
                              bg=self.COLORS["bg2"], fg=color,
                              selectcolor=self.COLORS["bg2"],
                              activebackground=self.COLORS["bg2"],
                              activeforeground=color,
                              font=("Segoe UI", 10),
                              highlightthickness=0)
            cb.pack(padx=15, pady=2, anchor=tk.W)

        # Separator
        ttk.Separator(left_panel, orient=tk.HORIZONTAL).pack(fill=tk.X, padx=15, pady=10)

        # Action buttons
        self.scan_btn = tk.Button(left_panel, text="▶  START SCAN",
                                 command=self._start_scan,
                                 bg=self.COLORS["success"], fg="white",
                                 font=("Segoe UI", 12, "bold"),
                                 relief=tk.FLAT, cursor="hand2",
                                 activebackground="#218838",
                                 activeforeground="white")
        self.scan_btn.pack(padx=15, pady=(5, 5), fill=tk.X, ipady=8)

        self.stop_btn = tk.Button(left_panel, text="■  STOP",
                                 command=self._stop_scan,
                                 bg=self.COLORS["danger"], fg="white",
                                 font=("Segoe UI", 12, "bold"),
                                 relief=tk.FLAT, cursor="hand2",
                                 state=tk.DISABLED,
                                 activebackground="#c82333",
                                 activeforeground="white")
        self.stop_btn.pack(padx=15, pady=(0, 5), fill=tk.X, ipady=8)

        # Report buttons
        report_frame = tk.Frame(left_panel, bg=self.COLORS["bg2"])
        report_frame.pack(padx=15, pady=10, fill=tk.X)

        self.html_report_btn = tk.Button(report_frame, text="📄 HTML Report",
                                        command=self._save_html_report,
                                        bg=self.COLORS["bg2"], fg=self.COLORS["accent"],
                                        font=("Segoe UI", 10),
                                        relief=tk.FLAT, cursor="hand2",
                                        state=tk.DISABLED,
                                        highlightbackground=self.COLORS["border"],
                                        highlightthickness=1)
        self.html_report_btn.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 5), ipady=4)

        self.json_report_btn = tk.Button(report_frame, text="📊 JSON Export",
                                        command=self._save_json_report,
                                        bg=self.COLORS["bg2"], fg=self.COLORS["warning"],
                                        font=("Segoe UI", 10),
                                        relief=tk.FLAT, cursor="hand2",
                                        state=tk.DISABLED,
                                        highlightbackground=self.COLORS["border"],
                                        highlightthickness=1)
        self.json_report_btn.pack(side=tk.RIGHT, fill=tk.X, expand=True, ipady=4)

        # ─── RIGHT PANEL — RESULTS ─────────────────────────────
        # Notebook (tabs)
        self.notebook = ttk.Notebook(right_panel)
        self.notebook.pack(fill=tk.BOTH, expand=True, padx=2, pady=2)

        # Style the notebook
        style.configure("TNotebook", background=self.COLORS["bg"],
                       borderwidth=0)
        style.configure("TNotebook.Tab", background=self.COLORS["bg2"],
                       foreground=self.COLORS["fg"],
                       padding=[12, 4],
                       font=("Segoe UI", 9))
        style.map("TNotebook.Tab",
                 background=[("selected", self.COLORS["accent"])],
                 foreground=[("selected", "white")])

        # Tab 1: Log / Console Output
        self.log_tab = tk.Frame(self.notebook, bg=self.COLORS["bg"])
        self.notebook.add(self.log_tab, text="📟 Console")

        self.log_text = scrolledtext.ScrolledText(
            self.log_tab, bg="#0a0a14", fg="#00ff88",
            font=("Consolas", 10), insertbackground=self.COLORS["accent"],
            relief=tk.FLAT, highlightbackground=self.COLORS["border"],
            highlightthickness=1, state=tk.DISABLED,
            wrap=tk.WORD
        )
        self.log_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        # Tab 2: Vulnerabilities Table
        self.vuln_tab = tk.Frame(self.notebook, bg=self.COLORS["bg"])
        self.notebook.add(self.vuln_tab, text="⚠️ Vulnerabilities")

        # Treeview for vulnerabilities
        columns = ("type", "url", "param", "severity", "description")
        self.vuln_tree = ttk.Treeview(self.vuln_tab, columns=columns,
                                     show="headings", selectmode="browse")

        # Configure columns
        self.vuln_tree.heading("type", text="Type")
        self.vuln_tree.heading("url", text="URL")
        self.vuln_tree.heading("param", text="Parameter")
        self.vuln_tree.heading("severity", text="Severity")
        self.vuln_tree.heading("description", text="Description")

        self.vuln_tree.column("type", width=130)
        self.vuln_tree.column("url", width=250)
        self.vuln_tree.column("param", width=100)
        self.vuln_tree.column("severity", width=80)
        self.vuln_tree.column("description", width=250)

        # Style the tree
        style.configure("Treeview", background=self.COLORS["bg2"],
                       foreground=self.COLORS["fg"],
                       rowheight=28,
                       fieldbackground=self.COLORS["bg2"],
                       font=("Segoe UI", 9))
        style.configure("Treeview.Heading", background=self.COLORS["bg"],
                       foreground=self.COLORS["accent"],
                       font=("Segoe UI", 9, "bold"))
        style.map("Treeview", background=[("selected", self.COLORS["accent"])])

        # Scrollbar for tree
        tree_scroll = ttk.Scrollbar(self.vuln_tab, orient=tk.VERTICAL,
                                    command=self.vuln_tree.yview)
        self.vuln_tree.configure(yscrollcommand=tree_scroll.set)

        self.vuln_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(5, 0), pady=5)
        tree_scroll.pack(side=tk.RIGHT, fill=tk.Y, padx=(0, 5), pady=5)

        # Tab 3: Stats Dashboard
        self.stats_tab = tk.Frame(self.notebook, bg=self.COLORS["bg"])
        self.notebook.add(self.stats_tab, text="📊 Dashboard")

        self._build_stats_tab()

        # Bind close event
        self.root.protocol("WM_DELETE_WINDOW", self._on_closing)

    def _build_stats_tab(self):
        """Build the statistics dashboard tab."""
        frame = tk.Frame(self.stats_tab, bg=self.COLORS["bg"])
        frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=20)

        # Stats grid
        stats_frame = tk.Frame(frame, bg=self.COLORS["bg"])
        stats_frame.pack(fill=tk.X, pady=(0, 20))

        self.stats_widgets = {}
        stats = [
            ("urls", "URLs Crawled", "0"),
            ("forms", "Forms Found", "0"),
            ("critical", "Critical", "0", self.COLORS["danger"]),
            ("high", "High", "0", self.COLORS["warning"]),
            ("medium", "Medium", "0", self.COLORS["info"]),
            ("low", "Low", "0", self.COLORS["success"]),
            ("duration", "Duration", "—"),
            ("status", "Status", "Idle", self.COLORS["text_muted"]),
        ]

        row, col = 0, 0
        for key, label, default, *color in stats:
            card = tk.Frame(stats_frame, bg=self.COLORS["bg2"],
                          highlightbackground=self.COLORS["border"],
                          highlightthickness=1, width=150, height=100)
            card.grid(row=row, column=col, padx=5, pady=5)
            card.pack_propagate(False)

            lbl_color = color[0] if color else self.COLORS["accent"]

            tk.Label(card, text=label, fg=self.COLORS["text_muted"],
                    bg=self.COLORS["bg2"], font=("Segoe UI", 9)).pack(pady=(10, 0))

            value_label = tk.Label(card, text=default, fg=lbl_color,
                                  bg=self.COLORS["bg2"],
                                  font=("Segoe UI", 20, "bold"))
            value_label.pack(pady=(0, 10))

            self.stats_widgets[key] = value_label

            col += 1
            if col >= 4:
                col = 0
                row += 1

        # Label showing selected vulnerability details
        tk.Label(frame, text="Select a vulnerability in the 'Vulnerabilities' tab for details",
                fg=self.COLORS["text_muted"], bg=self.COLORS["bg"],
                font=("Segoe UI", 10, "italic")).pack(pady=10)

    def _set_status_indicator(self, status: str):
        """Update the status LED indicator."""
        colors = {
            "idle": ("#8892b0", "#2a2a4a"),
            "scanning": ("#00ff88", "#003d1a"),
            "complete": ("#00d4ff", "#003d4d"),
            "error": ("#dc3545", "#4a0d15"),
        }
        fg, bg = colors.get(status, colors["idle"])
        self.status_indicator.delete("all")
        self.status_indicator.create_oval(2, 2, 14, 14, fill=fg, outline=bg, width=2)

    def _log(self, message: str, color: str = "#00ff88"):
        """Append a message to the console log."""
        self.log_text.configure(state=tk.NORMAL)
        timestamp = datetime.datetime.now().strftime("%H:%M:%S")
        self.log_text.insert(tk.END, f"[{timestamp}] ", "#888888")
        self.log_text.insert(tk.END, f"{message}\n", color)
        self.log_text.see(tk.END)
        self.log_text.configure(state=tk.DISABLED)

        # Configure tags for colors
        self.log_text.tag_configure("#888888", foreground="#888888")
        self.log_text.tag_configure("#00ff88", foreground="#00ff88")
        self.log_text.tag_configure("#ff4444", foreground="#ff4444")
        self.log_text.tag_configure("#ffaa00", foreground="#ffaa00")
        self.log_text.tag_configure("#00d4ff", foreground="#00d4ff")

    def _log_colored(self, message: str, tag: str = "#00ff88"):
        """Log with a specific color tag."""
        self.log_text.configure(state=tk.NORMAL)
        timestamp = datetime.datetime.now().strftime("%H:%M:%S")
        self.log_text.insert(tk.END, f"[{timestamp}] ", "#888888")
        self.log_text.insert(tk.END, f"{message}\n", tag)
        self.log_text.see(tk.END)
        self.log_text.configure(state=tk.DISABLED)

    def _start_scan(self):
        """Start the scan in a background thread."""
        if self.is_scanning:
            return

        url = self.url_entry.get().strip()
        if not url or url == "https://example.com":
            messagebox.showwarning("Invalid URL", "Please enter a valid target URL.")
            return

        if not url.startswith(("http://", "https://")):
            url = "https://" + url
            self.url_entry.delete(0, tk.END)
            self.url_entry.insert(0, url)

        # Clear previous results
        for item in self.vuln_tree.get_children():
            self.vuln_tree.delete(item)

        self._update_scanning_state(True)
        self._set_status_indicator("scanning")
        self.status_label.configure(text="Scanning...", fg="#00ff88")

        self._log("=" * 60, "#00d4ff")
        self._log(f"🚀 Starting scan on: {url}", "#00d4ff")
        self._log(f"   Depth: {self.depth_var.get()} | Threads: {self.threads_var.get()}", "#00d4ff")
        modules = []
        if self.sqli_var.get(): modules.append("SQLi")
        if self.xss_var.get(): modules.append("XSS")
        if self.csrf_var.get(): modules.append("CSRF")
        self._log(f"   Modules: {', '.join(modules)}", "#00d4ff")
        self._log("=" * 60, "#00d4ff")

        # Run scan in background thread
        self.scan_thread = threading.Thread(target=self._run_scan, args=(url,), daemon=True)
        self.scan_thread.start()

    def _run_scan(self, url: str):
        """Run the actual scan (called from background thread)."""
        try:
            self.scanner = WebScanner(
                target_url=url,
                max_depth=self.depth_var.get(),
                threads=self.threads_var.get(),
            )

            # Override print to capture output in GUI log
            import builtins
            original_print = builtins.print

            def gui_print(*args, **kwargs):
                msg = " ".join(str(a) for a in args)
                # Color code based on content
                if "[!]" in msg or "FOUND" in msg:
                    tag = "#ff4444"
                elif "[+]" in msg or "[*]" in msg:
                    tag = "#00d4ff"
                elif "[✓]" in msg:
                    tag = "#00ff88"
                else:
                    tag = "#00ff88"

                self.root.after(0, self._log_colored, msg, tag)

            builtins.print = gui_print

            # Add print override for colorama too
            self.scan_result = self.scanner.scan()

            # Restore print
            builtins.print = original_print

            # Update GUI with results
            self.root.after(0, self._display_results)

        except Exception as e:
            self.root.after(0, self._log, f"❌ Scan error: {str(e)}", "#ff4444")
            self.root.after(0, self._update_scanning_state, False)
            self.root.after(0, self._set_status_indicator, "error")
            self.root.after(0, self.status_label.configure,
                          {"text": "Error", "fg": self.COLORS["danger"]})

    def _stop_scan(self):
        """Stop the current scan."""
        if self.is_scanning and self.scanner:
            self._log("⚠️ Scan stopped by user", "#ffaa00")
            self._update_scanning_state(False)
            self._set_status_indicator("idle")
            self.status_label.configure(text="Stopped", fg=self.COLORS["warning"])

    def _display_results(self):
        """Display scan results in the GUI."""
        result = self.scan_result
        if not result:
            return

        self._update_scanning_state(False)
        self._set_status_indicator("complete")
        self.status_label.configure(text="Complete ✓", fg=self.COLORS["success"])

        # Update stats dashboard
        self.stats_widgets["urls"].configure(text=str(result.total_urls_scanned))
        self.stats_widgets["forms"].configure(text=str(result.total_forms_found))
        self.stats_widgets["duration"].configure(text=f"{result.scan_duration_seconds:.2f}s")
        self.stats_widgets["status"].configure(text="Complete ✓", fg=self.COLORS["success"])

        # Count by severity
        critical = sum(1 for v in result.vulnerabilities if v.severity == "Critical")
        high = sum(1 for v in result.vulnerabilities if v.severity == "High")
        medium = sum(1 for v in result.vulnerabilities if v.severity == "Medium")
        low = sum(1 for v in result.vulnerabilities if v.severity == "Low")

        self.stats_widgets["critical"].configure(text=str(critical))
        self.stats_widgets["high"].configure(text=str(high))
        self.stats_widgets["medium"].configure(text=str(medium))
        self.stats_widgets["low"].configure(text=str(low))

        # Populate vulnerabilities table
        for v in result.vulnerabilities:
            self.vuln_tree.insert("", tk.END, values=(
                v.type, v.url, v.parameter, v.severity, v.description[:100]
            ))

        # Enable report buttons
        self.html_report_btn.configure(state=tk.NORMAL)
        self.json_report_btn.configure(state=tk.NORMAL)

        # Switch to vulnerabilities tab if findings exist
        if result.vulnerabilities:
            self.notebook.select(1)  # Vulnerabilities tab
            self._log(f"\n⚠️ Found {len(result.vulnerabilities)} vulnerabilities!", "#ffaa00")
        else:
            self._log("\n✅ No vulnerabilities detected. Clean scan!", "#00ff88")

        self._log(f"📄 Reports: HTML | JSON export available", "#00d4ff")

    def _update_scanning_state(self, scanning: bool):
        """Toggle UI between scanning and idle states."""
        self.is_scanning = scanning

        if scanning:
            self.scan_btn.configure(state=tk.DISABLED, text="⏳ Scanning...")
            self.stop_btn.configure(state=tk.NORMAL)
            self.url_entry.configure(state=tk.DISABLED)
        else:
            self.scan_btn.configure(state=tk.NORMAL, text="▶  START SCAN")
            self.stop_btn.configure(state=tk.DISABLED)
            self.url_entry.configure(state=tk.NORMAL)

    def _save_html_report(self):
        """Save scan results as HTML report."""
        if not self.scan_result:
            return

        file_path = filedialog.asksaveasfilename(
            defaultextension=".html",
            filetypes=[("HTML files", "*.html"), ("All files", "*.*")],
            initialdir=os.path.expanduser("~/Desktop"),
        )

        if file_path:
            ReportGenerator.save_report(self.scan_result, file_path)
            self._log(f"📄 HTML report saved: {file_path}", "#00d4ff")

            # Ask if user wants to open
            if messagebox.askyesno("Open Report", "Open the report in your browser?"):
                webbrowser.open(f"file://{os.path.abspath(file_path)}")

    def _save_json_report(self):
        """Save scan results as JSON."""
        if not self.scan_result:
            return

        file_path = filedialog.asksaveasfilename(
            defaultextension=".json",
            filetypes=[("JSON files", "*.json"), ("All files", "*.*")],
            initialdir=os.path.expanduser("~/Desktop"),
        )

        if file_path:
            ReportGenerator.save_json(self.scan_result, file_path)
            self._log(f"📊 JSON report saved: {file_path}", "#00d4ff")

    def _on_closing(self):
        """Handle window close event."""
        if self.is_scanning:
            if not messagebox.askokcancel("Quit", "A scan is in progress. Quit anyway?"):
                return
        self.root.destroy()

    def run(self):
        """Start the GUI application."""
        self._log("🔍 Web Security Scanner v1.0", "#00d4ff")
        self._log("   SQL Injection | XSS | CSRF Detection", "#00d4ff")
        self._log("   Enter a target URL and click START SCAN", "#00d4ff")
        self._log("-" * 50, "#888888")

        self.root.mainloop()
