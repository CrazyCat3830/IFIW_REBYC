"""
קובץ זה אחראי על ממשק המשתמש הראשי של המערכת.

ה-Dashboard מציג בזמן אמת נתונים מתוך מסד הנתונים וה-Orchestrator:
- סטטוס הרצת הניטור
- מדדי תעבורה כלליים
- התראות אחרונות מ-SQLite ומ-Firebase
- חבילות רשת אחרונות
- התפלגות פרוטוקולים
- כתובות מקור פעילות
- גרף packets per second
- הודעות מערכת חיות
- ייצוא ראיות Forensics עבור התראות

הקובץ משתמש ב-Tkinter לבניית הממשק וב-Matplotlib להצגת גרף התעבורה.
"""
from __future__ import annotations

import os
import sys
import subprocess
import re
import tkinter as tk
from tkinter import END, BOTH, LEFT, RIGHT, Y, X, TOP, messagebox

from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
from matplotlib.figure import Figure

from firebase_alerts import load_alerts

SCREEN_WIDTH = 1000
SCREEN_HEIGHT = 650

REFRESH_ALERTS_MS = 5000
REFRESH_MESSAGES_MS = 500
REFRESH_METRICS_MS = 1000
HISTORY_SECONDS = 60
USER_EMAIL = "operator@local"


CARD_BG = "#f8f8f8"
PANEL_BG = "#ffffff"
BORDER = "#cfcfcf"
TEXT = "#1f1f1f"
SUBTEXT = "#555555"
WINDOW_BG = "#efefef"


class MetricCard(tk.Frame):
    """
    Small reusable UI component that displays one dashboard metric.
    Each card contains a title label and a large value label.
    """
    def __init__(self, master, title: str):
        """
        Creates a metric card with a fixed title and an initial value of zero.
        """
        super().__init__(master, bg=CARD_BG, bd=1, relief="solid", highlightthickness=0)
        self.title_lbl = tk.Label(self, text=title, bg=CARD_BG, fg=SUBTEXT, anchor="w", font=("Segoe UI", 10))
        self.title_lbl.pack(anchor="w", padx=12, pady=(6, 1))
        self.value_lbl = tk.Label(self, text="0", bg=CARD_BG, fg=TEXT, anchor="w", font=("Segoe UI", 16, "bold"))
        self.value_lbl.pack(anchor="w", padx=12, pady=(0, 6))

    def set(self, value: str):
        """
        Updates the displayed metric value.
        """
        self.value_lbl.config(text=value)


class DashboardWindow:
    def __init__(self, orch):
        """
        Initializes the main dashboard window.
        The dashboard receives an Orchestrator object, uses its database
        connection, builds the Tkinter UI, and starts the first refresh cycle.
        """
        self.orch = orch
        self.db = orch.db
        self.root = tk.Tk()
        self.root.title("IFIW REBYC Dashboard")
        self.root.geometry("1200x700")
        self.root.configure(bg=WINDOW_BG)
        self.root.minsize(SCREEN_WIDTH, SCREEN_HEIGHT)
        # Stores the alert selected by the operator, so refresh does not lose context.
        self.selected_alert_id: int | None = None
        # Used to avoid showing the same alert twice when it exists in both DB and Firebase.
        self.db_alert_ids = []

        self._build_ui()
        self._refresh_all_initial()

    # ---------------- UI ----------------
    def _build_ui(self):
        """
        Builds all main UI sections: header, metric cards and dashboard grid.
        """
        self._build_header()
        self._build_metric_row()
        self._build_main_grid()

    def _build_header(self):
        """
        Builds the top command bar with status, capture controls
        and evidence export buttons.
        """
        header = tk.Frame(self.root, bg=WINDOW_BG)
        header.pack(side=TOP, fill=X, padx=8, pady=(6, 4))

        self.status_var = tk.StringVar(value="Status: Idle")
        status_lbl = tk.Label(header, textvariable=self.status_var, bg=WINDOW_BG, fg=TEXT, font=("Segoe UI", 12, "bold"))
        status_lbl.pack(side=LEFT, padx=(0, 10))

        self.start_btn = tk.Button(header, text="Start", width=8, command=self._start_capture)
        self.start_btn.pack(side=LEFT, padx=2)

        self.stop_btn = tk.Button(header, text="Stop", width=8, command=self._stop_capture)
        self.stop_btn.pack(side=LEFT, padx=2)

        self.export_latest_btn = tk.Button(
            header,
            text="Export Evidence (Latest Alert)",
            command=self._export_latest_alert,
        )
        self.export_latest_btn.pack(side=LEFT, padx=(8, 2))

        self.export_selected_btn = tk.Button(
            header,
            text="Export Evidence (Selected Alert)",
            command=self._export_selected_alert,
        )
        self.export_selected_btn.pack(side=LEFT, padx=2)

        self.open_folder_btn = tk.Button(
            header,
            text="Open Evidence Folder",
            command=self._open_evidence_folder,
        )
        self.open_folder_btn.pack(side=LEFT, padx=2)

    def _build_metric_row(self):
        """
        Builds the row of summary metric cards shown at the top of the dashboard.
        """
        row = tk.Frame(self.root, bg=WINDOW_BG)
        row.pack(side=TOP, fill=X, padx=8, pady=(0, 6))

        self.cards = {}
        titles = [
            ("total_packets", "Total Packets"),
            ("total_alerts", "Total Alerts"),
            ("packets_60s", "Packets / 60s"),
            ("alerts_5m", "Alerts / 5m"),
            ("active_flows", "Active Flows"),
            ("avg_pps", "Avg PPS / 60s"),
            ("avg_bps", "Avg Bps / 60s"),
            ("unique_sources", "Unique Sources"),
        ]
        for idx, (key, title) in enumerate(titles):
            card = MetricCard(row, title)
            card.grid(row=0, column=idx, sticky="nsew", padx=(0 if idx == 0 else 6, 0), pady=0)
            # Makes all metric cards expand evenly across the row.
            row.grid_columnconfigure(idx, weight=1, uniform="metric")
            self.cards[key] = card

    def _panel(self, master, title: str, row: int, column: int, rowspan: int = 1, columnspan: int = 1):
        """
        Creates a titled dashboard panel and places it inside a grid.
        Returns:
            outer: the panel frame
            body: the inner frame where widgets should be added
        """
        outer = tk.Frame(master, bg=PANEL_BG, bd=1, relief="solid")
        outer.grid(row=row, column=column, rowspan=rowspan, columnspan=columnspan, sticky="nsew", padx=4, pady=4)
        title_lbl = tk.Label(outer, text=title, bg=PANEL_BG, fg=TEXT, anchor="w", font=("Segoe UI", 10, "bold"))
        title_lbl.pack(side=TOP, fill=X, padx=8, pady=(6, 4))
        body = tk.Frame(outer, bg=PANEL_BG)
        body.pack(side=TOP, fill=BOTH, expand=True, padx=6, pady=(0, 6))
        return outer, body

    def _build_main_grid(self):
        """
        Dashboard layout priorities:
        1. Recent Alerts
        2. Traffic visibility
        3. Forensics workflow
        4. Live operational messages
        The layout is optimized for 1366x768 laptop displays.
        """
        grid = tk.Frame(self.root, bg=WINDOW_BG)
        grid.pack(side=TOP, fill=BOTH, expand=True, padx=4, pady=(0, 6))

        for c, weight in enumerate((42, 28, 42)):
            # Controls relative width of dashboard columns.
            grid.grid_columnconfigure(c, weight=weight, uniform="main")

        for r, weight in enumerate((45, 18, 22)):
            grid.grid_rowconfigure(r, weight=weight)

        # Top row
        _, alerts_body = self._panel(grid, "Recent Alerts", 0, 0)
        self.alerts_list = self._make_listbox(alerts_body, font=("Consolas", 10))
        # Update forensics panel whenever user selects an alert.
        self.alerts_list.bind("<<ListboxSelect>>", self._on_alert_selected)
        # Double-click exports evidence for the selected alert.
        self.alerts_list.bind("<Double-Button-1>", lambda e: self._export_selected_alert())

        _, talkers_body = self._panel(grid, "Top Talkers (last 5 minutes)", 0, 1)
        self.talkers_list = self._make_listbox(talkers_body, font=("Consolas", 10))

        _, chart_body = self._panel(grid, "Packets per second (last 60 seconds)", 0, 2)
        self.fig_pps = Figure(figsize=(4.5, 2.2), dpi=100)
        self.ax_pps = self.fig_pps.add_subplot(111)
        self.ax_pps.tick_params(labelsize=8)
        self.canvas_pps = FigureCanvasTkAgg(self.fig_pps, master=chart_body)
        self.canvas_pps.get_tk_widget().pack(fill=BOTH, expand=True)

        # Middle row
        _, packets_body = self._panel(grid, "Recent Packets", 1, 0)
        self.packets_list = self._make_listbox(packets_body, font=("Consolas", 9))

        _, proto_body = self._panel(grid, "Protocols (last 5 minutes)", 1, 1)
        self.proto_text = tk.Text(proto_body, height=4, bg=PANEL_BG, relief="flat", font=("Consolas", 10), wrap="none")
        self.proto_text.pack(fill=BOTH, expand=True)
        self.proto_text.config(state="disabled")

        _, alert_types_body = self._panel(grid, "Alert Types (last 30 minutes)", 1, 2)
        self.alert_types_text = tk.Text(alert_types_body, height=4, bg=PANEL_BG, relief="flat", font=("Consolas", 10),
                                        wrap="none")
        self.alert_types_text.pack(fill=BOTH, expand=True)
        self.alert_types_text.config(state="disabled")

        # Bottom row
        _, forensic_body = self._panel(grid, "Forensics", 2, 0, columnspan=2)
        forensic_body.grid_columnconfigure(0, weight=3)
        forensic_body.grid_columnconfigure(1, weight=2)

        left = tk.Frame(forensic_body, bg=PANEL_BG)
        left.grid(row=0, column=0, sticky="nsew", padx=(0, 10))
        right = tk.Frame(forensic_body, bg=PANEL_BG)
        right.grid(row=0, column=1, sticky="nsew")

        self.forensics_details = tk.Text(left, height=5, bg=PANEL_BG, relief="flat", font=("Consolas", 9), wrap="word")
        self.forensics_details.pack(fill=BOTH, expand=True)
        self.forensics_details.config(state="disabled")

        tk.Label(right, text="Recent Evidence Exports", bg=PANEL_BG, fg=SUBTEXT, anchor="w",
                 font=("Segoe UI", 9, "bold")).pack(anchor="w")
        self.audit_list = self._make_listbox(right, font=("Consolas", 8), height=4)

        _, messages_body = self._panel(grid, "Live Messages", 2, 2)
        self.messages_list = self._make_listbox(messages_body, font=("Consolas", 9))

    def _make_listbox(self, master, font=("Segoe UI", 10), height=10):
        """
        Creates a scrollable Tkinter Listbox for displaying live dashboard rows.
        """
        frame = tk.Frame(master, bg=PANEL_BG)
        frame.pack(fill=BOTH, expand=True)
        scroll = tk.Scrollbar(frame)
        scroll.pack(side=RIGHT, fill=Y)
        # Connects the listbox and scrollbar in both directions.
        listbox = tk.Listbox(frame, yscrollcommand=scroll.set, bg="#ffffff", fg=TEXT, font=font, relief="flat", bd=0, height=height)
        listbox.pack(side=LEFT, fill=BOTH, expand=True)
        scroll.config(command=listbox.yview)
        return listbox

    # ---------------- actions ----------------
    def _start_capture(self):
        """
        Starts packet sniffing through the orchestrator and updates the status label.
        """
        self.orch.start_sniff(iface=None)
        self.status_var.set("Status: Running")

    def _stop_capture(self):
        """
        Stops packet sniffing through the orchestrator and updates the status label.
        """
        self.orch.stop_sniff()
        self.status_var.set("Status: Stopped")

    def _open_evidence_folder(self):
        """
        Opens the local folder where evidence files are stored.
        """
        folder = getattr(self.orch, "evidence_dir", None) or "evidence_bundles"
        os.makedirs(folder, exist_ok=True)
        path = os.path.abspath(folder)
        if sys.platform.startswith("win"):
            os.startfile(path)
        elif sys.platform.startswith("darwin"):
            subprocess.Popen(["open", path])
        else:
            subprocess.Popen(["xdg-open", path])

    def _parse_selected_alert_id(self) -> int | None:
        """
        Extracts the selected alert ID from the alerts list.

        Returns None when no alert is selected or the line format is invalid.
        """
        if self.selected_alert_id is not None:
            return self.selected_alert_id
        sel = self.alerts_list.curselection()
        if not sel:
            return None
        line = self.alerts_list.get(sel[0])
        m = re.search(r"#(\d+)", line)
        return int(m.group(1)) if m else None

    def _export_latest_alert(self):
        """
        Exports evidence for the most recent alert stored in the database.
        """
        alerts = self.db.get_recent_alerts(limit=1)
        if not alerts:
            messagebox.showinfo("Forensics", "No alerts available yet.")
            return
        self._export_alert(alert_id=alerts[0]["alert_id"])

    def _export_selected_alert(self):
        """
        Exports evidence for the alert currently selected by the operator.
        """
        alert_id = self._parse_selected_alert_id()
        if alert_id is None:
            messagebox.showinfo("Forensics", "Select an alert first.")
            return
        self._export_alert(alert_id)

    def _export_alert(self, alert_id: int):
        """
        Calls the orchestrator to export forensic evidence for a specific alert
        and updates the dashboard with the export result.
        """
        try:
            pcap_path, meta_path, sha = self.orch.export_forensics(user_email=USER_EMAIL, alert_id=alert_id)
        except Exception as e:
            messagebox.showerror("Forensics Export Failed", str(e))
            return

        self._set_forensics_text(
            f"Export complete for alert #{alert_id}\n"
            f"PCAP: {pcap_path}\n"
            f"Metadata: {meta_path}\n"
            f"SHA256: {sha}"
        )
        self._refresh_forensics_panel(alert_id)
        messagebox.showinfo("Evidence Exported", f"PCAP:\n{pcap_path}\n\nMETA:\n{meta_path}\n\nSHA256:\n{sha}")

    # ---------------- refresh ----------------
    def _refresh_all_initial(self):
        """
        Performs the first dashboard refresh when the window opens.
        """
        self._refresh_status()
        self._refresh_metrics()
        self._refresh_alerts()
        self._refresh_packets()
        self._refresh_protocols()
        self._refresh_talkers()
        self._refresh_alert_types()
        self._refresh_forensics_panel(self.selected_alert_id)
        self._refresh_messages()

    def _refresh_status(self):
        """
        Refreshes the running/stopped status according to orchestrator runtime data.
        """
        runtime = self.orch.get_runtime_stats() if hasattr(self.orch, "get_runtime_stats") else {}
        is_running = runtime.get("running", getattr(self.orch, "running", False))
        self.status_var.set("Status: Running" if is_running else "Status: Stopped")
        self.root.after(REFRESH_METRICS_MS, self._refresh_status)

    def _refresh_metrics(self):
        """
        Updates dashboard metric cards using the latest
        database snapshot and runtime statistics.
        Also refreshes the PPS chart.
        """
        snapshot = self.db.get_dashboard_snapshot()
        runtime = self.orch.get_runtime_stats() if hasattr(self.orch, "get_runtime_stats") else {"active_flows": len(getattr(self.orch, "flows", {}))}

        total_packets = int(snapshot.get("total_packets", 0) or 0)
        total_alerts = int(snapshot.get("total_alerts", 0) or 0)
        packets_60s = int(snapshot.get("packets_60s", 0) or 0)
        alerts_5m = int(snapshot.get("alerts_5m", 0) or 0)
        active_flows = int(runtime.get("active_flows", 0) or 0)
        bytes_60s = int(snapshot.get("bytes_60s", 0) or 0)
        avg_pps = packets_60s / 60.0
        avg_bps = bytes_60s / 60.0
        unique_sources = int(snapshot.get("unique_sources_60m", 0) or 0)

        self.cards["total_packets"].set(f"{total_packets}")
        self.cards["total_alerts"].set(f"{total_alerts}")
        self.cards["packets_60s"].set(f"{packets_60s}")
        self.cards["alerts_5m"].set(f"{alerts_5m}")
        self.cards["active_flows"].set(f"{active_flows}")
        self.cards["avg_pps"].set(f"{avg_pps:.2f}")
        self.cards["avg_bps"].set(self._format_bytes(avg_bps) + "B")
        self.cards["unique_sources"].set(f"{unique_sources}")

        self._refresh_pps_chart()
        # Tkinter after() schedules the next refresh without blocking the GUI.
        self.root.after(REFRESH_METRICS_MS, self._refresh_metrics)

    def _refresh_alerts(self):
        """
        Refreshes the Recent Alerts panel.
        Sources:
        - Local SQLite database
        - Firebase cloud alerts
        The current alert selection is preserved across
        refresh cycles to avoid interrupting the operator.
        """
        current_selection_id = self.selected_alert_id
        self.alerts_list.delete(0, END)
        self.db_alert_ids = []

        try:
            for alert in self.db.get_recent_alerts(limit=40):
                self.db_alert_ids.append(int(alert["alert_id"]))
                line = (
                    f"(DB) #{alert['alert_id']} | {alert['timestamp']} | {alert['alert_type']} "
                    f"| sev={alert['severity']} | {alert['description']}"
                )
                self.alerts_list.insert(END, line)
        except Exception as e:
            self.alerts_list.insert(END, f"[dashboard] DB error: {e}")

        try:
            cloud_alerts = load_alerts(self.orch.firebase_uid, self.orch.firebase_token)
            if isinstance(cloud_alerts, dict):
                items = list(cloud_alerts.items())
            elif isinstance(cloud_alerts, list):
                items = list(enumerate(cloud_alerts))
            else:
                items = []

            for alert_id, alert in items[:15]:
                if not isinstance(alert, dict):
                    continue
                try:
                    normalized_id = int(alert_id)
                except Exception:
                    normalized_id = None
                if normalized_id in self.db_alert_ids:
                    continue
                line = (
                    f"(Cloud) #{alert_id} | {alert.get('timestamp', '')} | {alert.get('type', '')} "
                    f"| sev={alert.get('severity', '')} | {alert.get('description', '')}"
                )
                self.alerts_list.insert(END, line)
        except Exception:
            pass

        if current_selection_id is not None:
            for i in range(self.alerts_list.size()):
                if f"#{current_selection_id}" in self.alerts_list.get(i):
                    self.alerts_list.selection_clear(0, END)
                    self.alerts_list.selection_set(i)
                    self.alerts_list.see(i)
                    break

        self.root.after(REFRESH_ALERTS_MS, self._refresh_alerts)

    def _refresh_packets(self):
        """
        Refreshes the Recent Packets panel using the latest packet records.
        """
        self.packets_list.delete(0, END)
        try:
            for row in self.db.get_recent_packets(limit=25):
                proto = (row.get("proto_name") or "other").upper()
                src = self._format_endpoint(row.get("src_ip"), row.get("src_port"))
                dst = self._format_endpoint(row.get("dst_ip"), row.get("dst_port"))
                line = f"#{row['packet_id']} | {row['ts']} | {proto} | {src} -> {dst} | {row.get('raw_len', 0)}B"
                self.packets_list.insert(END, line)
        except Exception as e:
            self.packets_list.insert(END, f"[dashboard] Packet query error: {e}")
        self.root.after(REFRESH_METRICS_MS, self._refresh_packets)

    def _refresh_protocols(self):
        """
        Refreshes the protocol distribution summary for the last five minutes.
        """
        proto_counts = self.db.get_protocol_counts(minutes=5)
        total = sum(proto_counts.values()) or 1
        lines = []
        for proto in ("udp", "tcp", "icmp", "other"):
            count = int(proto_counts.get(proto, 0))
            if count <= 0:
                continue
            bar = "█" * max(1, int((count / total) * 40))
            lines.append(f"{proto:<8} {bar} {count}")
        if not lines:
            lines = ["No packets in the last 5 minutes."]
        self._set_text_widget(self.proto_text, "\n\n".join(lines))
        self.root.after(REFRESH_METRICS_MS * 2, self._refresh_protocols)

    def _refresh_talkers(self):
        self.talkers_list.delete(0, END)
        try:
            rows = self.db.get_top_talkers(minutes=5, limit=10)
            for r in rows:
                line = f"{r['src_ip']} | {r['packet_count']} pkts | {self._format_bytes(r['byte_count'])}B"
                self.talkers_list.insert(END, line)
            if not rows:
                self.talkers_list.insert(END, "No source traffic in the last 5 minutes.")
        except Exception as e:
            self.talkers_list.insert(END, f"[dashboard] Talkers error: {e}")
        self.root.after(REFRESH_METRICS_MS * 2, self._refresh_talkers)

    def _refresh_alert_types(self):
        counts = self.db.get_alert_type_counts(minutes=30)
        lines = [f"{k} | {v}" for k, v in counts.items()]
        if not lines:
            lines = ["No alerts in the last 30 minutes."]
        self._set_text_widget(self.alert_types_text, "\n".join(lines))
        self.root.after(REFRESH_METRICS_MS * 2, self._refresh_alert_types)

    def _refresh_messages(self):
        """
        Consumes new runtime messages from the orchestrator and displays them.
        """
        try:
            msgs = self.orch.consume_messages()
            for m in msgs:
                line = f"{m.ts} | {m.level} | {m.title}"
                if m.alert_id is not None:
                    line += f" | alert#{m.alert_id}"
                if m.body:
                    line += f" | {m.body}"
                self.messages_list.insert(END, line)
            if self.messages_list.size() > 250:
                self.messages_list.delete(0, self.messages_list.size() - 250)
        except Exception as e:
            self.messages_list.insert(END, f"[dashboard] Message bus error: {e}")
        self.root.after(REFRESH_MESSAGES_MS, self._refresh_messages)

    def _refresh_pps_chart(self):
        """
        Refreshes the packets-per-second Matplotlib chart using the last 60 seconds.
        """
        rows = self.db.get_packets_per_second(seconds=60)
        counts = {r["bucket"]: int(r["count"]) for r in rows}
        labels = list(counts.keys())[-HISTORY_SECONDS:]
        values = [counts[k] for k in labels]

        self.ax_pps.clear()
        self.ax_pps.plot(values, linewidth=1.5)
        if values:
            positions = list(range(len(values)))
            step = max(1, len(labels) // 4)
            tick_positions = positions[::step]
            tick_labels = [labels[i] for i in tick_positions]
            self.ax_pps.set_xticks(tick_positions)
            self.ax_pps.set_xticklabels(tick_labels, rotation=0)
            self.ax_pps.set_ylim(bottom=0)
        self.ax_pps.grid(True, alpha=0.25)
        self.fig_pps.tight_layout()
        self.canvas_pps.draw_idle()

    def _refresh_forensics_panel(self, alert_id: int | None):
        """
        Shows forensic details for the selected alert and lists recent evidence exports.
        """
        selected_alert = self.db.get_alert_by_id(alert_id) if alert_id else None
        if selected_alert:
            lines = [
                f"Selected alert: #{selected_alert['alert_id']}",
                f"Type: {selected_alert['alert_type']} | Severity: {selected_alert['severity']}",
                f"Timestamp: {selected_alert['timestamp']}",
                f"Packet ID: {selected_alert.get('packet_id')}",
                f"Current PCAP path: {selected_alert.get('pcap_path') or 'Not exported yet'}",
                "",
                "Tip: double-click the alert or use 'Export Evidence (Selected Alert)'.",
            ]
            self._set_forensics_text("\n".join(lines))
        else:
            self._set_forensics_text("Select an alert to view forensics details and export evidence.")

        self.audit_list.delete(0, END)
        try:
            for row in self.db.get_recent_forensics_audit(limit=10):
                line = f"#{row['audit_id']} | {row['created_at']} | {os.path.basename(row['artifact_path'] or '')}"
                self.audit_list.insert(END, line)
        except Exception as e:
            self.audit_list.insert(END, f"[dashboard] Audit error: {e}")

    def _on_alert_selected(self, _event=None):
        """
        Handles alert selection events from the Recent Alerts listbox.
        """
        alert_id = self._parse_selected_alert_id()
        self.selected_alert_id = alert_id
        self._refresh_forensics_panel(alert_id)

    # ---------------- helpers ----------------
    def _set_forensics_text(self, text: str):
        """
        Updates only the forensics details text area.
        """
        self._set_text_widget(self.forensics_details, text)

    @staticmethod
    def _set_text_widget(widget: tk.Text, text: str):
        """
        Safely replaces the content of a disabled Tkinter Text widget.
        """
        # Text widgets are disabled during normal use, so they must be enabled before editing.
        widget.config(state="normal")
        widget.delete("1.0", END)
        widget.insert("1.0", text)
        widget.config(state="disabled")

    @staticmethod
    def _format_endpoint(ip, port):
        """
        Formats an IP address and port as a display string.
        """
        if ip is None:
            ip = "?"
        if port is None:
            return str(ip)
        return f"{ip}:{port}"

    @staticmethod
    def _format_bytes(num: float | int) -> str:
        """
        Converts bytes into a human-readable string.
        """
        value = float(num or 0)
        units = ["", "K", "M", "G"]
        idx = 0
        while value >= 1024 and idx < len(units) - 1:
            value /= 1024.0
            idx += 1
        return f"{value:.1f} {units[idx]}" if idx else f"{int(value)} "

    def run(self):
        """
        Starts the Tkinter event loop.
        """
        self.root.mainloop()


def start_dashboard(orch, db_path: str = "DB.db"):
    """
    Entry point used by main.py to create and run the dashboard.
    """
    app = DashboardWindow(orch)
    app.run()
