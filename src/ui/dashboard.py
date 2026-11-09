"""Interactive dark-mode AegisAI-XDR dashboard."""

from __future__ import annotations

import csv
from datetime import datetime, timezone
import hashlib
import html
import platform
import queue
import threading
import time
from pathlib import Path
from typing import Any, Callable
import tkinter as tk
from tkinter import filedialog, messagebox, ttk

import customtkinter as ctk
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
from matplotlib.figure import Figure
from reportlab.lib import colors
from reportlab.lib.pagesizes import landscape, letter
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

from src.collectors.base_collector import create_platform_collector
from src.collectors.attack_simulator import generate_events
from src.collectors.network_connections_collector import NetworkConnectionsCollector
from src.collectors.windows_security_collector import WindowsSecurityEventCollector
from src.engine.threat_intel import ThreatIntel
from src.engine.evaluation import evaluate_predictions
from src.normalizer.parser import NormalizedEvent
from src.storage.baseline import BaselineStore
from src.storage.db_manager import DBManager
from src.storage.training_history import load_training_history, training_status


MITRE_MITIGATIONS = {
    "Initial Access": "Patch exposed applications; restrict public-facing services.",
    "Execution": "Constrain script interpreters; validate parent-child process lineage.",
    "Persistence": "Review new services, scheduled tasks, and startup entries.",
    "Privilege Escalation": "Apply least privilege and audit elevation events.",
    "Defense Evasion": "Protect security tooling and preserve audit logs.",
    "Credential Access": "Use MFA, credential isolation, and access monitoring.",
    "Discovery": "Review unusual system and account enumeration.",
    "Lateral Movement": "Segment networks and restrict remote administration.",
    "Collection": "Audit access to sensitive data stores.",
    "Command and Control": "Validate outbound destinations and apply egress controls.",
    "Exfiltration": "Monitor unusual outbound transfer volume.",
    "Impact": "Maintain tested backups and restrict destructive permissions.",
}

KILL_CHAIN = (
    "Reconnaissance → Execution → Persistence → Command & Control → Exfiltration"
)


class AegisDashboard:
    def __init__(
        self,
        root_dir: Path,
        settings_loader: Callable[[], dict[str, Any]],
        pipeline_runner: Callable[..., tuple[list[NormalizedEvent], list[dict[str, Any]]]],
    ) -> None:
        ctk.set_appearance_mode("dark")
        ctk.set_default_color_theme("dark-blue")
        self.root_dir = root_dir
        self.settings_loader = settings_loader
        self.pipeline_runner = pipeline_runner
        self.settings = settings_loader()
        self.intel = ThreatIntel(self.root_dir / "data" / "threat_intel.json")
        self.intel_counts = self.intel.counts()
        self.training_info = training_status(self.root_dir)
        self.root = ctk.CTk()
        self.root.title("AegisAI-XDR | Security Operations Center")
        self.root.geometry("1500x980")
        self.root.minsize(1180, 780)
        self.events: list[NormalizedEvent] = []
        self.alerts: list[dict[str, Any]] = []
        self.seen_ids: set[str] = set()
        self.event_by_id: dict[str, NormalizedEvent] = {}
        self.alert_by_event: dict[str, list[dict[str, Any]]] = {}
        self.queue: queue.Queue[tuple[str, Any]] = queue.Queue()
        self.scan_running = False
        self.auto_deadline = 0.0
        self.health_context: dict[str, Any] = {}
        self.health_canvas: tk.Canvas | None = None
        self.baseline_status = "Baseline not captured"
        self.playbook_log: list[str] = []
        self.status_text = tk.StringVar(value="Ready | Live collection is read-only")
        self.search_text = tk.StringVar()
        self.severity_filter = tk.StringVar(value="All")
        self._build_ui()
        self.root.after(100, self._drain_queue)

    def _build_ui(self) -> None:
        self.root.configure(fg_color="#0b1220")
        self.root.grid_columnconfigure(0, weight=1)
        self.root.grid_rowconfigure(2, weight=1)
        header = ctk.CTkFrame(self.root, fg_color="#111b2e", corner_radius=10)
        header.grid(row=0, column=0, sticky="ew", padx=14, pady=(14, 8))
        ctk.CTkLabel(
            header,
            text="AEGISAI  /  EXTENDED DETECTION & RESPONSE",
            font=ctk.CTkFont(size=21, weight="bold"),
            text_color="#e5edf8",
        ).pack(side="left", padx=18, pady=14)
        ctk.CTkLabel(
            header, text="LOCAL SOC  •  READ-ONLY COLLECTION", text_color="#92a7c7"
        ).pack(side="right", padx=18)

        controls = ctk.CTkFrame(self.root, fg_color="transparent")
        controls.grid(row=1, column=0, sticky="ew", padx=14, pady=(0, 8))
        self._button(controls, "LIVE  |  Scan this device", "#18864b", self.live_scan)
        self._button(controls, "SIMULATE  |  Attack scenarios", "#c77716", self.simulate)
        self._button(controls, "EVALUATE  |  Scientific test", "#2463b5", self.evaluate)
        self._button(controls, "AUTO SOC  |  60 sec", "#6046a5", self.start_auto)
        self._button(controls, "Update Threat Intel", "#34465f", self.update_intel)
        self._button(controls, "Export CSV", "#34465f", self.export_csv)
        self._button(controls, "Export PDF", "#34465f", self.export_pdf)
        self._button(controls, "Clear view", "#713c48", self.clear_view)

        body = ctk.CTkFrame(self.root, fg_color="transparent")
        body.grid(row=2, column=0, sticky="nsew", padx=14, pady=(0, 8))
        body.grid_columnconfigure(0, weight=1)
        body.grid_rowconfigure(2, weight=1)
        self.cards_frame = ctk.CTkFrame(body, fg_color="transparent")
        self.cards_frame.grid(row=0, column=0, sticky="ew", pady=(0, 8))
        self.card_values: dict[str, ctk.CTkLabel] = {}
        for column, (key, title) in enumerate(
            (
                ("events", "TOTAL EVENTS"),
                ("alerts", "REAL ALERTS"),
                ("benign", "BENIGN"),
                ("fpr", "FALSE POSITIVE RATE"),
                ("risk", "DEVICE RISK"),
                ("health", "DEVICE HEALTH"),
            )
        ):
            card = ctk.CTkFrame(self.cards_frame, fg_color="#111b2e", corner_radius=8)
            card.grid(row=0, column=column, padx=(0, 8), sticky="ew")
            self.cards_frame.grid_columnconfigure(column, weight=1)
            ctk.CTkLabel(card, text=title, text_color="#8da1bf").pack(
                anchor="w", padx=12, pady=(10, 0)
            )
            if key == "health":
                self.health_canvas = tk.Canvas(
                    card,
                    width=96,
                    height=88,
                    background="#111b2e",
                    highlightthickness=0,
                )
                self.health_canvas.pack(anchor="center", pady=(1, 0))
            value = ctk.CTkLabel(
                card, text="—", font=ctk.CTkFont(size=20, weight="bold")
            )
            value.pack(anchor="w", padx=12, pady=(0, 10))
            self.card_values[key] = value
        self.training_days_label = ctk.CTkLabel(
            self.cards_frame,
            text=f"Training Days: {self.training_info['days']} / 7",
            text_color="#a9c5e8",
        )
        self.training_days_label.grid(row=1, column=0, columnspan=2, sticky="w", pady=(5, 0))
        self.model_status_label = ctk.CTkLabel(
            self.cards_frame,
            text=f"Model Status: {self.training_info['status']}",
            text_color="#a9c5e8",
        )
        self.model_status_label.grid(row=1, column=2, columnspan=4, sticky="w", pady=(5, 0))
        self.intel_status_label = ctk.CTkLabel(
            self.cards_frame,
            text=self._intel_status_text(),
            text_color="#61d08d",
        )
        self.intel_status_label.grid(row=2, column=0, columnspan=6, sticky="w", pady=(2, 0))

        charts = ctk.CTkFrame(body, fg_color="#111b2e", corner_radius=8)
        charts.grid(row=1, column=0, sticky="ew", pady=(0, 8))
        self.figure = Figure(figsize=(10.5, 2.3), dpi=90, facecolor="#111b2e")
        self.severity_axis = self.figure.add_subplot(121)
        self.timeline_axis = self.figure.add_subplot(122)
        self.canvas = FigureCanvasTkAgg(self.figure, master=charts)
        self.canvas.get_tk_widget().pack(fill="both", expand=True, padx=8, pady=6)

        toolbar = ctk.CTkFrame(body, fg_color="transparent")
        toolbar.grid(row=2, column=0, sticky="nsew")
        toolbar.grid_columnconfigure(0, weight=3)
        toolbar.grid_columnconfigure(1, weight=2)
        toolbar.grid_rowconfigure(1, weight=1)
        filters = ctk.CTkFrame(toolbar, fg_color="transparent")
        filters.grid(row=0, column=0, columnspan=2, sticky="ew", pady=(0, 5))
        ctk.CTkLabel(filters, text="Search").pack(side="left", padx=(2, 6))
        search = ctk.CTkEntry(filters, textvariable=self.search_text, width=260)
        search.pack(side="left", padx=(0, 12))
        self.search_text.trace_add("write", lambda *_: self._render_table())
        ctk.CTkLabel(filters, text="Severity").pack(side="left", padx=(0, 6))
        severity = ctk.CTkComboBox(
            filters,
            values=["All", "Critical", "High", "Medium", "Low", "Benign"],
            variable=self.severity_filter,
            width=140,
        )
        severity.pack(side="left")
        self.severity_filter.trace_add("write", lambda *_: self._render_table())

        table_frame = ctk.CTkFrame(toolbar, fg_color="#111b2e", corner_radius=8)
        table_frame.grid(row=1, column=0, sticky="nsew", padx=(0, 8))
        table_frame.grid_rowconfigure(0, weight=1)
        table_frame.grid_columnconfigure(0, weight=1)
        style = ttk.Style()
        style.theme_use("clam")
        style.configure(
            "Aegis.Treeview",
            background="#101a2b",
            foreground="#d8e2f0",
            fieldbackground="#101a2b",
            borderwidth=0,
            rowheight=27,
        )
        style.configure(
            "Aegis.Treeview.Heading",
            background="#1c2b43",
            foreground="#c9d8ec",
            relief="flat",
        )
        style.map("Aegis.Treeview", background=[("selected", "#254f7d")])
        columns = (
            "timestamp",
            "severity",
            "host",
            "user",
            "process",
            "detection",
            "source",
            "port",
            "mitre",
            "anomaly",
            "count",
        )
        self.tree = ttk.Treeview(
            table_frame, columns=columns, show="headings", style="Aegis.Treeview"
        )
        for name, title, width in (
            ("timestamp", "TIME / UTC", 125),
            ("severity", "SEVERITY", 82),
            ("host", "HOST", 110),
            ("user", "USER", 80),
            ("process", "PROCESS", 115),
            ("detection", "DETECTION / EVENT", 190),
            ("source", "SOURCE IP", 115),
            ("port", "REMOTE PORT", 78),
            ("mitre", "MITRE TECHNIQUE", 185),
            ("anomaly", "ANOMALY", 72),
            ("count", "COUNT", 55),
        ):
            self.tree.heading(name, text=title)
            self.tree.column(name, width=width, minwidth=55, stretch=name in {"detection"})
        scroll = ttk.Scrollbar(table_frame, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=scroll.set)
        self.tree.grid(row=0, column=0, sticky="nsew")
        scroll.grid(row=0, column=1, sticky="ns")
        self.tree.bind("<<TreeviewSelect>>", self._show_details)

        detail = ctk.CTkFrame(toolbar, fg_color="#111b2e", corner_radius=8)
        detail.grid(row=1, column=1, sticky="nsew")
        detail.grid_rowconfigure(1, weight=1)
        detail.grid_columnconfigure(0, weight=1)
        ctk.CTkLabel(
            detail, text="MITRE ATT&CK  /  FORENSIC TIMELINE", text_color="#a9c5e8"
        ).grid(row=0, column=0, sticky="w", padx=12, pady=(10, 3))
        self.details = ctk.CTkTextbox(
            detail, fg_color="#0d1727", text_color="#d5dfed", wrap="word"
        )
        self.details.grid(row=1, column=0, sticky="nsew", padx=10, pady=4)
        self.details.insert(
            "1.0",
            "Select an event to inspect its evidence, tactic, mitigation, and timeline.",
        )
        self.details.configure(state="disabled")
        self.soar_button = ctk.CTkButton(
            detail,
            text="Simulate response (no action executed)",
            command=self.simulate_response,
            fg_color="#8b3844",
        )
        self.soar_button.grid(row=2, column=0, sticky="ew", padx=10, pady=(4, 10))

        footer = ctk.CTkFrame(self.root, fg_color="#111b2e", corner_radius=0)
        footer.grid(row=3, column=0, sticky="ew")
        ctk.CTkLabel(footer, textvariable=self.status_text, text_color="#a1b4cf").pack(
            side="left", padx=14, pady=7
        )
        self._update_dashboard()

    @staticmethod
    def _button(
        parent: ctk.CTkFrame, text: str, color: str, command: Callable[[], None]
    ) -> None:
        ctk.CTkButton(
            parent,
            text=text,
            command=command,
            fg_color=color,
            hover_color=color,
            height=36,
            font=ctk.CTkFont(size=12, weight="bold"),
        ).pack(side="left", padx=(0, 7))

    def _submit(self, label: str, action: Callable[[], Any]) -> None:
        if self.scan_running:
            self.status_text.set("A scan is already running.")
            return
        self.scan_running = True
        self.status_text.set(f"{label} in progress…")

        def worker() -> None:
            try:
                self.queue.put(("result", action()))
            except Exception as error:
                self.queue.put(("error", f"{type(error).__name__}: {error}"))
            finally:
                self.queue.put(("finished", label))

        threading.Thread(target=worker, daemon=True).start()

    def live_scan(self) -> None:
        self._submit("Live device scan", self._collect_live)

    def _collect_live(self) -> dict[str, Any]:
        collector = create_platform_collector()
        raw_events = collector.collect(250)
        collection_warnings = list(getattr(collector, "collection_warnings", []))
        if platform.system().lower() == "windows":
            security_ids = set(WindowsSecurityEventCollector.EVENT_IDS)
            raw_events = [
                event
                for event in raw_events
                if int(event.get("os_event_code") or 0) not in security_ids
            ]
            try:
                security_collector = WindowsSecurityEventCollector()
                raw_events.extend(security_collector.collect(250))
                collection_warnings.extend(security_collector.collection_warnings)
            except (OSError, RuntimeError, ValueError) as error:
                collection_warnings.append(f"Windows Security events collection failed: {error}")
        try:
            raw_events.extend(NetworkConnectionsCollector().collect(250))
        except (OSError, RuntimeError, ValueError) as error:
            collection_warnings.append(f"Network connections collection failed: {error}")
        snapshot: dict[str, Any] = {}
        if hasattr(collector, "collect_host_snapshot"):
            snapshot = collector.collect_host_snapshot()
        baseline = BaselineStore(self.root_dir / "data" / "baseline.json")
        previous = baseline.load()
        baseline_view = self._baseline_view(snapshot) if snapshot else {}
        if snapshot:
            prior_event_ids = set(previous.get("event_ids", [])) if previous else set()
            fresh_events: list[dict[str, Any]] = []
            now = datetime.now(timezone.utc)
            for event in raw_events:
                event_id = str(event.get("event_id") or "")
                if not event_id:
                    identity = "|".join(
                        str(event.get(field, ""))
                        for field in ("timestamp", "channel", "os_event_code", "raw_payload")
                    )
                    event_id = hashlib.sha256(identity.encode("utf-8")).hexdigest()
                    event["event_id"] = event_id
                if previous:
                    if event_id not in prior_event_ids:
                        fresh_events.append(event)
                else:
                    try:
                        timestamp = datetime.fromisoformat(
                            str(event.get("timestamp", "")).replace("Z", "+00:00")
                        )
                        if timestamp.tzinfo is None:
                            timestamp = timestamp.replace(tzinfo=timezone.utc)
                        if (now - timestamp.astimezone(timezone.utc)).total_seconds() <= 300:
                            fresh_events.append(event)
                    except ValueError:
                        continue
            all_event_ids = prior_event_ids | {
                str(event.get("event_id"))
                for event in raw_events
                if event.get("event_id")
            }
            baseline_view["event_ids"] = sorted(all_event_ids)[-1000:]
            event_times = [
                str(event.get("timestamp", ""))
                for event in raw_events
                if event.get("timestamp")
            ]
            baseline_view["event_watermark"] = max(event_times, default="")
            raw_events = fresh_events
        observed_users = {
            str(event.get("user", "")).strip()
            for event in raw_events
            if int(event.get("os_event_code") or 0) == 4624
            and event.get("user")
            and str(event["user"]).upper()
            not in {"SYSTEM", "LOCAL SERVICE", "NETWORK SERVICE", "ANONYMOUS LOGON"}
            and not str(event["user"]).endswith("$")
        }
        if snapshot:
            baseline_view["users"] = sorted(set(baseline_view["users"]) | observed_users)
            raw_events.extend(self._snapshot_events(snapshot, observed_users))
        differences = baseline.compare(baseline_view) if snapshot else {
            "processes": [], "services": [], "users": []
        }
        history = self._load_history()
        events, alerts = self.pipeline_runner(raw_events, self.settings, history)
        return {
            "mode": "live",
            "events": events,
            "alerts": alerts,
            "snapshot": snapshot,
            "differences": differences,
            "first_baseline": previous is None and bool(snapshot),
            "baseline_captured_at": (baseline.load() or {}).get("captured_at", ""),
            "warnings": collection_warnings,
        }

    @staticmethod
    def _baseline_view(snapshot: dict[str, Any]) -> dict[str, Any]:
        processes = snapshot.get("processes", [])
        return {
            "captured_at": snapshot.get("captured_at", ""),
            "host_name": snapshot.get("host_name", ""),
            "user": snapshot.get("user", ""),
            "service_scope": snapshot.get("service_scope", "running"),
            "processes": [
                f"{item.get('process_name', item.get('Name', ''))}|"
                f"{item.get('process_path', item.get('ExecutablePath', ''))}"
                for item in processes
                if isinstance(item, dict)
            ],
            "services": list(snapshot.get("services", [])),
            "users": list(snapshot.get("users", [])),
        }

    def _snapshot_events(
        self, snapshot: dict[str, Any], observed_users: set[str] | None = None
    ) -> list[dict[str, Any]]:
        baseline_store = BaselineStore(self.root_dir / "data" / "baseline.json")
        existing = baseline_store.load()
        prior_processes = set(existing.get("processes", [])) if existing else set()
        current = self._baseline_view(snapshot)
        current["users"] = sorted(set(current["users"]) | (observed_users or set()))
        new_processes = (
            set(current["processes"]) - prior_processes if existing is not None else set()
        )
        raw: list[dict[str, Any]] = []
        for item in snapshot.get("processes", []):
            if not isinstance(item, dict):
                continue
            process_key = (
                f"{item.get('process_name', '')}|{item.get('process_path', '')}"
            )
            if process_key not in new_processes:
                continue
            raw.append(
                {
                    "event_id": f"snapshot-process:{item.get('process_id', 0)}:{snapshot.get('captured_at')}",
                    "timestamp": snapshot.get("captured_at"),
                    "host_name": snapshot.get("host_name"),
                    "user": snapshot.get("user"),
                    "os_event_code": 4688,
                    "raw_payload": f"New Process Detected: {item.get('process_name', '')}",
                    **item,
                }
            )
        context_process = next(
            (
                item
                for item in snapshot.get("processes", [])
                if isinstance(item, dict)
                and str(item.get("process_name", "")).lower() == "powershell.exe"
            ),
            None,
        )
        if context_process:
            raw.append(
                {
                    "event_id": (
                        f"snapshot-context:{snapshot.get('host_name')}:"
                        f"{str(snapshot.get('captured_at', ''))[:10]}"
                    ),
                    "timestamp": snapshot.get("captured_at"),
                    "host_name": snapshot.get("host_name"),
                    "user": snapshot.get("user"),
                    "process_name": context_process.get("process_name"),
                    "process_path": context_process.get("process_path"),
                    "parent_process": context_process.get("parent_process"),
                    "parent_process_chain": context_process.get("parent_process_chain"),
                    "process_id": context_process.get("process_id"),
                    "parent_process_id": context_process.get("parent_process_id"),
                    "raw_payload": "Observed PowerShell process in current host snapshot",
                }
            )
        service_scope_changed = (
            existing is not None
            and existing.get("service_scope") != current.get("service_scope", "running")
        )
        if existing:
            if not service_scope_changed:
                new_services = set(current["services"]) - set(existing.get("services", []))
            else:
                new_services = set()
            for service in sorted(new_services):
                raw.append(
                    {
                        "timestamp": snapshot.get("captured_at"),
                        "event_id": f"snapshot-service:{service}:{snapshot.get('captured_at')}",
                        "host_name": snapshot.get("host_name"),
                        "user": snapshot.get("user"),
                        "os_event_code": 7045,
                        "raw_payload": f"New service installed: {service}",
                    }
                )
            for user in sorted(set(current["users"]) - set(existing.get("users", []))):
                raw.append(
                    {
                        "timestamp": snapshot.get("captured_at"),
                        "event_id": f"snapshot-user:{user}:{snapshot.get('captured_at')}",
                        "host_name": snapshot.get("host_name"),
                        "user": user,
                        "os_event_code": 4624,
                        "raw_payload": f"New User Login: {user}",
                    }
                )
        return raw

    def _load_history(self) -> list[dict[str, Any]]:
        database = DBManager(
            self.root_dir / self.settings.get("database_path", "aegis_soc.db")
        )
        try:
            return (
                database.recent_benign_events(days=7)
                + database.recent_process_observations(days=7)
                + load_training_history(self.root_dir)
            )
        finally:
            database.close()

    def _intel_status_text(self) -> str:
        return (
            "Threat Intel: Free Feeds Only - No API Key Required"
            f" | IPs: {self.intel_counts['ips']}, Domains: {self.intel_counts['domains']}"
        )

    def simulate(self) -> None:
        self._submit("Offline attack simulation", self._simulate)

    def _simulate(self) -> dict[str, Any]:
        raw = generate_events()
        for index, event in enumerate(raw):
            event["event_id"] = f"SIM-{index}-{event['timestamp']}"
        events, alerts = self.pipeline_runner(raw, self.settings, [])
        return {"mode": "simulate", "events": events, "alerts": alerts}

    def evaluate(self) -> None:
        self._submit("Scientific evaluation", self._evaluate)

    def _evaluate(self) -> dict[str, Any]:
        raw = generate_events()
        for index, event in enumerate(raw):
            event["event_id"] = f"EVAL-{index}-{event['timestamp']}"
        events, alerts = self.pipeline_runner(raw, self.settings, [])
        metrics = evaluate_predictions(events, alerts)
        return {
            "mode": "evaluate",
            "events": events,
            "alerts": alerts,
            "accuracy": metrics["accuracy"],
            "evaluation_count": metrics["count"],
        }

    def start_auto(self) -> None:
        if self.auto_deadline > time.monotonic():
            self.status_text.set("AUTO SOC is already active (5-second interval, 60-second limit).")
            return
        self.auto_deadline = time.monotonic() + 60
        self.status_text.set("AUTO SOC started: read-only scan every 5 seconds for 60 seconds.")
        self.live_scan()
        self.root.after(5000, self._auto_tick)

    def _auto_tick(self) -> None:
        if time.monotonic() >= self.auto_deadline:
            self.auto_deadline = 0.0
            self.status_text.set("AUTO SOC finished its 60-second monitoring window.")
            return
        if not self.scan_running:
            self.live_scan()
        self.root.after(5000, self._auto_tick)

    def update_intel(self) -> None:
        def update() -> dict[str, Any]:
            return self.intel.update_feeds()

        self._submit("Threat intelligence update", update)

    def _drain_queue(self) -> None:
        try:
            while True:
                kind, value = self.queue.get_nowait()
                if kind == "result":
                    if isinstance(value, dict) and "events" in value:
                        self._accept_results(value)
                    elif isinstance(value, dict) and "added" in value:
                        self.intel_counts = {
                            "ips": value["ips"],
                            "domains": value["domains"],
                        }
                        self.intel_status_label.configure(text=self._intel_status_text())
                        self.status_text.set(
                            f"Threat Intel updated: {value['added']} feed indicators. "
                            f"IPs: {value['ips']}, Domains: {value['domains']}."
                            + (f" Feed skipped: {', '.join(value['skipped'])}." if value.get("skipped") else "")
                        )
                elif kind == "error":
                    self.status_text.set(f"Operation failed: {value}")
                    messagebox.showerror("AegisAI-XDR", str(value), parent=self.root)
                elif kind == "finished":
                    self.scan_running = False
        except queue.Empty:
            pass
        self.root.after(100, self._drain_queue)

    def _accept_results(self, result: dict[str, Any]) -> None:
        new_events: list[NormalizedEvent] = []
        new_ids: set[str] = set()
        for event in result["events"]:
            if event.event_id in self.seen_ids:
                continue
            self.seen_ids.add(event.event_id)
            self.events.append(event)
            self.event_by_id[event.event_id] = event
            new_events.append(event)
            new_ids.add(event.event_id)
        for alert in result["alerts"]:
            if alert["event_id"] not in new_ids:
                continue
            self.alerts.append(alert)
            self.alert_by_event.setdefault(alert["event_id"], []).append(alert)
            for related_id in alert.get("related_event_ids", []):
                if related_id != alert["event_id"] and related_id in self.event_by_id:
                    self.alert_by_event.setdefault(related_id, []).append(alert)
        snapshot = result.get("snapshot", {})
        if snapshot:
            self.health_context = {
                **snapshot,
                **result.get("differences", {}),
                "failed_logins": sum(event.failed_logins for event in new_events),
            }
        if result.get("first_baseline"):
            self.baseline_status = "First-run baseline captured"
        elif result.get("baseline_captured_at"):
            self.baseline_status = (
                f"Baseline captured {result['baseline_captured_at'][:19]} UTC"
            )
        if result.get("mode") == "evaluate":
            result_status = (
                f"Evaluation: {result['accuracy']:.1%} accuracy "
                f"on {result['evaluation_count']} synthetic events."
            )
            self.status_text.set(result_status)
        elif result.get("mode") == "live":
            differences = result.get("differences", {})
            delta_count = sum(len(differences.get(key, [])) for key in ("processes", "services", "users"))
            snapshot_host = snapshot.get("host_name", "unknown host")
            snapshot_user = snapshot.get("user", "unknown user")
            self.status_text.set(
                f"LIVE | {snapshot_host} | {snapshot_user} | "
                f"{len(new_events)} new events, {delta_count} baseline changes | "
                f"{self.baseline_status}"
                + (
                    " | " + "; ".join(result["warnings"][:2])
                    if result.get("warnings")
                    else ""
                )
            )
        elif result.get("mode") == "simulate":
            self.status_text.set("SIMULATE | Offline synthetic events only; no attack executed.")
        self._persist(new_events, snapshot)
        self._render_table()
        self._update_dashboard()

    def _persist(
        self, events: list[NormalizedEvent], snapshot: dict[str, Any] | None = None
    ) -> None:
        if not events and not snapshot:
            return
        event_ids = {event.event_id for event in events}
        alerts = [alert for alert in self.alerts if alert["event_id"] in event_ids]
        database = DBManager(
            self.root_dir / self.settings.get("database_path", "aegis_soc.db")
        )
        try:
            for event in events:
                database.save_event(event)
            database.save_alerts(alerts)
            if snapshot:
                database.save_process_observations(
                    str(snapshot.get("captured_at") or datetime.now(timezone.utc).isoformat()),
                    snapshot.get("processes", []),
                )
            database.commit()
        finally:
            database.close()

    def _visible_records(self) -> list[tuple[NormalizedEvent, list[dict[str, Any]], int]]:
        grouped: dict[tuple[Any, ...], tuple[NormalizedEvent, list[dict[str, Any]], int]] = {}
        for event in self.events:
            alerts = self.alert_by_event.get(event.event_id, [])
            if not alerts:
                key = (
                    event.process_name,
                    event.raw_payload,
                    event.detection_type,
                    event.src_ip,
                    event.dst_port,
                    event.event_severity,
                )
                grouped[key] = (event, [], grouped.get(key, (event, [], 0))[2] + 1)
                continue
            for alert in alerts:
                key = (
                    alert["rule_id"],
                    event.process_name,
                    alert.get("src_ip", ""),
                    alert.get("severity", ""),
                )
                previous = grouped.get(key)
                grouped[key] = (
                    event,
                    [alert],
                    1 if previous is None else previous[2] + 1,
                )
        records = list(grouped.values())
        query = self.search_text.get().strip().lower()
        severity = self.severity_filter.get().strip().casefold()
        filtered: list[tuple[NormalizedEvent, list[dict[str, Any]], int]] = []
        for event, alerts, count in records:
            level = str(alerts[0]["severity"] if alerts else event.event_severity).casefold()
            searchable = " ".join(
                (
                    event.host_name,
                    event.user,
                    event.process_name,
                    event.detection_type,
                    event.mitre_technique,
                    event.raw_payload,
                    " ".join(alert["title"] for alert in alerts),
                    event.src_ip,
                    event.dst_ip,
                    str(event.dst_port),
                )
            ).lower()
            if severity not in {"all", level} or (query and query not in searchable):
                continue
            filtered.append((event, alerts, count))
        return sorted(filtered, key=lambda row: row[0].timestamp, reverse=True)

    def _render_table(self) -> None:
        self.tree.delete(*self.tree.get_children())
        for index, (event, alerts, count) in enumerate(self._visible_records()):
            alert = alerts[0] if alerts else {}
            severity = alert.get("severity", event.event_severity)
            detection = alert.get("title") or event.detection_type or "Observed event"
            timestamp = event.timestamp.replace("T", " ")[:19]
            row = (
                timestamp,
                severity,
                event.host_name,
                event.user,
                event.process_name or "—",
                detection,
                alert.get("src_ip") or event.src_ip or "—",
                event.dst_port or "—",
                event.mitre_technique or alert.get("mitre_id") or "—",
                str(event.anomaly_score),
                f"x{count}",
            )
            self.tree.insert("", "end", iid=str(index), values=row, tags=(severity,))
        self.tree.tag_configure("Critical", foreground="#ff7272")
        self.tree.tag_configure("High", foreground="#ffad6e")
        self.tree.tag_configure("Medium", foreground="#f2d579")
        self.tree.tag_configure("Low", foreground="#8bd6a7")
        self.tree.tag_configure("Benign", foreground="#a7b8d2")

    def _show_details(self, _event: tk.Event[Any] | None) -> None:
        if _event is not None and _event.widget is not self.tree:
            return
        selection = self.tree.selection()
        if not selection:
            return
        visible = self._visible_records()
        index = int(selection[0])
        if index >= len(visible):
            return
        event, alerts, count = visible[index]
        alert = alerts[0] if alerts else {}
        tactic = event.mitre_tactic or alert.get("mitre_tactic") or "—"
        technique = event.mitre_technique or alert.get("mitre_id") or "—"
        details = [
            f"FORENSIC TIMELINE  |  {event.timestamp}",
            f"{event.host_name}  •  {event.user or 'unknown user'}  •  {event.process_name or 'event'}",
            f"Parent: {event.parent_process or 'unknown'}",
            f"Parent lineage: {event.parent_process_chain or 'not available'}",
            f"Detection: {alert.get('title') or event.detection_type or 'Observed event'}  |  "
            f"Severity: {alert.get('severity', event.event_severity)}  |  Duplicates: x{count}",
            f"Source IP: {event.src_ip or '—'}  |  Remote IP: {event.dst_ip or '—'}  |  "
            f"Remote port: {event.dst_port or '—'}",
            f"Anomaly score: {event.anomaly_score}/100",
            f"MITRE ATT&CK: {technique}  |  {tactic}",
            f"Mitigation: {MITRE_MITIGATIONS.get(tactic, 'Investigate the event and validate its context.')}",
            f"Kill chain: {KILL_CHAIN}",
            f"Defender: {self._status_text(self.health_context.get('defender_enabled'))}  |  "
            f"Firewall: {self._status_text(self.health_context.get('firewall_enabled'))}",
            f"Last Windows update: {self.health_context.get('last_update') or 'Unknown'}",
            f"Baseline: {self.baseline_status}",
            f"Decoded payload: {event.decoded_payload or 'None'}",
            f"Evidence: {event.raw_payload[:1200]}",
        ]
        if self.playbook_log:
            details.extend(("", "SOAR AUDIT LOG", *self.playbook_log[-5:]))
        self.details.configure(state="normal")
        self.details.delete("1.0", "end")
        self.details.insert("1.0", "\n".join(details))
        self.details.configure(state="disabled")

    def simulate_response(self) -> None:
        selection = self.tree.selection()
        if not selection:
            messagebox.showinfo("SOAR simulation", "Select an event first.", parent=self.root)
            return
        event, alerts, _ = self._visible_records()[int(selection[0])]
        critical = next((alert for alert in alerts if alert["severity"] == "Critical"), None)
        if not critical:
            messagebox.showinfo(
                "SOAR simulation",
                "This playbook preview is available only for Critical alerts.",
                parent=self.root,
            )
            return
        entry = (
            f"Playbook Executed (SIMULATION ONLY) | {event.timestamp} | "
            f"{critical['title']} | would: Kill Process, Block IP, Isolate Host, Disable User"
        )
        self.playbook_log.append(entry)
        self._show_details(None)
        self.status_text.set("SOAR playbook preview logged; no host action was performed.")

    def _update_dashboard(self) -> None:
        total = len(self.events)
        alert_event_ids = {
            event_id
            for alert in self.alerts
            if alert.get("rule_id") != "Traffic_Spike_Warning"
            for event_id in [alert.get("event_id", ""), *alert.get("related_event_ids", [])]
        }
        incident_keys = {
            (alert.get("rule_id"), alert.get("title"), alert.get("src_ip"))
            for alert in self.alerts
            if alert.get("rule_id") != "Traffic_Spike_Warning"
        }
        real_alerts = len(incident_keys)
        benign = max(0, total - len(alert_event_ids))
        evaluation = evaluate_predictions(self.events, self.alerts)
        known_events = [event for event in self.events if event.true_label != "Unknown"]
        false_positives = sum(
            event.true_label == "Benign" and predicted
            for event, predicted in zip(known_events, evaluation["predicted"])
        )
        benign_truth = sum(event.true_label == "Benign" for event in known_events)
        fpr = f"{false_positives / benign_truth:.1%}" if benign_truth else "N/A"
        highest = max((alert["risk_score"] for alert in self.alerts), default=0)
        risk = "CRITICAL" if highest >= 85 else "WARNING" if highest >= 65 else "SAFE"
        health = self._health_score()
        for key, value in (
            ("events", str(total)),
            ("alerts", str(real_alerts)),
            ("benign", str(benign)),
            ("fpr", fpr),
            ("risk", risk),
            (
                "health",
                f"{health}/100 "
                f"{'SAFE' if health >= 80 else 'WARNING' if health >= 55 else 'CRITICAL'}",
            ),
        ):
            self.card_values[key].configure(text=value)
        self.card_values["risk"].configure(
            text_color={"SAFE": "#61d08d", "WARNING": "#f0bf59", "CRITICAL": "#ff6969"}[risk]
        )
        self.card_values["health"].configure(
            text_color="#61d08d" if health >= 80 else "#f0bf59" if health >= 55 else "#ff6969"
        )
        self._draw_health_circle(health)
        self._draw_charts()

    def _draw_health_circle(self, score: int) -> None:
        if self.health_canvas is None:
            return
        color = "#61d08d" if score >= 80 else "#f0bf59" if score >= 55 else "#ff6969"
        self.health_canvas.delete("all")
        self.health_canvas.create_oval(
            12, 6, 84, 78, outline="#293b55", width=8
        )
        self.health_canvas.create_arc(
            12,
            6,
            84,
            78,
            start=90,
            extent=-score * 3.6,
            style="arc",
            outline=color,
            width=8,
        )
        self.health_canvas.create_text(
            48, 42, text=str(score), fill="#e5edf8", font=("Segoe UI", 18, "bold")
        )

    def _health_score(self) -> int:
        score = 100
        unique_alerts = {
            (alert.get("rule_id"), alert.get("title"), alert.get("src_ip")): alert
            for alert in self.alerts
            if alert.get("rule_id") != "Traffic_Spike_Warning"
        }
        score -= min(
            45,
            sum(
                15 if alert["severity"] == "Critical" else 7
                for alert in unique_alerts.values()
            ),
        )
        score -= min(20, len(self.health_context.get("services", [])) * 5)
        score -= min(10, int(self.health_context.get("failed_logins", 0)) * 2)
        if self.health_context.get("defender_enabled") is False:
            score -= 20
        if self.health_context.get("firewall_enabled") is False:
            score -= 20
        last_update = self.health_context.get("last_update")
        if last_update:
            try:
                updated = datetime.fromisoformat(str(last_update).replace("Z", "+00:00"))
                if (datetime.now(timezone.utc) - updated).days > 60:
                    score -= 10
            except ValueError:
                pass
        return max(0, min(100, score))

    @staticmethod
    def _status_text(value: Any) -> str:
        if value is True:
            return "Enabled"
        if value is False:
            return "Disabled"
        return "Unknown"

    def _draw_charts(self) -> None:
        self.severity_axis.clear()
        self.timeline_axis.clear()
        colors_by_level = {
            "Critical": "#ef5555",
            "High": "#ef9b4a",
            "Medium": "#e6ce62",
            "Low": "#4fb982",
        }
        severity_counts = {
            level: sum(alert["severity"] == level for alert in self.alerts)
            for level in colors_by_level
        }
        nonzero = [(name, value) for name, value in severity_counts.items() if value]
        self.severity_axis.set_facecolor("#111b2e")
        if nonzero:
            self.severity_axis.pie(
                [item[1] for item in nonzero],
                labels=[item[0] for item in nonzero],
                colors=[colors_by_level[item[0]] for item in nonzero],
                autopct="%1.0f%%",
                textprops={"color": "#dbe6f5", "fontsize": 8},
            )
        else:
            self.severity_axis.text(0.5, 0.5, "No alerts", color="#a6b8d3", ha="center")
        self.severity_axis.set_title("Severity distribution", color="#dbe6f5", fontsize=10)
        self.timeline_axis.set_facecolor("#111b2e")
        by_minute: dict[str, int] = {}
        for alert in self.alerts:
            minute = alert["timestamp"][:16].replace("T", " ")
            by_minute[minute] = by_minute.get(minute, 0) + 1
        points = sorted(by_minute.items())
        if points:
            self.timeline_axis.plot(
                [point[0] for point in points],
                [point[1] for point in points],
                color="#54a8ff",
                marker="o",
                linewidth=2,
            )
            self.timeline_axis.tick_params(axis="x", rotation=25, labelsize=7, colors="#9fb2cd")
            self.timeline_axis.tick_params(axis="y", labelsize=8, colors="#9fb2cd")
        else:
            self.timeline_axis.text(0.5, 0.5, "No alert timeline", color="#a6b8d3", ha="center")
        self.timeline_axis.set_title("Alerts over time", color="#dbe6f5", fontsize=10)
        self.timeline_axis.grid(color="#28364a", alpha=0.5)
        for axis in (self.severity_axis, self.timeline_axis):
            for spine in axis.spines.values():
                spine.set_color("#28364a")
        self.figure.tight_layout()
        self.canvas.draw_idle()

    def export_csv(self) -> None:
        path = filedialog.asksaveasfilename(
            parent=self.root,
            defaultextension=".csv",
            filetypes=[("CSV files", "*.csv")],
            initialfile="aegis_events.csv",
        )
        if not path:
            return
        alert_map = {
            event_id: "|".join(alert["rule_id"] for alert in alerts)
            for event_id, alerts in self.alert_by_event.items()
        }
        with Path(path).open("w", newline="", encoding="utf-8-sig") as file:
            fieldnames = list(self.events[0].to_dict()) + ["alert_rule_ids"] if self.events else [
                "event_id", "timestamp", "alert_rule_ids"
            ]
            writer = csv.DictWriter(file, fieldnames=fieldnames)
            writer.writeheader()
            for event in self.events:
                row = event.to_dict()
                row["alert_rule_ids"] = alert_map.get(event.event_id, "")
                writer.writerow(row)
        self.status_text.set(f"CSV exported: {path}")

    def export_pdf(self) -> None:
        path = filedialog.asksaveasfilename(
            parent=self.root,
            defaultextension=".pdf",
            filetypes=[("PDF files", "*.pdf")],
            initialfile="aegis_soc_report.pdf",
        )
        if not path:
            return
        styles = getSampleStyleSheet()
        document = SimpleDocTemplate(path, pagesize=landscape(letter))
        rows: list[list[Any]] = [
            ["Time (UTC)", "Severity", "Host", "User", "Process", "Detection", "Risk", "Count"]
        ]
        for event, alerts, _count in self._visible_records():
            alert = alerts[0] if alerts else {}
            rows.append(
                [
                    event.timestamp[:19],
                    alert.get("severity", "Benign"),
                    event.host_name,
                    event.user,
                    event.process_name,
                    Paragraph(html.escape(alert.get("title", "Observed event")), styles["BodyText"]),
                    alert.get("risk_score", "—"),
                    f"x{_count}",
                ]
            )
        table = Table(
            rows, repeatRows=1, colWidths=[95, 55, 85, 65, 90, 275, 45, 45]
        )
        table.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1c2b43")),
                    ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                    ("GRID", (0, 0), (-1, -1), 0.25, colors.HexColor("#9aa8b8")),
                    ("VALIGN", (0, 0), (-1, -1), "TOP"),
                    ("FONTSIZE", (0, 0), (-1, -1), 7),
                    ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#edf2f7")]),
                ]
            )
        )
        document.build(
            [
                Paragraph("AegisAI-XDR | SOC Forensic Report", styles["Title"]),
                Paragraph(
                    f"Generated {datetime.now(timezone.utc).isoformat()} | "
                    f"Health score {self._health_score()}/100 | {len(self.events)} events",
                    styles["Normal"],
                ),
                Spacer(1, 12),
                table,
            ]
        )
        self.status_text.set(f"PDF exported: {path}")

    def clear_view(self) -> None:
        if not messagebox.askyesno(
            "Clear view",
            "Clear the current dashboard view? Stored events and the device baseline will remain.",
            parent=self.root,
        ):
            return
        self.events.clear()
        self.alerts.clear()
        self.seen_ids.clear()
        self.event_by_id.clear()
        self.alert_by_event.clear()
        self.health_context = {}
        self._render_table()
        self._update_dashboard()
        self.status_text.set("Dashboard view cleared; database and baseline were retained.")

    def run(self) -> None:
        self.root.mainloop()


def launch_dashboard(
    root_dir: Path,
    settings_loader: Callable[[], dict[str, Any]],
    pipeline_runner: Callable[..., tuple[list[NormalizedEvent], list[dict[str, Any]]]],
) -> None:
    AegisDashboard(root_dir, settings_loader, pipeline_runner).run()
