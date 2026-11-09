"""SQLite persistence for normalized events and detection alerts."""

from __future__ import annotations

import json
from pathlib import Path
import sqlite3
from datetime import datetime, timedelta, timezone
from typing import Any

from src.normalizer.parser import NormalizedEvent


class DBManager:
    def __init__(self, database_path: str | Path) -> None:
        self.database_path = str(database_path)
        self.connection = sqlite3.connect(self.database_path)
        self.connection.row_factory = sqlite3.Row
        self.connection.executescript(
            """
            CREATE TABLE IF NOT EXISTS events (
                event_id TEXT PRIMARY KEY,
                timestamp TEXT NOT NULL,
                true_label TEXT NOT NULL,
                payload_json TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS alerts (
                alert_id INTEGER PRIMARY KEY AUTOINCREMENT,
                event_id TEXT NOT NULL,
                rule_id TEXT NOT NULL,
                severity TEXT NOT NULL,
                risk_score INTEGER NOT NULL,
                alert_json TEXT NOT NULL,
                FOREIGN KEY(event_id) REFERENCES events(event_id)
            );
            CREATE TABLE IF NOT EXISTS process_observations (
                observed_at TEXT NOT NULL,
                process_name TEXT NOT NULL,
                process_path TEXT NOT NULL,
                parent_process TEXT NOT NULL,
                PRIMARY KEY (observed_at, process_name, process_path)
            );
            """
        )
        self.connection.commit()

    def save_event(self, event: NormalizedEvent) -> None:
        self.connection.execute(
            "INSERT OR REPLACE INTO events(event_id, timestamp, true_label, payload_json) "
            "VALUES (?, ?, ?, ?)",
            (event.event_id, event.timestamp, event.true_label, json.dumps(event.to_dict())),
        )

    def save_alerts(self, alerts: list[dict[str, Any]]) -> None:
        self.connection.executemany(
            "INSERT INTO alerts(event_id, rule_id, severity, risk_score, alert_json) "
            "VALUES (?, ?, ?, ?, ?)",
            [
                (
                    alert["event_id"],
                    alert["rule_id"],
                    alert["severity"],
                    alert["risk_score"],
                    json.dumps(alert),
                )
                for alert in alerts
            ],
        )

    def commit(self) -> None:
        self.connection.commit()

    def events_with_alerts(self) -> list[dict[str, Any]]:
        rows = self.connection.execute("SELECT payload_json FROM events ORDER BY timestamp")
        events = [json.loads(row["payload_json"]) for row in rows]
        alerts_by_event: dict[str, list[str]] = {}
        for row in self.connection.execute("SELECT event_id, rule_id FROM alerts"):
            alerts_by_event.setdefault(row["event_id"], []).append(row["rule_id"])
        for event in events:
            event["predicted_label"] = (
                alerts_by_event.get(event["event_id"], ["Benign"])[0]
            )
            event["alert_rule_ids"] = alerts_by_event.get(event["event_id"], [])
        return events

    def recent_benign_events(self, days: int = 7) -> list[dict[str, Any]]:
        if days < 1:
            raise ValueError("days must be positive.")
        cutoff = (datetime.now(timezone.utc) - timedelta(days=days)).isoformat()
        rows = self.connection.execute(
            "SELECT e.payload_json FROM events AS e "
            "WHERE e.timestamp >= ? AND NOT EXISTS "
            "(SELECT 1 FROM alerts AS a WHERE a.event_id = e.event_id) "
            "ORDER BY e.timestamp",
            (cutoff,),
        )
        return [json.loads(row["payload_json"]) for row in rows]

    def save_process_observations(
        self, observed_at: str, processes: list[dict[str, Any]]
    ) -> None:
        hour_bucket = observed_at[:13]
        self.connection.executemany(
            "INSERT OR IGNORE INTO process_observations "
            "(observed_at, process_name, process_path, parent_process) "
            "VALUES (?, ?, ?, ?)",
            [
                (
                    hour_bucket,
                    str(process.get("process_name") or ""),
                    str(process.get("process_path") or ""),
                    str(process.get("parent_process") or ""),
                )
                for process in processes
                if process.get("process_name")
            ],
        )

    def recent_process_observations(self, days: int = 7) -> list[dict[str, Any]]:
        if days < 1:
            raise ValueError("days must be positive.")
        cutoff = (datetime.now(timezone.utc) - timedelta(days=days)).strftime("%Y-%m-%dT%H")
        rows = self.connection.execute(
            "SELECT observed_at, process_name, process_path, parent_process "
            "FROM process_observations WHERE observed_at >= ? ORDER BY observed_at",
            (cutoff,),
        )
        return [
            {
                "timestamp": row["observed_at"] + ":00:00+00:00",
                "process_name": row["process_name"],
                "process_path": row["process_path"],
                "parent_process": row["parent_process"],
            }
            for row in rows
        ]

    def close(self) -> None:
        self.connection.close()
