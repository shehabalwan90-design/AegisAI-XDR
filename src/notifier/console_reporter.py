"""SOC alert display, CSV export, and classification evaluation."""

from __future__ import annotations

import csv
import json
from pathlib import Path
from typing import Any

from rich.console import Console
from rich.table import Table
from sklearn.metrics import classification_report, confusion_matrix

from src.engine.evaluation import evaluate_predictions
from src.normalizer.parser import NormalizedEvent


class ConsoleReporter:
    def __init__(self) -> None:
        self.console = Console()

    def display_alerts(self, alerts: list[dict[str, Any]]) -> None:
        table = Table(title="AegisAI-XDR | SOC Alert Triage")
        for column in ("Severity", "Risk", "Rule", "Source IP", "MITRE", "Action"):
            table.add_column(column)
        for alert in alerts:
            color = {
                "Critical": "bold red",
                "High": "red",
                "Medium": "yellow",
                "Low": "green",
            }.get(alert["severity"], "white")
            table.add_row(
                f"[{color}]{alert['severity']}[/{color}]",
                str(alert["risk_score"]),
                alert["title"],
                alert["src_ip"] or "-",
                alert["mitre_id"],
                alert["soc_action"],
            )
        self.console.print(table)
        if not alerts:
            self.console.print("No alerts detected.")

    @staticmethod
    def export_csv(events: list[NormalizedEvent], alerts: list[dict[str, Any]], path: str) -> None:
        alert_map: dict[str, list[str]] = {}
        for alert in alerts:
            alert_map.setdefault(alert["event_id"], []).append(alert["rule_id"])
        output_path = Path(path)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        fieldnames = list(events[0].to_dict()) + ["alert_rule_ids", "predicted_label"] if events else [
            "event_id", "timestamp", "true_label", "alert_rule_ids", "predicted_label"
        ]
        with output_path.open("w", newline="", encoding="utf-8") as csv_file:
            writer = csv.DictWriter(csv_file, fieldnames=fieldnames)
            writer.writeheader()
            for event in events:
                row = event.to_dict()
                rule_ids = alert_map.get(event.event_id, [])
                row["alert_rule_ids"] = "|".join(rule_ids)
                row["predicted_label"] = rule_ids[0] if rule_ids else "Benign"
                writer.writerow(row)

    def evaluate(self, events: list[NormalizedEvent], alerts: list[dict[str, Any]]) -> None:
        metrics = evaluate_predictions(events, alerts)
        known_events = [event for event in events if event.true_label != "Unknown"]
        true_labels = ["Malicious" if label else "Benign" for label in metrics["true"]]
        predicted_labels = [
            "Malicious" if label else "Benign" for label in metrics["predicted"]
        ]
        self.console.print(f"Accuracy: {metrics['accuracy']:.3f}")
        self.console.print(classification_report(
            true_labels, predicted_labels, labels=["Benign", "Malicious"], zero_division=0
        ))
        self.console.print("Confusion matrix [Benign, Malicious]:")
        self.console.print(confusion_matrix(
            true_labels, predicted_labels, labels=["Benign", "Malicious"]
        ))
        self.console.print("Misclassified alerts:")
        found = False
        for event, truth, prediction in zip(known_events, true_labels, predicted_labels):
            if truth == prediction:
                continue
            found = True
            kind = "False Negative" if truth == "Malicious" else "False Positive"
            self.console.print(
                f"- {kind}: event {event.event_id}, label={event.true_label}, "
                f"payload={event.raw_payload!r}"
            )
        if not found:
            self.console.print("None.")
        self.console.print(
            "Educational note: rule-based systems can miss novel behavior whose payload or "
            "sequence does not match known signatures (a zero-day false negative)."
        )

    @staticmethod
    def export_json(alerts: list[dict[str, Any]], path: str) -> None:
        output_path = Path(path)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(json.dumps(alerts, indent=2), encoding="utf-8")
