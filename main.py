"""AegisAI-XDR v0.2 command-line pipeline."""

from __future__ import annotations

import argparse
import logging
from pathlib import Path
from typing import Any

import yaml

from src.collectors.attack_simulator import generate_events
from src.collectors.base_collector import create_platform_collector
from src.engine.atomic_engine import AtomicEngine
from src.engine.behavioral_engine import BehavioralEngine
from src.engine.correlation_engine import CorrelationEngine
from src.normalizer.parser import NormalizedEvent, normalize_event
from src.notifier.console_reporter import ConsoleReporter
from src.storage.db_manager import DBManager
from src.engine.threat_intel import ThreatIntel
from src.engine.risk_scorer import score_risk
from src.storage.training_history import load_training_history


ROOT = Path(__file__).resolve().parent


def load_settings() -> dict[str, Any]:
    with (ROOT / "config" / "settings.yaml").open(encoding="utf-8") as settings_file:
        return yaml.safe_load(settings_file) or {}


def run_pipeline(
    raw_events: list[dict[str, Any]],
    settings: dict[str, Any],
    history_events: list[dict[str, Any]] | None = None,
) -> tuple[list[NormalizedEvent], list[dict[str, Any]]]:
    weights = settings.get("asset_criticality", {})
    events = [
        normalize_event(
            raw,
            asset_criticality=weights,
            default_asset=settings.get("default_asset", "workstation"),
        )
        for raw in raw_events
    ]
    rules_path = ROOT / settings.get("rule_path", "config/rules/sigma_host_network.yaml")
    atomic = AtomicEngine(rules_path)
    correlation = CorrelationEngine(
        window_seconds=int(settings.get("correlation_window_seconds", 300)),
        static_traffic_tuning=bool(settings.get("static_traffic_tuning", True)),
    )
    behavioral = BehavioralEngine(history_events)
    threat_intel = ThreatIntel(ROOT / "data" / "threat_intel.json")
    alerts: list[dict[str, Any]] = []
    for event in events:
        event_alerts = behavioral.classify(event)
        event_alerts.extend(atomic.classify(event))
        event_alerts.extend(correlation.process(event))
        for indicator in threat_intel.match_event(event):
            severity = "Critical" if "SHA-256" in indicator else "High"
            score, _ = score_risk(100 if severity == "Critical" else 85, event.asset_weight)
            event_alerts.append(
                {
                    "event_id": event.event_id,
                    "rule_id": "Known_Malware_Hash" if severity == "Critical" else "Threat_Intel_Match",
                    "title": indicator,
                    "category": "threat_intelligence",
                    "mitre_id": "T1204",
                    "mitre_tactic": "Execution",
                    "base_score": 100 if severity == "Critical" else 85,
                    "risk_score": score,
                    "severity": severity,
                    "soc_action": "Validate the indicator and preserve evidence before response.",
                    "src_ip": event.src_ip,
                    "timestamp": event.timestamp,
                    "anomaly_score": event.anomaly_score,
                }
            )
        high_findings = [alert for alert in event_alerts if alert["risk_score"] > 70]
        if event.anomaly_score > 85 and high_findings:
            event_alerts = [
                alert for alert in event_alerts if alert["risk_score"] <= 70
            ]
            risk, severity = score_risk(
                min(100, max(alert["risk_score"] for alert in high_findings) + 10),
                1.0,
            )
            event_alerts.append(
                {
                    "event_id": event.event_id,
                    "rule_id": "Converged_Anomaly",
                    "title": "ML + rule high-confidence convergence",
                    "category": "behavioral",
                    "mitre_id": high_findings[0]["mitre_id"],
                    "mitre_tactic": high_findings[0]["mitre_tactic"],
                    "base_score": risk,
                    "risk_score": risk,
                    "severity": severity,
                    "soc_action": "Triage correlated anomaly and rule evidence as one incident.",
                    "src_ip": event.src_ip,
                    "timestamp": event.timestamp,
                    "anomaly_score": event.anomaly_score,
                    "correlated_rules": [alert["rule_id"] for alert in high_findings],
                }
            )
        alerts.extend(event_alerts)
    return events, alerts


def main() -> None:
    parser = argparse.ArgumentParser(description="AegisAI-XDR host telemetry pipeline")
    parser.add_argument("--mode", choices=("live", "simulate", "evaluate"), default="simulate")
    parser.add_argument("--simulate", action="store_true", help="Run the offline attack simulation.")
    parser.add_argument(
        "--collect-only",
        action="store_true",
        help="Collect one bounded, read-only daily host snapshot without opening the GUI.",
    )
    parser.add_argument("--limit", type=int, default=100)
    parser.add_argument("--export-csv", metavar="PATH")
    parser.add_argument("--export-json", metavar="PATH")
    parser.add_argument("--gui", action="store_true", help="Launch the dark-mode SOC dashboard.")
    args = parser.parse_args()
    if args.simulate:
        args.mode = "simulate"
    if args.collect_only:
        if args.gui:
            parser.error("--collect-only cannot be combined with --gui.")
        from src.collectors.background_collector import collect_daily_snapshot

        logging.basicConfig(
            level=logging.INFO,
            format="%(asctime)s %(levelname)s %(name)s: %(message)s",
        )
        snapshot_path = collect_daily_snapshot(ROOT)
        if snapshot_path is None:
            print("Daily snapshot already exists; collection skipped.")
        else:
            print(f"Snapshot saved: {snapshot_path}")
        return
    if args.gui:
        from src.ui.dashboard import launch_dashboard

        launch_dashboard(ROOT, load_settings, run_pipeline)
        return
    if args.limit < 1:
        parser.error("--limit must be positive.")
    settings = load_settings()
    if args.mode == "live":
        raw_events = create_platform_collector().collect(args.limit)
    else:
        raw_events = generate_events()
        if args.limit:
            raw_events = raw_events[:args.limit] if args.mode != "evaluate" else raw_events
    database_path = ROOT / settings.get("database_path", "aegis_soc.db")
    database = DBManager(database_path)
    try:
        history_events = database.recent_benign_events(days=7)
        if args.mode == "live":
            history_events.extend(load_training_history(ROOT))
        events, alerts = run_pipeline(raw_events, settings, history_events)
        for event in events:
            database.save_event(event)
        database.save_alerts(alerts)
        database.commit()
    finally:
        database.close()
    reporter = ConsoleReporter()
    reporter.display_alerts(alerts)
    if args.mode == "evaluate":
        reporter.evaluate(events, alerts)
    if args.export_csv:
        reporter.export_csv(events, alerts, args.export_csv)
    if args.export_json:
        reporter.export_json(alerts, args.export_json)


if __name__ == "__main__":
    main()
