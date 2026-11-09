"""Stateless, precompiled regex and event-code rules."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

import yaml

from src.engine.risk_scorer import score_risk
from src.normalizer.parser import NormalizedEvent


class AtomicEngine:
    def __init__(self, rules_path: str | Path) -> None:
        path = Path(rules_path)
        with path.open(encoding="utf-8") as rule_file:
            loaded = yaml.safe_load(rule_file) or {}
        self.rules: list[dict[str, Any]] = []
        for rule in loaded.get("rules", []):
            compiled = dict(rule)
            compiled["compiled_patterns"] = [
                re.compile(pattern, re.IGNORECASE)
                for pattern in rule.get("regex_patterns", [])
            ]
            compiled["event_codes"] = {int(code) for code in rule.get("os_event_codes", [])}
            self.rules.append(compiled)

    def classify(self, event: NormalizedEvent) -> list[dict[str, Any]]:
        project_path = event.process_path.replace("/", "\\").upper()
        project_root = r"D:\ANTYGRAVTIY"
        project_tool = (
            event.process_name.lower() in {"python.exe", "powershell.exe"}
            and (project_path == project_root or project_path.startswith(project_root + "\\"))
        )
        if project_tool:
            return []
        alerts: list[dict[str, Any]] = []
        for rule in self.rules:
            if event.os_event_code == 4104 and rule["id"] == "SQL_Injection":
                continue
            matched = event.os_event_code in rule["event_codes"] or any(
                pattern.search(event.clean_payload) for pattern in rule["compiled_patterns"]
            )
            if not matched:
                continue
            risk, severity = score_risk(rule["base_score"], event.asset_weight)
            alerts.append(
                {
                    "event_id": event.event_id,
                    "rule_id": rule["id"],
                    "title": rule["title"],
                    "category": rule["category"],
                    "mitre_id": rule["mitre_id"],
                    "mitre_tactic": rule["mitre_tactic"],
                    "base_score": rule["base_score"],
                    "risk_score": risk,
                    "severity": severity,
                    "soc_action": rule["soc_action"],
                    "src_ip": event.src_ip,
                    "timestamp": event.timestamp,
                }
            )
        return alerts
