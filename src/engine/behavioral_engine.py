"""Behavioral detections and a cold-start-aware host anomaly model."""

from __future__ import annotations

from collections import Counter
from datetime import date, datetime, timezone
import math
from pathlib import PureWindowsPath
from typing import Any

from sklearn.ensemble import IsolationForest

from src.engine.risk_scorer import score_risk
from src.normalizer.parser import NormalizedEvent


OFFICE_PROCESSES = {"WINWORD.EXE", "EXCEL.EXE", "POWERPNT.EXE", "OUTLOOK.EXE"}
SUSPICIOUS_PATHS = (
    "\\TEMP\\",
    "\\APPDATA\\",
    "\\USERS\\PUBLIC\\",
    "%TEMP%",
    "%APPDATA%",
)
CHAIN = ("WINWORD.EXE", "POWERSHELL.EXE", "CERTUTIL.EXE", "RUNDLL32.EXE")


def _process(value: str) -> str:
    return PureWindowsPath(value.replace("/", "\\")).name.upper()


class BehavioralEngine:
    """Adds process lineage, path, obfuscation, and historical anomaly context."""

    def __init__(self, history: list[dict[str, Any]] | None = None) -> None:
        self.history = history or []
        self.process_counts = Counter(
            _process(str(row.get("process_name", "")))
            for row in self.history
            if row.get("process_name")
        )
        self.known_processes = set(self.process_counts)
        self.model: IsolationForest | None = None
        self.training_scores: list[float] = []
        training = [self._features(row) for row in self.history if row.get("process_name")]
        observation_dates: set[date] = set()
        for row in self.history:
            if not row.get("process_name") or not row.get("timestamp"):
                continue
            try:
                timestamp = datetime.fromisoformat(
                    str(row["timestamp"]).replace("Z", "+00:00")
                )
                if timestamp.tzinfo is None:
                    timestamp = timestamp.replace(tzinfo=timezone.utc)
                observation_dates.add(timestamp.astimezone(timezone.utc).date())
            except ValueError:
                continue
        self.training_days = len(observation_dates)
        if len(training) >= 20 and self.training_days >= 7:
            self.model = IsolationForest(
                n_estimators=100, contamination="auto", random_state=42
            )
            self.model.fit(training)
            self.training_scores = sorted(
                float(value) for value in self.model.score_samples(training)
            )

    def _features(self, row: dict[str, Any] | NormalizedEvent) -> list[float]:
        get = row.get if isinstance(row, dict) else lambda key, default="": getattr(row, key, default)
        process_name = _process(str(get("process_name", "")))
        timestamp = str(get("timestamp", ""))
        try:
            hour = datetime.fromisoformat(timestamp.replace("Z", "+00:00")).hour
        except ValueError:
            hour = 12
        path = str(get("process_path", "")).upper().replace("/", "\\")
        unusual_path = float(any(token in path for token in SUSPICIOUS_PATHS))
        process_frequency = math.log1p(self.process_counts.get(process_name, 0)) / 10
        return [
            math.sin(hour * math.tau / 24),
            math.cos(hour * math.tau / 24),
            float(len(process_name)),
            process_frequency,
            float(get("failed_logins", 0) or 0),
            unusual_path,
            min(len(str(get("command_line", ""))), 2000) / 2000,
        ]

    def anomaly_score(self, event: NormalizedEvent) -> int:
        process_name = _process(event.process_name)
        if self.model and self.training_scores:
            value = float(self.model.score_samples([self._features(event)])[0])
            rank = sum(score <= value for score in self.training_scores) / len(self.training_scores)
            score = round((1 - rank) * 100)
            if process_name and process_name not in self.known_processes:
                score = max(score, 70)
        else:
            score = 70 if process_name and process_name not in self.known_processes else 20
        path = event.process_path.upper().replace("/", "\\")
        if any(token in path for token in SUSPICIOUS_PATHS):
            score += 20
        return min(100, max(0, score))

    def classify(self, event: NormalizedEvent) -> list[dict[str, Any]]:
        event.anomaly_score = self.anomaly_score(event)
        process_name = _process(event.process_name)
        parent_name = _process(event.parent_process)
        path = event.process_path.upper().replace("/", "\\")
        project_root = r"D:\ANTYGRAVTIY"
        project_tool = (
            process_name in {"PYTHON.EXE", "POWERSHELL.EXE"}
            and (path == project_root or path.startswith(project_root + "\\"))
        )
        if project_tool:
            return []
        alerts: list[dict[str, Any]] = []
        if process_name == "POWERSHELL.EXE" and parent_name in OFFICE_PROCESSES:
            alerts.append(self._alert(event, "Office spawned PowerShell", "T1059.001", 100, "Critical"))
        if event.process_name and any(token in path for token in SUSPICIOUS_PATHS):
            alerts.append(self._alert(event, "Process launched from unusual location", "T1036", 80))
        lineage = [
            _process(part.strip())
            for part in event.parent_process_chain.replace("→", "->").split("->")
            if part.strip()
        ]
        lineage.append(process_name)
        chain_index = 0
        for item in lineage:
            if item == CHAIN[chain_index]:
                chain_index += 1
                if chain_index == len(CHAIN):
                    break
        if chain_index == len(CHAIN):
            alerts.append(
                self._alert(event, "Confirmed multi-stage process chain", "T1218.011", 100, "Critical")
            )
        if event.decoded_payload and event.decoded_payload != event.raw_payload:
            alerts.append(
                self._alert(
                    event,
                    "Obfuscated PowerShell payload",
                    "T1027",
                    min(100, 65 + 20),
                )
            )
        elif (
            any(
                token in event.clean_payload
                for token in ("CHAR(", "FROMCHARCODE", "REVERSE", "ESREVER")
            )
            or event.clean_payload.count("+") >= 5
        ):
            alerts.append(self._alert(event, "Obfuscation indicators", "T1027", 70))
        return alerts

    @staticmethod
    def _alert(
        event: NormalizedEvent,
        title: str,
        mitre_id: str,
        risk: int,
        severity_override: str | None = None,
    ) -> dict[str, Any]:
        score, severity = score_risk(risk, event.asset_weight)
        return {
            "event_id": event.event_id,
            "rule_id": f"Behavior_{mitre_id.replace('.', '_')}",
            "title": title,
            "category": "behavioral",
            "mitre_id": mitre_id,
            "mitre_tactic": "Execution" if "T1059" in mitre_id else "Defense Evasion",
            "base_score": risk,
            "risk_score": score,
            "severity": severity_override or severity,
            "soc_action": "Validate process lineage, binary signer, and user intent.",
            "src_ip": event.src_ip,
            "timestamp": event.timestamp,
            "process_name": event.process_name,
            "parent_process": event.parent_process,
            "anomaly_score": event.anomaly_score,
        }
