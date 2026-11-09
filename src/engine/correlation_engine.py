"""Stateful sliding-window correlation over normalized event streams."""

from __future__ import annotations

from collections import defaultdict, deque
from datetime import datetime, timedelta, timezone
from typing import Any

from src.engine.risk_scorer import score_risk
from src.normalizer.parser import NormalizedEvent


class CorrelationEngine:
    def __init__(self, window_seconds: int = 300, static_traffic_tuning: bool = True) -> None:
        if window_seconds < 1:
            raise ValueError("window_seconds must be positive.")
        self.window = timedelta(seconds=window_seconds)
        self.static_traffic_tuning = static_traffic_tuning
        self.events: deque[tuple[datetime, NormalizedEvent]] = deque()

    @staticmethod
    def _time(event: NormalizedEvent) -> datetime:
        value = datetime.fromisoformat(event.timestamp.replace("Z", "+00:00"))
        return value.replace(tzinfo=timezone.utc) if value.tzinfo is None else value

    def process(self, event: NormalizedEvent) -> list[dict[str, Any]]:
        now = self._time(event)
        self.events.append((now, event))
        while self.events and now - self.events[0][0] > self.window:
            self.events.popleft()
        alerts: list[dict[str, Any]] = []
        source_events = [
            item for _, item in self.events if event.src_ip and item.src_ip == event.src_ip
        ]
        failures = [
            item for item in source_events
            if item.os_event_code == 4625 or item.failed_logins > 0
        ]
        user_counts: dict[str, int] = defaultdict(int)
        for failure in failures:
            user_counts[failure.user or "unknown"] += max(1, failure.failed_logins)
        source_total = sum(user_counts.values())
        if user_counts.get(event.user or "unknown", 0) >= 5:
            alert = self._alert(event, "Single_Account_Brute_Force", "T1110", 75)
            alert["related_event_ids"] = [
                item.event_id
                for item in failures
                if (item.user or "unknown") == (event.user or "unknown")
            ]
            alerts.append(alert)
        if source_total >= 5 and len(user_counts) >= 2:
            alert = self._alert(event, "Password_Spraying", "T1110.003", 80)
            alert["related_event_ids"] = [item.event_id for item in failures]
            alerts.append(alert)
        is_static_file = any(
            token in event.clean_payload for token in ("GET ", ".PDF", ".PNG")
        )
        if event.pkt_rate > 5000 or "SYN_FLOOD" in event.clean_payload:
            if self.static_traffic_tuning and is_static_file:
                alerts.append(self._alert(event, "Traffic_Spike_Warning", "T1498", 50))
            else:
                alerts.append(self._alert(event, "DDoS_SYN_Flood", "T1498", 85))
        return alerts

    @staticmethod
    def _alert(
        event: NormalizedEvent, rule_id: str, mitre_id: str, base_score: int
    ) -> dict[str, Any]:
        risk, severity = score_risk(base_score, event.asset_weight)
        return {
            "event_id": event.event_id,
            "rule_id": rule_id,
            "title": rule_id.replace("_", " "),
            "category": "correlation",
            "mitre_id": mitre_id,
            "mitre_tactic": "Credential Access" if "T1110" in mitre_id else "Impact",
            "base_score": base_score,
            "risk_score": risk,
            "severity": severity,
            "soc_action": "Correlate source activity across the configured time window.",
            "src_ip": event.src_ip,
            "timestamp": event.timestamp,
        }
