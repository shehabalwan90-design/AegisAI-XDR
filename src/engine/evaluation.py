"""Shared, label-aware binary evaluation for offline fixtures."""

from __future__ import annotations

from typing import Any

from src.normalizer.parser import NormalizedEvent


INFORMATIONAL_RULES = {"Traffic_Spike_Warning"}


def evaluate_predictions(
    events: list[NormalizedEvent], alerts: list[dict[str, Any]]
) -> dict[str, Any]:
    """Score malicious classification while retaining correlation and warning semantics."""
    known_events = [event for event in events if event.true_label != "Unknown"]
    predicted_ids: set[str] = set()
    for alert in alerts:
        if alert.get("rule_id") in INFORMATIONAL_RULES:
            continue
        predicted_ids.add(str(alert.get("event_id", "")))
        predicted_ids.update(str(value) for value in alert.get("related_event_ids", []))
    truth = [event.true_label != "Benign" for event in known_events]
    predicted = [event.event_id in predicted_ids for event in known_events]
    correct = sum(actual == result for actual, result in zip(truth, predicted))
    return {
        "accuracy": correct / max(1, len(known_events)),
        "count": len(known_events),
        "true": truth,
        "predicted": predicted,
        "predicted_event_ids": predicted_ids,
    }
