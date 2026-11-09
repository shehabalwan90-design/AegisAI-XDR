"""Local, privacy-preserving baseline for process/service/user name changes."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any


class BaselineStore:
    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)

    def load(self) -> dict[str, Any] | None:
        if not self.path.exists():
            return None
        data = json.loads(self.path.read_text(encoding="utf-8"))
        if not isinstance(data, dict):
            raise ValueError(f"Invalid baseline format at {self.path}.")
        return data

    def capture(self, snapshot: dict[str, Any]) -> dict[str, Any]:
        baseline = {
            "captured_at": snapshot.get("captured_at", ""),
            "host_name": snapshot.get("host_name", ""),
            "user": snapshot.get("user", ""),
            "processes": sorted(set(snapshot.get("processes", []))),
            "services": sorted(set(snapshot.get("services", []))),
            "service_scope": snapshot.get("service_scope", "running"),
            "users": sorted(set(snapshot.get("users", []))),
            "event_ids": sorted(set(snapshot.get("event_ids", [])))[-1000:],
            "event_watermark": snapshot.get("event_watermark", ""),
        }
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.write_text(json.dumps(baseline, indent=2), encoding="utf-8")
        return baseline

    def compare(self, snapshot: dict[str, Any]) -> dict[str, list[str]]:
        baseline = self.load()
        if baseline is None:
            self.capture(snapshot)
            return {"processes": [], "services": [], "users": []}
        service_scope_changed = baseline.get("service_scope") != snapshot.get(
            "service_scope", "running"
        )
        differences = {
            key: (
                []
                if key == "services" and service_scope_changed
                else sorted(set(snapshot.get(key, [])) - set(baseline.get(key, [])))
            )
            for key in ("processes", "services", "users")
        }
        for key in ("processes", "services", "users"):
            if key == "services" and service_scope_changed:
                baseline[key] = sorted(set(snapshot.get(key, [])))
            else:
                baseline[key] = sorted(
                    set(baseline.get(key, [])) | set(snapshot.get(key, []))
                )
        baseline["service_scope"] = snapshot.get("service_scope", "running")
        baseline["event_ids"] = sorted(
            set(baseline.get("event_ids", [])) | set(snapshot.get("event_ids", []))
        )[-1000:]
        if snapshot.get("event_watermark"):
            baseline["event_watermark"] = snapshot["event_watermark"]
        self.path.write_text(json.dumps(baseline, indent=2), encoding="utf-8")
        return differences
