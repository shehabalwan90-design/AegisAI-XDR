"""Bounded once-per-day host snapshots for offline model training."""

from __future__ import annotations

from datetime import datetime, timezone
import json
import logging
from pathlib import Path
import time
from typing import Any

from src.collectors.base_collector import create_platform_collector
from src.storage.training_history import training_status


LOGGER = logging.getLogger(__name__)
COLLECTION_SECONDS = 5 * 60
SAMPLE_INTERVAL_SECONDS = 60


def collect_daily_snapshot(root_dir: str | Path) -> Path | None:
    root = Path(root_dir)
    history_dir = root / "data" / "baseline_history"
    snapshot_date = datetime.now().astimezone().date().isoformat()
    destination = history_dir / f"{snapshot_date}.json"
    if destination.exists():
        LOGGER.info("Daily snapshot already exists: %s", destination.name)
        return None

    collector = create_platform_collector()
    collect_snapshot = getattr(collector, "collect_host_snapshot", None)
    if not callable(collect_snapshot):
        raise OSError("Background snapshots are currently supported on Windows only.")

    started = time.monotonic()
    observations: list[dict[str, Any]] = []
    process_inventory: dict[tuple[str, str], dict[str, Any]] = {}
    services: set[str] = set()
    sample_count = 0
    latest: dict[str, Any] = {}
    while True:
        snapshot = collect_snapshot()
        observed_at = datetime.now(timezone.utc).isoformat()
        latest = snapshot
        sample_count += 1
        processes = snapshot.get("processes", [])
        if isinstance(processes, dict):
            processes = [processes]
        for item in processes:
            if not isinstance(item, dict):
                continue
            process_name = str(item.get("process_name") or item.get("Name") or "")
            process_path = str(item.get("process_path") or item.get("ExecutablePath") or "")
            if not process_name:
                continue
            process = {
                "process_name": process_name,
                "process_path": process_path,
                "timestamp": observed_at,
            }
            observations.append(process)
            process_inventory[(process_name.lower(), process_path.lower())] = process
        services.update(str(service) for service in snapshot.get("services", []))

        remaining = COLLECTION_SECONDS - (time.monotonic() - started)
        if remaining <= 0:
            break
        time.sleep(min(SAMPLE_INTERVAL_SECONDS, remaining))
        if time.monotonic() - started >= COLLECTION_SECONDS:
            break

    payload = {
        "date": snapshot_date,
        "captured_at": datetime.now(timezone.utc).isoformat(),
        "host_name": latest.get("host_name", ""),
        "user": latest.get("user", ""),
        "processes": list(process_inventory.values()),
        "process_observations": observations,
        "services": sorted(services),
        "users": latest.get("users", []),
        "service_scope": latest.get("service_scope", "all"),
        "defender_enabled": latest.get("defender_enabled"),
        "firewall_enabled": latest.get("firewall_enabled"),
        "last_update": latest.get("last_update"),
        "health_errors": latest.get("health_errors", []),
        "sample_count": sample_count,
        "collection_seconds": round(time.monotonic() - started),
    }
    history_dir.mkdir(parents=True, exist_ok=True)
    temporary_path = destination.with_suffix(".json.tmp")
    temporary_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    temporary_path.replace(destination)
    LOGGER.info("Daily host snapshot saved to %s", destination)
    status = training_status(root)
    LOGGER.info(
        "Training Days: %s/7 | Model Status: %s",
        status["days"],
        status["status"],
    )
    return destination
