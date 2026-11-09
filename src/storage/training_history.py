"""Daily process observations and IsolationForest training status."""

from __future__ import annotations

from datetime import date
import json
import logging
from pathlib import Path
import pickle
from typing import Any

from src.engine.behavioral_engine import BehavioralEngine


LOGGER = logging.getLogger(__name__)
MINIMUM_TRAINING_DAYS = 7


def _snapshot_files(root_dir: Path) -> list[tuple[date, Path]]:
    history_dir = root_dir / "data" / "baseline_history"
    snapshots: list[tuple[date, Path]] = []
    if not history_dir.exists():
        return snapshots
    for path in history_dir.glob("????-??-??.json"):
        try:
            snapshot_date = date.fromisoformat(path.stem)
            json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError, json.JSONDecodeError) as error:
            LOGGER.warning("Snapshot skipped: %s (%s)", path.name, error)
            continue
        snapshots.append((snapshot_date, path))
    return sorted(snapshots)


def load_training_history(
    root_dir: str | Path, limit_days: int | None = MINIMUM_TRAINING_DAYS
) -> list[dict[str, Any]]:
    history: list[dict[str, Any]] = []
    snapshots = _snapshot_files(Path(root_dir))
    if limit_days is not None:
        snapshots = snapshots[-limit_days:]
    for _, path in snapshots:
        try:
            snapshot = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as error:
            LOGGER.warning("Snapshot skipped: %s (%s)", path.name, error)
            continue
        observations = snapshot.get("process_observations", [])
        if not isinstance(observations, list):
            LOGGER.warning("Snapshot skipped: %s (invalid process observations)", path.name)
            continue
        history.extend(
            row
            for row in observations
            if isinstance(row, dict) and row.get("process_name")
        )
    return history


def training_status(root_dir: str | Path) -> dict[str, Any]:
    root = Path(root_dir)
    snapshots = _snapshot_files(root)
    days = len({snapshot_date for snapshot_date, _ in snapshots})
    model_path = root / "data" / "models" / "isolation_forest.pkl"
    trained = False
    if days >= MINIMUM_TRAINING_DAYS:
        history = load_training_history(root)
        engine = BehavioralEngine(history)
        if engine.model is not None:
            model_path.parent.mkdir(parents=True, exist_ok=True)
            temporary_path = model_path.with_suffix(".pkl.tmp")
            with temporary_path.open("wb") as model_file:
                pickle.dump(engine, model_file, protocol=pickle.HIGHEST_PROTOCOL)
            temporary_path.replace(model_path)
            trained = True
        else:
            LOGGER.warning(
                "IsolationForest training deferred: 7 days exist but fewer than 20 process observations are available."
            )
    if trained:
        status = "Fully Trained - 7/7 days"
    else:
        status = f"Collecting - {min(days, MINIMUM_TRAINING_DAYS)}/7 days - Pre-trained Initial"
    return {
        "days": min(days, MINIMUM_TRAINING_DAYS),
        "status": status,
        "trained": trained,
        "model_path": model_path,
    }
