"""Stable plugin boundary for future supervised and unsupervised detectors."""

from abc import ABC, abstractmethod
from typing import Any

from src.normalizer.parser import NormalizedEvent


class BaseMLDetector(ABC):
    """A detector consumes normalized events and emits standard alert records."""

    @abstractmethod
    def detect(self, event: NormalizedEvent) -> list[dict[str, Any]]:
        """Return zero or more alerts in the shared alert shape."""
