"""Shared collector contract and platform selection."""

from abc import ABC, abstractmethod
from typing import Any
import platform


class BaseCollector(ABC):
    """Interface implemented by platform-specific event collectors."""

    @abstractmethod
    def collect(self, limit: int = 100) -> list[dict[str, Any]]:
        """Return at most `limit` raw telemetry records."""


def create_platform_collector() -> BaseCollector:
    """Build the collector for the current host operating system."""
    system = platform.system().lower()
    if system == "windows":
        from src.collectors.windows_collector import WindowsCollector

        return WindowsCollector()
    if system == "linux":
        from src.collectors.linux_collector import LinuxCollector

        return LinuxCollector()
    raise OSError(f"Live collection is unsupported on platform: {system}")
