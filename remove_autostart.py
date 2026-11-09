"""Remove the AegisAI-XDR entry from the current Windows user's Startup folder."""

from __future__ import annotations

import os
from pathlib import Path
import platform


STARTUP_ENTRY_NAME = "AegisAI-AutoCollect.vbs"


def remove_autostart() -> bool:
    if platform.system().lower() != "windows":
        raise OSError("Windows Startup removal is supported on Windows only.")
    appdata = os.environ.get("APPDATA")
    if not appdata:
        raise RuntimeError("APPDATA is not set; cannot locate the Windows Startup folder.")
    entry = (
        Path(appdata)
        / "Microsoft"
        / "Windows"
        / "Start Menu"
        / "Programs"
        / "Startup"
        / STARTUP_ENTRY_NAME
    )
    if not entry.exists():
        return False
    entry.unlink()
    return True


if __name__ == "__main__":
    remove_autostart()
    print("Autostart removed")
