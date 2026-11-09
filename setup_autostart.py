"""Install the bounded collector in the current Windows user's Startup folder."""

from __future__ import annotations

import os
from pathlib import Path
import platform
import sys


ROOT = Path(__file__).resolve().parent
STARTUP_ENTRY_NAME = "AegisAI-AutoCollect.vbs"


def _vbs_string(value: str) -> str:
    return '"' + value.replace('"', '""') + '"'


def install_autostart() -> Path:
    if platform.system().lower() != "windows":
        raise OSError("Windows Startup installation is supported on Windows only.")
    appdata = os.environ.get("APPDATA")
    if not appdata:
        raise RuntimeError("APPDATA is not set; cannot locate the Windows Startup folder.")
    startup = Path(appdata) / "Microsoft" / "Windows" / "Start Menu" / "Programs" / "Startup"
    startup.mkdir(parents=True, exist_ok=True)
    pythonw = Path(sys.executable).with_name("pythonw.exe")
    interpreter = pythonw if pythonw.is_file() else Path(sys.executable)
    command = f'{_vbs_string(str(interpreter))} {_vbs_string(str(ROOT / "main.py"))} --collect-only'
    script = (
        'Set shell = CreateObject("WScript.Shell")\n'
        f"shell.CurrentDirectory = {_vbs_string(str(ROOT))}\n"
        f"shell.Run { _vbs_string(command) }, 0, False\n"
    )
    entry = startup / STARTUP_ENTRY_NAME
    entry.write_text(script, encoding="utf-8")
    return entry


if __name__ == "__main__":
    install_autostart()
    print("Autostart installed")
