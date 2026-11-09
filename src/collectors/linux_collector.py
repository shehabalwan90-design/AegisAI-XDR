"""Best-effort one-shot reader for common Linux host logs."""

from __future__ import annotations

from datetime import datetime, timezone
import os
import platform
import re
from typing import Any

from src.collectors.base_collector import BaseCollector


class LinuxCollector(BaseCollector):
    LOG_PATHS = ("/var/log/auth.log", "/var/log/syslog", "/var/log/secure")
    LINE_PATTERN = re.compile(
        r"^(?P<month>\w{3})\s+(?P<day>\d{1,2})\s+"
        r"(?P<clock>\d{2}:\d{2}:\d{2})\s+(?P<host>\S+)\s+(?P<message>.*)$"
    )

    def __init__(self) -> None:
        if platform.system().lower() != "linux":
            raise OSError("LinuxCollector can only run on Linux.")

    def collect(self, limit: int = 100) -> list[dict[str, Any]]:
        if limit < 1:
            return []
        lines: list[str] = []
        readable_paths = 0
        for path in self.LOG_PATHS:
            if not os.path.isfile(path) or not os.access(path, os.R_OK):
                continue
            readable_paths += 1
            with open(path, encoding="utf-8", errors="replace") as log_file:
                lines.extend(log_file.readlines()[-limit:])
        if not readable_paths:
            raise PermissionError(
                "No readable auth/syslog files found; check log paths and permissions."
            )
        events: list[dict[str, Any]] = []
        year = datetime.now().year
        for line in lines[-limit:]:
            match = self.LINE_PATTERN.match(line.rstrip())
            if not match:
                continue
            fields = match.groupdict()
            message = fields["message"]
            failed = bool(re.search(r"failed password|authentication failure", message, re.I))
            code = 4625 if failed else 0
            try:
                timestamp = datetime.strptime(
                    f"{year} {fields['month']} {fields['day']} {fields['clock']}",
                    "%Y %b %d %H:%M:%S",
                ).replace(tzinfo=timezone.utc).isoformat()
            except ValueError:
                timestamp = datetime.now(timezone.utc).isoformat()
            source = re.search(r"(?:from|rhost=)\s*(\d{1,3}(?:\.\d{1,3}){3})", message, re.I)
            user = re.search(r"(?:for|user=)\s+(?:invalid user\s+)?(\S+)", message, re.I)
            events.append(
                {
                    "timestamp": timestamp,
                    "host_name": fields["host"],
                    "os_event_code": code,
                    "raw_payload": message,
                    "src_ip": source.group(1) if source else "",
                    "user": user.group(1) if user else "",
                    "failed_logins": int(failed),
                }
            )
        return events
