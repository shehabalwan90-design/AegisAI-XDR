"""Windows Event Log collector with a PowerShell fallback."""

from __future__ import annotations

import json
import logging
import platform
import re
import subprocess
from typing import Any
from datetime import datetime, timezone

from src.collectors.base_collector import BaseCollector

LOGGER = logging.getLogger(__name__)


class WindowsCollector(BaseCollector):
    CHANNELS = (
        "Security",
        "System",
        "Microsoft-Windows-PowerShell/Operational",
    )
    EVENT_IDS = (4624, 4625, 4688, 4104, 1102, 7045)

    def __init__(self) -> None:
        if platform.system().lower() != "windows":
            raise OSError("WindowsCollector can only run on Windows.")
        self.collection_warnings: list[str] = []

    def collect(self, limit: int = 100) -> list[dict[str, Any]]:
        if limit < 1:
            return []
        script = (
            "[Console]::OutputEncoding = [System.Text.UTF8Encoding]::new($false); "
            "$ids = @(" + ",".join(str(code) for code in self.EVENT_IDS) + "); "
            "$logs = @('" + "','".join(self.CHANNELS) + "'); "
            "$collectionErrors = @(); "
            "$events = foreach ($log in $logs) { try { "
            "Get-WinEvent -FilterHashtable @{LogName=$log; Id=$ids} "
            "-MaxEvents " + str(int(limit)) + " -ErrorAction Stop "
            "} catch { if ($_.Exception.Message -notmatch 'No events were found') { "
            "$collectionErrors += ($log + ': ' + $_.Exception.Message) } } }; "
            "$records = @($events | Sort-Object TimeCreated -Descending | Select-Object -First "
            + str(int(limit)) + " "
            "@{Name='event_id';Expression={$_.LogName + ':' + "
            "$_.TimeCreated.ToUniversalTime().ToString('o') + ':' + $_.RecordId}},"
            "@{Name='timestamp';Expression={$_.TimeCreated.ToUniversalTime().ToString('o')}}," 
            "@{Name='host_name';Expression={$_.MachineName}},"
            "@{Name='os_event_code';Expression={$_.Id}},"
            "@{Name='channel';Expression={$_.LogName}},"
            "@{Name='raw_payload';Expression={$_.Message}}); "
            "@{events=$records; collection_errors=$collectionErrors} | "
            "ConvertTo-Json -Depth 4 -Compress"
        )
        result = subprocess.run(
            ["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script],
            check=False,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=60,
        )
        if result.returncode:
            detail = result.stderr.strip() or "PowerShell returned a non-zero status."
            raise RuntimeError(f"Windows Event Log collection failed: {detail}")
        if not result.stdout.strip():
            raise RuntimeError("Windows Event Log collection returned no data.")
        parsed = json.loads(result.stdout)
        if isinstance(parsed, dict) and "events" in parsed:
            records = parsed.get("events") or []
            warnings = parsed.get("collection_errors") or []
            self.collection_warnings = [warnings] if isinstance(warnings, str) else warnings
            for warning in self.collection_warnings:
                LOGGER.warning("Windows Event Log collection warning: %s", warning)
        else:
            records = parsed if isinstance(parsed, list) else [parsed]
        return [
            self._enrich_event(record)
            for record in records[:limit]
            if isinstance(record, dict)
        ]

    @staticmethod
    def _enrich_event(record: dict[str, Any]) -> dict[str, Any]:
        message = str(record.get("raw_payload") or "")
        fields = (
            ("process_path", r"New Process Name:\s*(.+)"),
            ("parent_process", r"Creator Process Name:\s*(.+)"),
            ("command_line", r"Process Command Line:\s*(.*)"),
            ("user", r"(?:Account Name|TargetUserName):\s*([^\s\r\n]+)"),
            ("src_ip", r"(?:Source Network Address|IpAddress):\s*([0-9a-fA-F:.]+)"),
        )
        for field, pattern in fields:
            match = re.search(pattern, message, re.IGNORECASE)
            if match:
                value = match.group(1).strip()
                if value not in {"-", "::1", "127.0.0.1"}:
                    record[field] = value
        if int(record.get("os_event_code") or 0) in {4624, 4625}:
            target = re.search(
                r"(?:New Logon|Account For Which Logon Failed):.*?"
                r"Account Name:\s*([^\s\r\n]+)",
                message,
                re.IGNORECASE | re.DOTALL,
            )
            if target:
                record["user"] = target.group(1).strip()
        path = str(record.get("process_path") or "")
        if path:
            record["process_name"] = path.replace("/", "\\").rsplit("\\", 1)[-1]
        if record.get("parent_process"):
            record["parent_process"] = (
                str(record["parent_process"]).replace("/", "\\").rsplit("\\", 1)[-1]
            )
        return record

    def collect_host_snapshot(self) -> dict[str, Any]:
        """Collect read-only process, service, user, and security posture context."""
        script = (
            "$ErrorActionPreference='Stop'; "
            "$processes = @(Get-CimInstance Win32_Process | Select-Object -First 500 "
            "ProcessId,ParentProcessId,Name,ExecutablePath,CommandLine); "
            "$services = @(Get-Service | Select-Object -ExpandProperty Name); "
            "$hostName = $env:COMPUTERNAME; "
            "$userName = [Security.Principal.WindowsIdentity]::GetCurrent().Name; "
            "$healthErrors = @(); "
            "$defender = $null; try { $defender = [bool](Get-MpComputerStatus "
            "-ErrorAction Stop).AMServiceEnabled } catch { $healthErrors += "
            "'Defender status unavailable: ' + $_.Exception.Message }; "
            "$firewall = $null; try { $profiles = @(Get-NetFirewallProfile "
            "-ErrorAction Stop); $firewall = [bool](($profiles | "
            "Where-Object Enabled -eq $false).Count -eq 0) } catch { $healthErrors += "
            "'Firewall status unavailable: ' + $_.Exception.Message }; "
            "$update = $null; try { $update = (Get-HotFix | "
            "Sort-Object InstalledOn -Descending | Select-Object -First 1).InstalledOn."
            "ToUniversalTime().ToString('o') } catch { $healthErrors += "
            "'Update status unavailable: ' + $_.Exception.Message }; "
            "@{host_name=$hostName; user=$userName; processes=$processes; "
            "services=$services; service_scope='all'; users=@($userName); "
            "defender_enabled=$defender; "
            "firewall_enabled=$firewall; last_update=$update; health_errors=$healthErrors; "
            "captured_at=[DateTime]::UtcNow.ToString('o')} | "
            "ConvertTo-Json -Depth 5 -Compress"
        )
        result = subprocess.run(
            ["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script],
            check=False,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=60,
        )
        if result.returncode:
            detail = result.stderr.strip() or "PowerShell returned a non-zero status."
            raise RuntimeError(f"Windows host snapshot failed: {detail}")
        if not result.stdout.strip():
            raise RuntimeError("Windows host snapshot returned no data.")
        snapshot = json.loads(result.stdout)
        if not isinstance(snapshot, dict):
            raise RuntimeError("Windows host snapshot returned an invalid shape.")
        process_records = snapshot.get("processes", [])
        if not process_records:
            process_records = []
        if isinstance(process_records, dict):
            process_records = [process_records]
        process_by_id = {
            int(item.get("ProcessId") or 0): item
            for item in process_records
            if isinstance(item, dict)
        }
        for item in process_records:
            if not isinstance(item, dict):
                continue
            parent_id = int(item.get("ParentProcessId") or 0)
            parent = process_by_id.get(parent_id, {})
            item["process_id"] = int(item.get("ProcessId") or 0)
            item["parent_process_id"] = parent_id
            item["process_name"] = str(item.get("Name") or "")
            item["process_path"] = str(item.get("ExecutablePath") or "")
            item["command_line"] = str(item.get("CommandLine") or "")
            item["parent_process"] = str(parent.get("Name") or "")
            lineage: list[str] = []
            seen: set[int] = set()
            cursor = parent_id
            while cursor in process_by_id and cursor not in seen:
                seen.add(cursor)
                ancestor = process_by_id[cursor]
                lineage.append(str(ancestor.get("Name") or ""))
                cursor = int(ancestor.get("ParentProcessId") or 0)
            item["parent_process_chain"] = " -> ".join(reversed(lineage))
        snapshot["processes"] = process_records
        snapshot["captured_at"] = snapshot.get("captured_at") or datetime.now(
            timezone.utc
        ).isoformat()
        return snapshot
