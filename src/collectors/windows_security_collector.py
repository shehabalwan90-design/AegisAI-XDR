"""Read-only collector for Windows Security authentication and process events."""

from __future__ import annotations

import json
import logging
import platform
import subprocess
from typing import Any


LOGGER = logging.getLogger(__name__)


class WindowsSecurityEventCollector:
    EVENT_IDS = (4625, 4624, 4688)
    EVENT_DETAILS = {
        4625: ("Failed Login - Brute Force", "T1110 - Brute Force", "Credential Access", "High"),
        4624: ("Successful Login", "T1078 - Valid Accounts", "Initial Access", "Benign"),
        4688: (
            "Process Creation",
            "T1059 - Command and Scripting Interpreter",
            "Execution",
            "Benign",
        ),
    }

    def __init__(self) -> None:
        if platform.system().lower() != "windows":
            raise OSError("WindowsSecurityEventCollector can only run on Windows.")

    def collect(self, limit: int = 100) -> list[dict[str, Any]]:
        if limit < 1:
            return []
        script = (
            "[Console]::OutputEncoding = [System.Text.UTF8Encoding]::new($false); "
            "$ids = @(" + ",".join(str(code) for code in self.EVENT_IDS) + "); "
            "$collectionErrors = @(); $events = @(); "
            "try { $events = @(Get-WinEvent -FilterHashtable @{LogName='Security'; Id=$ids} "
            "-MaxEvents " + str(int(limit)) + " -ErrorAction Stop) } "
            "catch { if ($_.Exception.Message -notmatch 'No events were found') { "
            "$collectionErrors += $_.Exception.Message } }; "
            "$records = foreach ($event in $events) { "
            "$fields = @{}; "
            "([xml]$event.ToXml()).Event.EventData.Data | ForEach-Object { "
            "if ($_.Name) { $fields[[string]$_.Name] = [string]$_.'#text' } }; "
            "$code = [int]$event.Id; "
            "$details = switch ($code) { "
            "4625 { @('Failed Login - Brute Force','T1110 - Brute Force','Credential Access','High') } "
            "4624 { @('Successful Login','T1078 - Valid Accounts','Initial Access','Benign') } "
            "4688 { @('Process Creation','T1059 - Command and Scripting Interpreter','Execution','Benign') } }; "
            "$account = $fields['TargetUserName']; "
            "if (-not $account) { $account = $fields['SubjectUserName'] }; "
            "$source = $fields['IpAddress']; "
            "if (-not $source -or $source -eq '-') { $source = '' }; "
            "$processPath = $fields['NewProcessName']; "
            "$processName = if ($processPath) { [IO.Path]::GetFileName($processPath) } else { '' }; "
            "[pscustomobject]@{ "
            "event_id=('Security:' + $event.RecordId); "
            "timestamp=$event.TimeCreated.ToUniversalTime().ToString('o'); "
            "host_name=$event.MachineName; os_event_code=$code; user=$account; "
            "src_ip=$source; process_name=$processName; process_path=$processPath; "
            "detection_type=$details[0]; mitre_technique=$details[1]; "
            "mitre_tactic=$details[2]; event_severity=$details[3]; "
            "raw_payload=$event.Message } }; "
            "$payload = @{events=@($records); collection_errors=$collectionErrors}; "
            "ConvertTo-Json -InputObject $payload -Depth 4 -Compress"
        )
        self.collection_warnings: list[str] = []
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
            raise RuntimeError(f"Windows Security event collection failed: {detail}")
        if not result.stdout.strip():
            return []
        try:
            parsed = json.loads(result.stdout)
        except json.JSONDecodeError as error:
            raise RuntimeError("Windows Security event collector returned invalid JSON.") from error
        if isinstance(parsed, dict) and "events" in parsed:
            records = parsed.get("events") or []
            warnings = parsed.get("collection_errors") or []
            self.collection_warnings = [warnings] if isinstance(warnings, str) else warnings
            for warning in self.collection_warnings:
                LOGGER.warning("Windows Security event collection warning: %s", warning)
        else:
            records = parsed if isinstance(parsed, list) else [parsed]
        normalized: list[dict[str, Any]] = []
        for record in records[:limit]:
            if not isinstance(record, dict):
                continue
            code = int(record.get("os_event_code") or 0)
            details = self.EVENT_DETAILS.get(code)
            if details is None:
                LOGGER.warning("Skipping unsupported Windows Security event ID %s.", code)
                continue
            detection, technique, tactic, severity = details
            record.update(
                detection_type=detection,
                mitre_technique=technique,
                mitre_tactic=tactic,
                event_severity=severity,
                collector_type="windows_security",
            )
            normalized.append(record)
        return normalized
