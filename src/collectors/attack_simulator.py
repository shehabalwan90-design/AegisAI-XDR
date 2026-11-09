"""Deterministic, offline telemetry fixtures; no attacks are executed."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any


def generate_events() -> list[dict[str, Any]]:
    """Return labeled synthetic benign and malicious host/network records."""
    base = datetime(2026, 1, 15, 12, 0, tzinfo=timezone.utc)
    events: list[dict[str, Any]] = []

    def add(
        payload: str,
        label: str,
        *,
        code: int = 0,
        src_ip: str = "198.51.100.10",
        user: str = "analyst",
        offset: int | None = None,
        pkt_rate: int = 0,
        asset: str = "web_server",
    ) -> None:
        index = len(events) if offset is None else offset
        events.append(
            {
                "timestamp": (base + timedelta(seconds=index)).isoformat(),
                "host_name": "aegis-lab",
                "asset_name": asset,
                "src_ip": src_ip,
                "dst_ip": "192.0.2.10",
                "dst_port": 443,
                "protocol": "TCP",
                "user": user,
                "process_name": "",
                "os_event_code": code,
                "failed_logins": int(code == 4625),
                "pkt_rate": pkt_rate,
                "raw_payload": payload,
                "true_label": label,
            }
        )

    add("GET /index.html 200", "Benign")
    add("Failed password for root from 203.0.113.8", "Brute_Force", code=4625,
        src_ip="203.0.113.8", user="root")
    for _ in range(4):
        add("Failed password for root from 203.0.113.8", "Brute_Force", code=4625,
            src_ip="203.0.113.8", user="root")
    add("UNION/**/SELECT username FROM users", "SQL_Injection")
    add("<script>alert(1)</script>", "XSS_Attack")
    add("../../../../etc/passwd", "Path_Traversal")
    add("GET /search?q=1; id", "Command_Injection")
    add("SMB ETERNALBLUE MS17-010 signature", "Malware_Exploit")
    add("powershell.exe -EncodedCommand VwByAGkAdABlAC0ASABvAHMAdAA=", "Suspicious_PowerShell")
    add("Audit log cleared by account", "Audit_Log_Tampering", code=1102)
    add("New service installed: AegisUpdate", "Service_Persistence", code=7045)
    add("GET /download/report.pdf 200", "Benign", pkt_rate=7000, src_ip="192.0.2.55")
    add("Transfer amount=-5000 account=customer-42", "Zero_Day")
    add("GET /product?id=%2527%2520UnIoN%2520SeLeCt%2520password", "SQL_Injection")
    add("UNI/**/ON SEL/**/ECT secret FROM accounts", "SQL_Injection")
    add("GET /legacy?path=../../../../etc/passwd", "Path_Traversal")
    add("powershell.exe -enc VwByAGkAdABlAC0ASABvAHMAdAA=", "Suspicious_PowerShell")
    add("POST /api/run?cmd=whoami", "Command_Injection")
    add("Successful login for operator", "Benign", code=4624, user="operator")

    for spray_user in ("alice", "bob", "carol"):
        for attempt in range(2):
            add(
                f"Failed password for {spray_user} from 203.0.113.77",
                "Password_Spraying",
                code=4625,
                src_ip="203.0.113.77",
                user=spray_user,
            )
    return events
