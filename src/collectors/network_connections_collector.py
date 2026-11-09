"""Read-only active network connection collector with a netstat fallback."""

from __future__ import annotations

from datetime import datetime, timezone
import ipaddress
import logging
import re
import socket
import subprocess
from typing import Any


LOGGER = logging.getLogger(__name__)


class NetworkConnectionsCollector:
    def collect(self, limit: int = 250) -> list[dict[str, Any]]:
        if limit < 1:
            return []
        try:
            return self._collect_psutil(limit)
        except RuntimeError as error:
            LOGGER.warning("psutil connection collection failed; falling back to netstat: %s", error)
        except ImportError:
            LOGGER.warning("psutil unavailable; falling back to netstat.")
        except (OSError, PermissionError) as error:
            LOGGER.warning("psutil connection collection failed; falling back to netstat: %s", error)
        return self._collect_netstat(limit)

    def _collect_psutil(self, limit: int) -> list[dict[str, Any]]:
        import psutil

        try:
            connections = psutil.net_connections(kind="inet")
        except psutil.Error as error:
            raise RuntimeError(f"psutil could not read network connections: {error}") from error
        records: list[dict[str, Any]] = []
        for connection in connections:
            remote = connection.raddr
            if not remote or not getattr(remote, "ip", None):
                continue
            remote_ip = str(remote.ip)
            if self._is_local(remote_ip):
                continue
            pid = int(connection.pid or 0)
            process_name = ""
            process_path = ""
            if pid:
                try:
                    process = psutil.Process(pid)
                    process_name = process.name()
                    try:
                        process_path = process.exe()
                    except psutil.Error:
                        pass
                except psutil.Error:
                    LOGGER.debug("Process details unavailable for PID %s.", pid)
            records.append(
                self._record(
                    remote_ip,
                    int(remote.port),
                    pid,
                    process_name,
                    process_path,
                    self._protocol(connection.type),
                )
            )
            if len(records) >= limit:
                break
        return self._deduplicate(records)

    def _collect_netstat(self, limit: int) -> list[dict[str, Any]]:
        result = subprocess.run(
            ["netstat", "-ano"],
            check=False,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=30,
        )
        if result.returncode:
            detail = result.stderr.strip() or "netstat returned a non-zero status."
            raise RuntimeError(f"Network connection collection failed: {detail}")
        process_names: dict[int, tuple[str, str]] = {}
        try:
            import psutil

            for process in psutil.process_iter(["pid", "name", "exe"]):
                info = process.info
                process_names[int(info["pid"])] = (
                    str(info.get("name") or ""),
                    str(info.get("exe") or ""),
                )
        except ImportError:
            pass
        records: list[dict[str, Any]] = []
        for line in result.stdout.splitlines():
            fields = line.split()
            if len(fields) < 4 or fields[0].upper() not in {"TCP", "UDP"}:
                continue
            remote_ip, remote_port = self._split_address(fields[2])
            if not remote_ip or self._is_local(remote_ip):
                continue
            try:
                pid = int(fields[-1])
            except ValueError:
                pid = 0
            process_name, process_path = process_names.get(pid, ("", ""))
            records.append(
                self._record(
                    remote_ip,
                    remote_port,
                    pid,
                    process_name,
                    process_path,
                    fields[0].upper(),
                )
            )
            if len(records) >= limit:
                break
        return self._deduplicate(records)

    @staticmethod
    def _record(
        remote_ip: str,
        remote_port: int,
        pid: int,
        process_name: str,
        process_path: str,
        protocol: str,
    ) -> dict[str, Any]:
        identity = f"{protocol}|{remote_ip}|{remote_port}|{pid}"
        return {
            "event_id": f"network:{identity}",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "host_name": socket.gethostname(),
            "collector_type": "network",
            "detection_type": "Network Connection",
            "mitre_technique": "",
            "event_severity": "Benign",
            "src_ip": remote_ip,
            "dst_ip": remote_ip,
            "dst_port": remote_port,
            "protocol": protocol,
            "process_id": pid,
            "process_name": process_name,
            "process_path": process_path,
            "raw_payload": (
                f"Remote connection: {remote_ip}:{remote_port} "
                f"({protocol}), process {process_name or 'unknown'} (PID {pid})"
            ),
        }

    @staticmethod
    def _split_address(value: str) -> tuple[str, int]:
        value = value.strip()
        if value.startswith("[") and "]:" in value:
            address, port = value[1:].rsplit("]:", 1)
        elif value.count(":") == 1:
            address, port = value.rsplit(":", 1)
        else:
            return "", 0
        address = address.split("%", 1)[0]
        try:
            return address, int(port)
        except ValueError:
            return "", 0

    @staticmethod
    def _is_local(address: str) -> bool:
        try:
            parsed = ipaddress.ip_address(address)
            return parsed.is_unspecified or parsed.is_loopback
        except ValueError:
            return True

    @staticmethod
    def _protocol(connection_type: int) -> str:
        return "TCP" if connection_type == socket.SOCK_STREAM else "UDP"

    @staticmethod
    def _deduplicate(records: list[dict[str, Any]]) -> list[dict[str, Any]]:
        unique: dict[str, dict[str, Any]] = {}
        for record in records:
            unique[record["event_id"]] = record
        return list(unique.values())
