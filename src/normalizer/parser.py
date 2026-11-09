"""Convert raw platform telemetry to the shared event representation."""

from __future__ import annotations

import base64
import binascii
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
import html
import re
from typing import Any
from urllib.parse import unquote


@dataclass
class NormalizedEvent:
    event_id: str
    timestamp: str
    host_name: str
    dst_ip: str
    asset_name: str
    asset_weight: float
    src_ip: str
    dst_port: int
    protocol: str
    user: str
    process_name: str
    os_event_code: int
    failed_logins: int
    pkt_rate: int
    raw_payload: str
    clean_payload: str
    true_label: str
    parent_process: str = ""
    parent_process_chain: str = ""
    process_id: int = 0
    parent_process_id: int = 0
    process_path: str = ""
    command_line: str = ""
    decoded_payload: str = ""
    anomaly_score: int = 0

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def deobfuscate_payload(payload: str) -> str:
    """Decode common URL/Base64 encodings and strip inline markup comments."""
    decoded = payload
    for _ in range(2):
        decoded = unquote(decoded)
    command = re.search(
        r"(?:-(?:e|enc(?:odedcommand)?)\s+)(['\"]?)([A-Za-z0-9+/]{8,}={0,2})\1",
        decoded,
        flags=re.IGNORECASE,
    )
    if command:
        try:
            encoded = command.group(2)
            encoded += "=" * (-len(encoded) % 4)
            decoded_bytes = base64.b64decode(encoded, validate=True)
            try:
                decoded_command = decoded_bytes.decode("utf-16le")
            except UnicodeDecodeError:
                decoded_command = decoded_bytes.decode("utf-8")
            decoded = decoded[:command.start(2)] + decoded_command + decoded[command.end(2):]
        except (binascii.Error, UnicodeDecodeError, ValueError):
            pass
    decoded = re.sub(r"/\*.*?\*/|<!--.*?-->", "", decoded, flags=re.DOTALL)
    decoded = html.unescape(decoded)
    return re.sub(r"\s+", " ", decoded).strip().upper()


def extract_decoded_payload(payload: str) -> str:
    """Return decoded PowerShell text for display without modifying the source."""
    command = re.search(
        r"(?:-(?:e|enc(?:odedcommand)?)\s+)(['\"]?)([A-Za-z0-9+/]{8,}={0,2})\1",
        payload,
        flags=re.IGNORECASE,
    )
    if not command:
        return ""
    encoded = command.group(2)
    if len(encoded) < 200:
        return ""
    try:
        decoded_bytes = base64.b64decode(encoded + "=" * (-len(encoded) % 4), validate=True)
        try:
            return decoded_bytes.decode("utf-16le").strip("\x00")
        except UnicodeDecodeError:
            return decoded_bytes.decode("utf-8").strip("\x00")
    except (binascii.Error, UnicodeDecodeError, ValueError):
        return ""


def normalize_event(
    raw: dict[str, Any],
    asset_criticality: dict[str, float] | None = None,
    default_asset: str = "workstation",
) -> NormalizedEvent:
    """Normalize a simulator, Windows, or Linux raw record."""
    asset_weights = asset_criticality or {}
    timestamp = raw.get("timestamp") or datetime.now(timezone.utc).isoformat()
    try:
        parsed_timestamp = datetime.fromisoformat(str(timestamp).replace("Z", "+00:00"))
        if parsed_timestamp.tzinfo is None:
            parsed_timestamp = parsed_timestamp.replace(tzinfo=timezone.utc)
        timestamp = parsed_timestamp.astimezone(timezone.utc).isoformat()
    except ValueError:
        timestamp = datetime.now(timezone.utc).isoformat()
    raw_payload = str(raw.get("raw_payload", raw.get("message", "")))
    command_line = str(raw.get("command_line") or "")
    detection_payload = " ".join(part for part in (raw_payload, command_line) if part)
    process_path = str(raw.get("process_path") or "")
    process_name = str(raw.get("process_name") or "")
    if not process_name and process_path:
        process_name = process_path.replace("/", "\\").rsplit("\\", 1)[-1]
    decoded_payload = str(
        raw.get("decoded_payload") or extract_decoded_payload(detection_payload)
    )
    asset_name = str(raw.get("asset_name") or default_asset)
    raw_code = raw.get("os_event_code")
    if raw_code is None:
        legacy_event_code = raw.get("event_id", 0)
        raw_code = legacy_event_code if str(legacy_event_code).isdigit() else 0
    code = int(raw_code or 0)
    failed_logins = int(raw.get("failed_logins", int(code == 4625)) or 0)
    return NormalizedEvent(
        event_id=str(raw.get("event_id") or f"{raw.get('host_name', 'host')}:{timestamp}:{code}"),
        timestamp=timestamp,
        host_name=str(raw.get("host_name") or "unknown"),
        dst_ip=str(raw.get("dst_ip") or ""),
        asset_name=asset_name,
        asset_weight=float(raw.get("asset_weight") or asset_weights.get(asset_name, 1.0)),
        src_ip=str(raw.get("src_ip") or ""),
        dst_port=int(raw.get("dst_port") or 0),
        protocol=str(raw.get("protocol") or ""),
        user=str(raw.get("user") or ""),
        process_name=process_name,
        os_event_code=code,
        failed_logins=failed_logins,
        pkt_rate=int(raw.get("pkt_rate") or 0),
        raw_payload=raw_payload,
        clean_payload=deobfuscate_payload(detection_payload),
        true_label=str(raw.get("true_label") or "Unknown"),
        parent_process=str(raw.get("parent_process") or ""),
        parent_process_chain=str(raw.get("parent_process_chain") or ""),
        process_id=int(raw.get("process_id") or 0),
        parent_process_id=int(raw.get("parent_process_id") or 0),
        process_path=process_path,
        command_line=command_line,
        decoded_payload=decoded_payload,
    )
