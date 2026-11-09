"""Local indicator storage and no-key public threat-intelligence feeds."""

from __future__ import annotations

import hashlib
import ipaddress
import json
import logging
from pathlib import Path
import re
from typing import Any, Callable
from datetime import datetime, timezone
from urllib.error import HTTPError, URLError
from urllib.parse import urlparse
from urllib.request import Request, urlopen


IPSUM_URL = "https://raw.githubusercontent.com/stamparm/ipsum/master/ipsum.txt"
FEODO_URL = "https://feodotracker.abuse.ch/downloads/ipblocklist.txt"
SSLBL_URL = "https://sslbl.abuse.ch/blacklist/sslipblacklist.txt"
URLHAUS_URL = "https://urlhaus.abuse.ch/downloads/text/"
LOGGER = logging.getLogger(__name__)


class ThreatIntel:
    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self._file_hashes: dict[tuple[str, int, int], str] = {}
        self._data_cache: dict[str, Any] | None = None
        self._cache_mtime_ns: int | None = None
        self._ioc_sets: dict[str, set[str]] = {}

    def load(self) -> dict[str, Any]:
        modified_at = self.path.stat().st_mtime_ns
        if self._data_cache is not None and modified_at == self._cache_mtime_ns:
            return self._data_cache
        data = json.loads(self.path.read_text(encoding="utf-8"))
        for key in ("ip_addresses", "domains", "sha256", "services", "commands"):
            if not isinstance(data.get(key), list):
                raise ValueError(f"Threat intel field {key!r} must be a list.")
        self._data_cache = data
        self._cache_mtime_ns = modified_at
        self._ioc_sets = {
            key: {str(value).lower() for value in data[key]}
            for key in ("ip_addresses", "domains", "sha256", "services", "commands")
        }
        return data

    def update_feeds(self, timeout: int = 60) -> dict[str, Any]:
        def download(url: str) -> str:
            request = Request(url, headers={"User-Agent": "AegisAI-XDR/1.0"})
            try:
                with urlopen(request, timeout=timeout) as response:
                    return response.read(8_000_000).decode("utf-8", errors="replace")
            except HTTPError as error:
                raise RuntimeError(f"HTTP {error.code}") from error
            except TimeoutError as error:
                raise RuntimeError(f"timed out after {timeout} seconds") from error
            except URLError as error:
                raise RuntimeError(f"connection failed: {error.reason}") from error

        skipped: list[str] = []
        successful: list[str] = []

        def fetch(
            name: str, url: str, parser: Callable[[str], set[str]]
        ) -> set[str] | None:
            try:
                values = parser(download(url))
            except (RuntimeError, OSError, ValueError) as error:
                skipped.append(name)
                LOGGER.warning("Feed skipped: %s (%s)", name, error)
                return None
            successful.append(url)
            return values

        ipsum_ips = fetch("IPsum", IPSUM_URL, parse_ipsum)
        feodo_ips = fetch("Feodo Tracker", FEODO_URL, parse_ip_list)
        sslbl_ips = fetch("SSLBL", SSLBL_URL, parse_ip_list)
        urlhaus_iocs = fetch("URLhaus", URLHAUS_URL, parse_urlhaus)

        data = self.load()
        feeds = data.setdefault("feed_iocs", {})
        if ipsum_ips is not None:
            feeds["ipsum_ips"] = sorted(ipsum_ips)
        if feodo_ips is not None:
            feeds["feodo_ips"] = sorted(feodo_ips)
        if sslbl_ips is not None:
            feeds["sslbl_ips"] = sorted(sslbl_ips)
        if urlhaus_iocs is not None:
            domains, addresses = split_iocs(urlhaus_iocs)
            feeds["urlhaus_domains"] = sorted(domains)
            feeds["urlhaus_ips"] = sorted(addresses)

        manual = data.setdefault(
            "manual_iocs",
            {
                "ip_addresses": data["ip_addresses"],
                "domains": data["domains"],
                "sha256": data["sha256"],
            },
        )
        data["ip_addresses"] = sorted(
            set(manual["ip_addresses"])
            | set(feeds.get("ipsum_ips", []))
            | set(feeds.get("feodo_ips", []))
            | set(feeds.get("sslbl_ips", []))
            | set(feeds.get("urlhaus_ips", []))
        )
        data["domains"] = sorted(
            set(manual["domains"]) | set(feeds.get("urlhaus_domains", []))
        )
        data["sha256"] = sorted(set(manual["sha256"]))
        data["updated_from"] = successful
        data["skipped_feeds"] = skipped
        feed_indicators = set().union(
            *(
                set(feeds.get(name, []))
                for name in (
                "ipsum_ips",
                "feodo_ips",
                "sslbl_ips",
                "urlhaus_domains",
                "urlhaus_ips",
            )
            )
        )
        data["feed_entries_added"] = len(feed_indicators)
        data["updated_at"] = datetime.now(timezone.utc).isoformat()
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.write_text(json.dumps(data, indent=2), encoding="utf-8")
        self._data_cache = None
        self._cache_mtime_ns = None
        self._ioc_sets = {}
        return {
            "added": data["feed_entries_added"],
            "feeds": successful,
            "skipped": skipped,
            "total": len(data["ip_addresses"]) + len(data["domains"]),
            "ips": len(data["ip_addresses"]),
            "domains": len(data["domains"]),
        }

    def counts(self) -> dict[str, int]:
        data = self.load()
        return {"ips": len(data["ip_addresses"]), "domains": len(data["domains"])}

    def match_event(self, event: Any) -> list[str]:
        data = self.load()
        matches: list[str] = []
        address = str(getattr(event, "src_ip", "") or "")
        if address.lower() in self._ioc_sets["ip_addresses"]:
            matches.append(f"Known threat IP: {address}")
        payload = str(getattr(event, "clean_payload", "") or "").lower()
        if any(domain in payload for domain in self._ioc_sets["domains"]):
            matches.append("Known threat domain")
        if any(name in payload for name in self._ioc_sets["services"]):
            matches.append("Known threat service")
        if any(command in payload for command in self._ioc_sets["commands"]):
            matches.append("Threat command indicator")
        binary_path = str(getattr(event, "process_path", "") or "")
        if binary_path and data["sha256"] and Path(binary_path).is_file():
            try:
                stat = Path(binary_path).stat()
                if stat.st_size <= 512 * 1024 * 1024:
                    cache_key = (str(Path(binary_path).resolve()), stat.st_size, stat.st_mtime_ns)
                    digest = self._file_hashes.get(cache_key)
                    if digest is None:
                        hasher = hashlib.sha256()
                        with Path(binary_path).open("rb") as binary:
                            for block in iter(lambda: binary.read(1024 * 1024), b""):
                                hasher.update(block)
                        digest = hasher.hexdigest()
                        self._file_hashes[cache_key] = digest
                    if digest in data["sha256"]:
                        matches.append(f"Known malware SHA-256: {digest}")
            except OSError:
                LOGGER.warning("Unable to hash process image %s.", binary_path, exc_info=True)
        return matches


def parse_ipsum(content: str) -> set[str]:
    addresses: set[str] = set()
    for line in content.splitlines():
        if not line or line.startswith("#"):
            continue
        fields = line.split()
        if len(fields) < 2:
            continue
        try:
            address = ipaddress.ip_address(fields[0])
            confidence = int(fields[1])
        except ValueError:
            continue
        if address.is_global and confidence >= 3:
            addresses.add(str(address))
    return addresses


def parse_ip_list(content: str) -> set[str]:
    addresses: set[str] = set()
    for line in content.splitlines():
        if not line or line.lstrip().startswith(("#", ";")):
            continue
        for candidate in re.findall(r"(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?::\d+)?", line):
            host = candidate.rsplit(":", 1)[0] if ":" in candidate else candidate
            try:
                address = ipaddress.ip_address(host)
            except ValueError:
                continue
            if address.is_global:
                addresses.add(str(address))
    return addresses


def parse_urlhaus(content: str) -> set[str]:
    indicators: set[str] = set()
    for line in content.splitlines():
        if not line or line.lstrip().startswith(("#", ";")):
            continue
        for value in re.findall(r"https?://[^\s,\"']+", line, re.IGNORECASE):
            host = (urlparse(value.rstrip(");")).hostname or "").lower().rstrip(".")
            if not host:
                continue
            try:
                address = ipaddress.ip_address(host)
            except ValueError:
                if valid_indicator_domain(host):
                    indicators.add(host)
            else:
                if address.is_global:
                    indicators.add(str(address))
    return indicators


def split_iocs(values: set[str]) -> tuple[set[str], set[str]]:
    domains: set[str] = set()
    addresses: set[str] = set()
    for value in values:
        try:
            ipaddress.ip_address(value)
        except ValueError:
            domains.add(value)
        else:
            addresses.add(value)
    return domains, addresses


def valid_indicator_domain(value: str) -> bool:
    return bool(re.fullmatch(r"(?=.{1,253}$)[a-z0-9.-]+", value, re.IGNORECASE))
