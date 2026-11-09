from pathlib import Path
import hashlib
import io
import json
import socket
import sys
from types import SimpleNamespace
from unittest.mock import Mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from src.collectors.attack_simulator import generate_events
from src.engine.atomic_engine import AtomicEngine
from src.engine.behavioral_engine import BehavioralEngine
from src.engine.correlation_engine import CorrelationEngine
from src.engine.evaluation import evaluate_predictions
from src.normalizer.parser import deobfuscate_payload, normalize_event
from src.storage.baseline import BaselineStore
from src.engine.threat_intel import ThreatIntel
from src.collectors.network_connections_collector import NetworkConnectionsCollector
from src.collectors.windows_security_collector import WindowsSecurityEventCollector


ROOT = Path(__file__).resolve().parents[1]


def test_deobfuscates_double_url_encoding_and_inline_comments():
    assert "UNION SELECT" in deobfuscate_payload("%2527%2520UnIoN%2520SeLeCt")
    assert "UNION SELECT" in deobfuscate_payload("UNI/**/ON SEL/**/ECT")


def test_decodes_encoded_powershell_command():
    assert "WRITE-HOST" in deobfuscate_payload(
        "powershell.exe -enc VwByAGkAdABlAC0ASABvAHMAdAA="
    )


def test_atomic_rules_cover_required_attack_families():
    engine = AtomicEngine(ROOT / "config" / "rules" / "sigma_host_network.yaml")
    sample_events = generate_events()
    expected = {
        "SQL_Injection", "XSS_Attack", "Path_Traversal", "Command_Injection",
        "Malware_Exploit", "Suspicious_PowerShell", "Audit_Log_Tampering",
        "Service_Persistence",
    }
    detected = {
        alert["rule_id"]
        for raw in sample_events
        for alert in engine.classify(normalize_event(raw))
    }
    assert expected <= detected


def test_correlates_password_spray_and_tunes_static_traffic():
    engine = CorrelationEngine(window_seconds=300, static_traffic_tuning=True)
    sample_events = generate_events()
    alerts = []
    for raw in sample_events:
        alerts.extend(engine.process(normalize_event(raw)))
    assert any(alert["rule_id"] == "Password_Spraying" for alert in alerts)
    assert any(alert["rule_id"] == "Traffic_Spike_Warning" for alert in alerts)
    assert not any(alert["rule_id"] == "DDoS_SYN_Flood" for alert in alerts)


def test_correlates_single_account_brute_force():
    engine = CorrelationEngine(window_seconds=300)
    sample_events = generate_events()
    alerts = [
        alert
        for raw in sample_events
        for alert in engine.process(normalize_event(raw))
    ]
    assert any(alert["rule_id"] == "Single_Account_Brute_Force" for alert in alerts)


def test_matches_command_injection_in_request_parameter():
    engine = AtomicEngine(ROOT / "config" / "rules" / "sigma_host_network.yaml")
    raw = next(event for event in generate_events() if "cmd=whoami" in event["raw_payload"])
    assert any(
        alert["rule_id"] == "Command_Injection"
        for alert in engine.classify(normalize_event(raw))
    )


def test_evaluation_stream_contains_zero_day_false_negative():
    engine = AtomicEngine(ROOT / "config" / "rules" / "sigma_host_network.yaml")
    zero_day = next(event for event in generate_events() if event["true_label"] == "Zero_Day")
    assert engine.classify(normalize_event(zero_day)) == []


def test_normalized_shape_and_risk_fields():
    event = normalize_event({"raw_payload": "hello", "asset_name": "domain_controller"},
                            {"domain_controller": 2.0})
    assert event.asset_weight == 2.0
    assert event.clean_payload == "HELLO"
    assert set(event.to_dict()) == {
        "event_id", "timestamp", "host_name", "dst_ip", "asset_name", "asset_weight",
        "src_ip", "dst_port", "protocol", "user", "process_name", "os_event_code",
        "failed_logins", "pkt_rate", "raw_payload", "clean_payload", "true_label",
        "parent_process", "parent_process_chain", "process_id", "parent_process_id",
        "process_path", "command_line", "decoded_payload", "anomaly_score",
        "detection_type", "mitre_technique", "mitre_tactic", "event_severity",
    }


def test_windows_security_collector_enriches_auth_and_process_events(monkeypatch):
    records = [
        {
            "event_id": "Security:1",
            "timestamp": "2026-11-09T12:00:00+00:00",
            "os_event_code": event_id,
            "user": "analyst",
            "src_ip": "198.51.100.10",
        }
        for event_id in (4625, 4624, 4688)
    ]
    monkeypatch.setattr(
        "src.collectors.windows_security_collector.platform.system",
        lambda: "Windows",
    )
    monkeypatch.setattr(
        "src.collectors.windows_security_collector.subprocess.run",
        Mock(return_value=SimpleNamespace(
            returncode=0,
            stdout=json.dumps(records),
            stderr="",
        )),
    )

    collected = WindowsSecurityEventCollector().collect()

    assert [event["detection_type"] for event in collected] == [
        "Failed Login - Brute Force",
        "Successful Login",
        "Process Creation",
    ]
    assert collected[0]["src_ip"] == "198.51.100.10"
    assert collected[0]["user"] == "analyst"
    assert collected[0]["mitre_technique"] == "T1110 - Brute Force"
    assert collected[1]["mitre_technique"] == "T1078 - Valid Accounts"
    assert collected[2]["mitre_technique"].startswith("T1059")


def test_network_collector_captures_remote_ip_port_and_process(monkeypatch):
    import psutil

    connection = SimpleNamespace(
        raddr=SimpleNamespace(ip="198.51.100.20", port=443),
        pid=123,
        type=socket.SOCK_STREAM,
    )
    process = SimpleNamespace(name=lambda: "browser.exe", exe=lambda: r"C:\browser.exe")
    monkeypatch.setattr(psutil, "net_connections", lambda kind: [connection])
    monkeypatch.setattr(psutil, "Process", lambda pid: process)

    events = NetworkConnectionsCollector().collect()

    assert len(events) == 1
    assert events[0]["src_ip"] == "198.51.100.20"
    assert events[0]["dst_port"] == 443
    assert events[0]["process_name"] == "browser.exe"
    assert events[0]["collector_type"] == "network"


def test_network_ioc_is_promoted_to_critical_c2_alert(monkeypatch):
    import main

    class MatchingIntel:
        def __init__(self, _path):
            pass

        def match_event(self, event):
            return ["Known threat IP: 198.51.100.20"] if event.src_ip else []

    monkeypatch.setattr(main, "ThreatIntel", MatchingIntel)
    raw_event = {
        "event_id": "network:TCP|198.51.100.20|443|123",
        "collector_type": "network",
        "src_ip": "198.51.100.20",
        "dst_ip": "198.51.100.20",
        "dst_port": 443,
        "process_name": "browser.exe",
        "raw_payload": "remote connection",
    }

    events, alerts = main.run_pipeline([raw_event], main.load_settings())

    assert events[0].detection_type == "Malicious IP - C2"
    assert events[0].event_severity == "Critical"
    assert any(
        alert["rule_id"] == "Malicious_IP_C2"
        and alert["severity"] == "Critical"
        and alert["title"] == "Malicious IP - C2"
        for alert in alerts
    )


def test_stable_string_event_identifier_is_not_parsed_as_event_code():
    event = normalize_event(
        {"event_id": "Security:2026-11-09T12:00:00Z:42", "raw_payload": "event"}
    )
    assert event.event_id == "Security:2026-11-09T12:00:00Z:42"
    assert event.os_event_code == 0


def test_4104_requires_suspicious_content_and_never_uses_sqli_rule():
    engine = AtomicEngine(ROOT / "config" / "rules" / "sigma_host_network.yaml")
    benign = normalize_event(
        {"os_event_code": 4104, "raw_payload": "Write-Output 'UNION SELECT benign text'"}
    )
    assert engine.classify(benign) == []
    suspicious = normalize_event(
        {"os_event_code": 4104, "raw_payload": "FromBase64String($payload)"}
    )
    assert [alert["rule_id"] for alert in engine.classify(suspicious)] == [
        "Suspicious_PowerShell"
    ]


def test_behavior_engine_detects_office_parent_and_full_process_chain():
    engine = BehavioralEngine()
    office_child = normalize_event(
        {
            "process_name": "powershell.exe",
            "parent_process": "C:\\Program Files\\Microsoft Office\\WINWORD.EXE",
            "process_path": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        }
    )
    alert = engine.classify(office_child)[0]
    assert alert["severity"] == "Critical"
    assert alert["title"] == "Office spawned PowerShell"

    chain = normalize_event(
        {
            "process_name": "rundll32.exe",
            "parent_process": "certutil.exe",
            "parent_process_chain": "winword.exe -> powershell.exe -> certutil.exe",
        }
    )
    assert any(
        alert["title"] == "Confirmed multi-stage process chain"
        and alert["risk_score"] == 100
        for alert in engine.classify(chain)
    )


def test_project_interpreter_is_whitelisted_and_new_process_is_not_an_alert():
    engine = AtomicEngine(ROOT / "config" / "rules" / "sigma_host_network.yaml")
    project_event = normalize_event(
        {
            "process_name": "powershell.exe",
            "process_path": r"D:\Antygravtiy\venv\Scripts\powershell.exe",
            "raw_payload": "powershell.exe -enc suspicious",
        }
    )
    assert engine.classify(project_event) == []
    behavioral = BehavioralEngine()
    new_process = normalize_event({"process_name": "first-run-tool.exe"})
    assert new_process.anomaly_score == 0
    assert behavioral.classify(new_process) == []
    assert new_process.anomaly_score == 70


def test_isolation_forest_trains_from_history_and_returns_bounded_score():
    history = [
        {
            "timestamp": f"2026-11-{day:02d}T{hour:02d}:00:00+00:00",
            "process_name": "explorer.exe",
            "process_path": r"C:\Windows\explorer.exe",
        }
        for day in range(3, 10)
        for hour in range(4)
    ]
    engine = BehavioralEngine(history)
    assert engine.model is not None
    assert engine.training_days == 7
    assert BehavioralEngine(history[:24]).model is None
    event = normalize_event(
        {
            "timestamp": "2026-11-09T09:30:00+00:00",
            "process_name": "explorer.exe",
            "process_path": r"C:\Windows\explorer.exe",
        }
    )
    assert 0 <= engine.anomaly_score(event) <= 100


def test_decoded_long_payload_is_available_separately():
    import base64

    original = "Write-Host " + ("A" * 140)
    encoded = base64.b64encode(original.encode("utf-16le")).decode("ascii")
    event = normalize_event({"command_line": f"powershell.exe -enc {encoded}"})
    assert event.decoded_payload == original


def test_baseline_reports_only_new_names_and_updates_after_comparison(tmp_path):
    store = BaselineStore(tmp_path / "baseline.json")
    first = {"processes": ["one.exe"], "services": ["svc"], "users": ["analyst"]}
    assert store.compare(first) == {"processes": [], "services": [], "users": []}
    current = {
        "processes": ["one.exe", "two.exe"],
        "services": ["svc", "new-svc"],
        "users": ["analyst", "operator"],
    }
    assert store.compare(current) == {
        "processes": ["two.exe"],
        "services": ["new-svc"],
        "users": ["operator"],
    }
    assert store.compare(current) == {"processes": [], "services": [], "users": []}


def test_baseline_service_scope_migration_does_not_flag_stopped_services(tmp_path):
    store = BaselineStore(tmp_path / "baseline.json")
    store.capture({"services": ["AppXSvc"], "service_scope": "running"})
    assert store.compare(
        {"services": ["AppXSvc", "ClipSVC"], "service_scope": "all"}
    )["services"] == []
    assert store.compare(
        {"services": ["AppXSvc", "ClipSVC", "NewService"], "service_scope": "all"}
    )["services"] == ["NewService"]


def test_threat_intel_matches_local_sha256(tmp_path):
    binary = tmp_path / "sample.bin"
    binary.write_bytes(b"test executable bytes")
    digest = hashlib.sha256(binary.read_bytes()).hexdigest()
    indicators = tmp_path / "threat_intel.json"
    indicators.write_text(
        json.dumps(
            {
                "ip_addresses": [],
                "domains": [],
                "sha256": [digest],
                "services": [],
                "commands": [],
            }
        ),
        encoding="utf-8",
    )
    event = normalize_event({"process_path": str(binary)})
    assert ThreatIntel(indicators).match_event(event) == [
        f"Known malware SHA-256: {digest}"
    ]


def test_threat_intel_public_feed_refresh_is_confidence_filtered(tmp_path, monkeypatch):
    indicators = tmp_path / "threat_intel.json"
    indicators.write_text(
        json.dumps(
            {
                "ip_addresses": [],
                "domains": [],
                "sha256": [],
                "services": [],
                "commands": [],
            }
        ),
        encoding="utf-8",
    )
    monkeypatch.setattr(
        "src.engine.threat_intel.urlopen",
        Mock(
            side_effect=[
                io.BytesIO(b"# IPsum Threat Intelligence Feed\n1.1.1.1\t3\n8.8.8.8\t2\n"),
                io.BytesIO(b"# Feodo Tracker\n2.2.2.2:443\n"),
                io.BytesIO(b"# SSLBL\n3.3.3.3\n"),
                io.BytesIO(b"# URLhaus\nhttps://bad.example/payload\n"),
            ]
        ),
    )
    result = ThreatIntel(indicators).update_feeds()
    refreshed = json.loads(indicators.read_text(encoding="utf-8"))
    assert result["added"] == 4
    assert refreshed["ip_addresses"] == ["1.1.1.1", "2.2.2.2", "3.3.3.3"]
    assert refreshed["domains"] == ["bad.example"]
    assert result["skipped"] == []


def test_scientific_evaluation_accuracy_exceeds_95_percent():
    from main import load_settings, run_pipeline

    events, alerts = run_pipeline(generate_events(), load_settings())
    assert evaluate_predictions(events, alerts)["accuracy"] > 0.95
