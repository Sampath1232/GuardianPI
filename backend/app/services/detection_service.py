"""
Guardian Pi — Detection Service
YARA-style pattern matching and heuristic anomaly scoring.
All rules are DEFENSIVE — detect threats, never exploit.
"""
from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from enum import Enum

logger = logging.getLogger("guardian.detection")


class RuleCategory(str, Enum):
    MALWARE = "malware"
    CREDENTIAL_ACCESS = "credential_access"
    PERSISTENCE = "persistence"
    DEFENSE_EVASION = "defense_evasion"
    EXECUTION = "execution"
    LATERAL_MOVEMENT = "lateral_movement"
    COLLECTION = "collection"
    C2 = "command_and_control"


@dataclass
class DetectionRule:
    """Sigma-style detection rule for process/event matching."""
    id: str
    name: str
    description: str
    severity: str  # critical | high | medium | low
    category: RuleCategory
    mitre_tactic: str
    mitre_technique: str
    # Pattern matching
    process_names: list[str] = field(default_factory=list)
    cmdline_patterns: list[str] = field(default_factory=list)
    file_patterns: list[str] = field(default_factory=list)
    network_indicators: list[str] = field(default_factory=list)


# ── Built-in Detection Rules ────────────────────────────────────

SIGMA_RULES: list[DetectionRule] = [
    DetectionRule(
        id="SIGMA-001", name="Mimikatz Credential Dumping",
        description="Detects mimikatz and related credential access tools",
        severity="critical", category=RuleCategory.CREDENTIAL_ACCESS,
        mitre_tactic="Credential Access", mitre_technique="T1003",
        process_names=["mimikatz", "sekurlsa", "kiwi"],
        cmdline_patterns=[r"sekurlsa::logonpasswords", r"lsadump::", r"privilege::debug"],
    ),
    DetectionRule(
        id="SIGMA-002", name="Reverse Shell Detection",
        description="Detects common reverse shell patterns across platforms",
        severity="critical", category=RuleCategory.EXECUTION,
        mitre_tactic="Execution", mitre_technique="T1059",
        cmdline_patterns=[
            r"/dev/tcp/\d+\.\d+\.\d+\.\d+",
            r"bash\s+-i\s+>&\s+/dev/tcp",
            r"nc\s+.*-e\s+/bin/(sh|bash)",
            r"python.*socket.*subprocess",
            r"php\s+-r.*fsockopen",
            r"ruby.*TCPSocket.*exec",
        ],
    ),
    DetectionRule(
        id="SIGMA-003", name="Brute Force Tools",
        description="Detects password cracking and brute force utilities",
        severity="high", category=RuleCategory.CREDENTIAL_ACCESS,
        mitre_tactic="Credential Access", mitre_technique="T1110",
        process_names=["hydra", "john", "hashcat", "medusa", "ncrack", "patator"],
    ),
    DetectionRule(
        id="SIGMA-004", name="Suspicious Persistence Mechanism",
        description="Detects unauthorized persistence attempts",
        severity="high", category=RuleCategory.PERSISTENCE,
        mitre_tactic="Persistence", mitre_technique="T1053",
        cmdline_patterns=[
            r"crontab\s+-e", r"schtasks\s+/create",
            r"reg\s+add.*\\Run", r"launchctl\s+load",
            r"systemctl\s+enable",
        ],
        file_patterns=[
            r"/etc/cron\.d/", r"\.bashrc$", r"\.profile$",
            r"\\Startup\\", r"LaunchAgents",
        ],
    ),
    DetectionRule(
        id="SIGMA-005", name="Encoded PowerShell Command",
        description="Detects base64-encoded PowerShell execution",
        severity="high", category=RuleCategory.DEFENSE_EVASION,
        mitre_tactic="Defense Evasion", mitre_technique="T1027",
        cmdline_patterns=[
            r"powershell.*-[eE](nc|ncodedcommand)",
            r"powershell.*[Ff]rom[Bb]ase64",
            r"powershell.*-[wW]\s+hidden",
        ],
    ),
    DetectionRule(
        id="SIGMA-006", name="Unusual Outbound Traffic",
        description="Detects connections to known C2/malicious ports",
        severity="medium", category=RuleCategory.C2,
        mitre_tactic="Command and Control", mitre_technique="T1571",
        network_indicators=["4444", "5555", "1337", "31337", "9999"],
    ),
    DetectionRule(
        id="SIGMA-007", name="Debugger/Tamper Tools",
        description="Detects debugger attachment and tampering tools",
        severity="medium", category=RuleCategory.DEFENSE_EVASION,
        mitre_tactic="Defense Evasion", mitre_technique="T1622",
        process_names=["gdb", "lldb", "strace", "ltrace", "x64dbg", "ollydbg", "windbg", "ida", "ida64"],
    ),
    DetectionRule(
        id="SIGMA-008", name="Lateral Movement Tools",
        description="Detects tools used for lateral movement",
        severity="high", category=RuleCategory.LATERAL_MOVEMENT,
        mitre_tactic="Lateral Movement", mitre_technique="T1021",
        process_names=["psexec", "wmiexec", "smbexec", "evil-winrm", "crackmapexec"],
    ),
]

# ── YARA-style string patterns ──────────────────────────────────

YARA_SIGNATURES = [
    {"name": "suspicious_shellcode", "pattern": rb"\xfc\xe8\x82\x00\x00\x00", "severity": "critical"},
    {"name": "metasploit_marker", "pattern": rb"metsrv.dll", "severity": "critical"},
    {"name": "cobalt_strike_beacon", "pattern": rb"beacon.dll", "severity": "critical"},
    {"name": "mimikatz_string", "pattern": rb"gentilkiwi", "severity": "critical"},
    {"name": "powersploit_marker", "pattern": rb"PowerSploit", "severity": "high"},
]


class DetectionEngine:
    """Runs detection rules against process data and file content."""

    def __init__(self):
        self.rules = SIGMA_RULES
        self.yara_sigs = YARA_SIGNATURES

    def match_process(self, process_name: str, cmdline: str = "") -> list[dict]:
        """Match a process against all Sigma rules. Returns list of matches."""
        matches = []
        pname_lower = process_name.lower()
        cmd_lower = cmdline.lower()

        for rule in self.rules:
            matched = False

            # Check process name patterns
            for pattern in rule.process_names:
                if pattern.lower() in pname_lower:
                    matched = True
                    break

            # Check command-line patterns
            if not matched:
                for pattern in rule.cmdline_patterns:
                    if re.search(pattern, cmd_lower, re.IGNORECASE):
                        matched = True
                        break

            if matched:
                matches.append({
                    "rule_id": rule.id,
                    "rule_name": rule.name,
                    "severity": rule.severity,
                    "category": rule.category.value,
                    "mitre_tactic": rule.mitre_tactic,
                    "mitre_technique": rule.mitre_technique,
                    "description": rule.description,
                })

        return matches

    def scan_file_content(self, content: bytes, filename: str = "") -> list[dict]:
        """Scan file content against YARA-style signatures."""
        matches = []
        for sig in self.yara_sigs:
            if sig["pattern"] in content:
                matches.append({
                    "signature": sig["name"],
                    "severity": sig["severity"],
                    "file": filename,
                })
        return matches

    def calculate_anomaly_score(self, metrics: dict) -> dict:
        """Heuristic anomaly scoring based on system metrics."""
        score = 0
        reasons = []

        cpu = metrics.get("cpu_percent", 0)
        ram = metrics.get("ram_percent", 0)
        connections = metrics.get("active_connections", 0)
        processes = metrics.get("process_count", 0)

        if cpu > 95:
            score += 30
            reasons.append(f"Extreme CPU usage: {cpu:.1f}%")
        elif cpu > 80:
            score += 15
            reasons.append(f"High CPU usage: {cpu:.1f}%")

        if ram > 95:
            score += 25
            reasons.append(f"Critical RAM usage: {ram:.1f}%")

        if connections > 500:
            score += 30
            reasons.append(f"Excessive connections: {connections}")
        elif connections > 200:
            score += 15
            reasons.append(f"High connection count: {connections}")

        if processes > 500:
            score += 10
            reasons.append(f"High process count: {processes}")

        risk_level = "critical" if score >= 60 else "high" if score >= 40 else "medium" if score >= 20 else "low"

        return {
            "anomaly_score": min(score, 100),
            "risk_level": risk_level,
            "reasons": reasons,
        }


# Singleton
detection_engine = DetectionEngine()
