"""Guardian Pi — Process Monitor: behavioral analysis of running processes."""
from __future__ import annotations
import logging
import psutil

logger = logging.getLogger("guardian.process")

# Suspicious process names and behavioral patterns
SUSPICIOUS_PROCESSES = {
    "hydra": "Brute-force attack tool", "nmap": "Network scanner",
    "netcat": "Network utility (potential backdoor)", "nc": "Netcat variant",
    "john": "Password cracker", "hashcat": "Password cracker",
    "mimikatz": "Credential dumper", "meterpreter": "Exploitation framework",
    "cobalt": "C2 framework indicator", "empire": "Post-exploitation framework",
    "lazagne": "Credential recovery tool", "responder": "LLMNR/NBT-NS poisoner",
}

class ProcessMonitor:
    def __init__(self):
        self._baseline_pids: set[int] = set()
        self._initialize_baseline()

    def _initialize_baseline(self):
        for proc in psutil.process_iter(["pid"]):
            try:
                self._baseline_pids.add(proc.info["pid"])
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass

    def scan(self) -> list[dict]:
        alerts = []
        for proc in psutil.process_iter(["pid", "name", "username", "cpu_percent", "memory_percent", "connections"]):
            try:
                info = proc.info
                name = (info.get("name") or "").lower()

                # Check against suspicious process list
                for bad_name, description in SUSPICIOUS_PROCESSES.items():
                    if bad_name in name:
                        alerts.append({
                            "severity": "high",
                            "title": f"Suspicious process: {info['name']}",
                            "pid": info["pid"], "process_name": info["name"],
                            "username": info.get("username"),
                            "description": description,
                        })

                # Detect high resource usage (potential crypto-miner)
                cpu = info.get("cpu_percent", 0) or 0
                if cpu > 90:
                    alerts.append({
                        "severity": "medium",
                        "title": f"High CPU usage: {info['name']} ({cpu}%)",
                        "pid": info["pid"], "process_name": info["name"],
                        "cpu_percent": cpu,
                    })

                # Detect new processes not in baseline
                if info["pid"] not in self._baseline_pids:
                    self._baseline_pids.add(info["pid"])
                    connections = info.get("connections") or []
                    if len(connections) > 20:
                        alerts.append({
                            "severity": "medium",
                            "title": f"New process with many connections: {info['name']}",
                            "pid": info["pid"], "connection_count": len(connections),
                        })
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                pass
        return alerts
