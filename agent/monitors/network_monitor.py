"""Guardian Pi — Network Monitor: connection tracking and anomaly detection."""
from __future__ import annotations
import logging
from collections import defaultdict
import psutil

logger = logging.getLogger("guardian.network")

# Known malicious port indicators
SUSPICIOUS_PORTS = {4444, 5555, 1337, 31337, 6666, 6667, 8888, 9999, 12345, 65535}
# Common C2 ports
C2_PORTS = {443, 8443, 4443, 8080, 9090}

class NetworkMonitor:
    def __init__(self):
        self._connection_history: list[int] = []
        self._known_remote_ips: set[str] = set()
        self._history_max = 60

    def detect_anomalies(self) -> list[dict]:
        alerts = []
        try:
            connections = psutil.net_connections(kind="inet")
        except (psutil.AccessDenied, PermissionError):
            return []

        current_count = len(connections)
        self._connection_history.append(current_count)
        if len(self._connection_history) > self._history_max:
            self._connection_history.pop(0)

        # Statistical anomaly: sudden spike in connections
        if len(self._connection_history) >= 5:
            avg = sum(self._connection_history[:-1]) / len(self._connection_history[:-1])
            if current_count > avg * 3 and current_count > 50:
                alerts.append({"severity": "high",
                    "title": f"Connection spike: {current_count} (avg: {avg:.0f})",
                    "current": current_count, "average": avg})

        # Per-connection analysis
        remote_port_counts = defaultdict(int)
        new_remote_ips = set()

        for conn in connections:
            if conn.status != "ESTABLISHED" or not conn.raddr:
                continue
            remote_ip = conn.raddr.ip
            remote_port = conn.raddr.port
            local_port = conn.laddr.port if conn.laddr else 0

            # Suspicious port detection
            if local_port in SUSPICIOUS_PORTS:
                alerts.append({"severity": "high",
                    "title": f"Listening on suspicious port {local_port}",
                    "local_port": local_port, "remote_ip": remote_ip})

            # Track new remote IPs
            if remote_ip not in self._known_remote_ips:
                new_remote_ips.add(remote_ip)
                self._known_remote_ips.add(remote_ip)

            remote_port_counts[remote_port] += 1

        # Detect port scanning (many connections to different ports)
        if len(remote_port_counts) > 30:
            alerts.append({"severity": "medium",
                "title": f"Possible port scan: connections to {len(remote_port_counts)} ports",
                "port_count": len(remote_port_counts)})

        # Large number of new remote IPs
        if len(new_remote_ips) > 20:
            alerts.append({"severity": "medium",
                "title": f"Burst of new connections: {len(new_remote_ips)} new IPs",
                "new_ip_count": len(new_remote_ips)})

        return alerts
