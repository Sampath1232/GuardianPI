"""Guardian Pi — Cross-Platform Firewall Manager"""
from __future__ import annotations
import logging
import platform
import re
import subprocess

logger = logging.getLogger("guardian.firewall")


class FirewallManager:
    """Cross-platform firewall management for defensive IP blocking."""

    def __init__(self):
        self.os_type = platform.system().lower()
        self._blocked_ips: set[str] = set()

    def _validate_ip(self, ip: str) -> bool:
        pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
        if not re.match(pattern, ip):
            return False
        return all(0 <= int(octet) <= 255 for octet in ip.split('.'))

    def block_ip(self, ip: str, reason: str = "Blocked by Guardian Pi") -> dict:
        """Block an IP address using the OS-native firewall."""
        if not self._validate_ip(ip):
            return {"success": False, "error": "Invalid IP address"}
        if ip.startswith("127.") or ip.startswith("10.") or ip.startswith("192.168."):
            return {"success": False, "error": "Cannot block private/loopback IPs"}

        try:
            if self.os_type == "linux":
                subprocess.run(["sudo", "iptables", "-A", "INPUT", "-s", ip, "-j", "DROP",
                    "-m", "comment", "--comment", reason], check=True, capture_output=True, timeout=10)
            elif self.os_type == "windows":
                subprocess.run(["netsh", "advfirewall", "firewall", "add", "rule",
                    f"name=GuardianPi_Block_{ip}", "dir=in", "action=block",
                    f"remoteip={ip}"], check=True, capture_output=True, timeout=10)
            elif self.os_type == "darwin":
                # macOS pf firewall
                subprocess.run(["sudo", "pfctl", "-t", "guardian_blocked", "-T", "add", ip],
                    check=True, capture_output=True, timeout=10)
            else:
                return {"success": False, "error": f"Unsupported OS: {self.os_type}"}

            self._blocked_ips.add(ip)
            logger.info(f"Blocked IP: {ip} — {reason}")
            return {"success": True, "ip": ip, "reason": reason}
        except subprocess.CalledProcessError as e:
            return {"success": False, "error": str(e)}

    def unblock_ip(self, ip: str) -> dict:
        """Remove an IP block (rollback support)."""
        if not self._validate_ip(ip):
            return {"success": False, "error": "Invalid IP address"}
        try:
            if self.os_type == "linux":
                subprocess.run(["sudo", "iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"],
                    check=True, capture_output=True, timeout=10)
            elif self.os_type == "windows":
                subprocess.run(["netsh", "advfirewall", "firewall", "delete", "rule",
                    f"name=GuardianPi_Block_{ip}"], check=True, capture_output=True, timeout=10)
            self._blocked_ips.discard(ip)
            return {"success": True, "ip": ip}
        except subprocess.CalledProcessError as e:
            return {"success": False, "error": str(e)}
