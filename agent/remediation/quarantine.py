"""Guardian Pi — Process Quarantine: safe process suspension with rollback."""
from __future__ import annotations
import logging
import platform
import psutil

logger = logging.getLogger("guardian.quarantine")

# Processes that must NEVER be quarantined (safety guardrail)
PROTECTED_PROCESSES = {
    "init", "systemd", "kernel", "launchd", "services.exe", "csrss.exe",
    "wininit.exe", "smss.exe", "lsass.exe", "svchost.exe", "explorer.exe",
    "winlogon.exe", "dwm.exe", "system", "system idle process",
}


class QuarantineManager:
    """Safely suspend suspicious processes with rollback capability."""

    def __init__(self):
        self._quarantined: dict[int, dict] = {}

    def quarantine_process(self, pid: int, reason: str = "") -> dict:
        """Suspend (not kill) a process. Returns rollback data."""
        try:
            proc = psutil.Process(pid)
            name = proc.name().lower()

            # Safety: never quarantine protected processes
            if name in PROTECTED_PROCESSES:
                return {"success": False, "error": f"Protected process: {name}"}

            # Safety: never quarantine our own agent
            if "guardian" in name:
                return {"success": False, "error": "Cannot quarantine self"}

            proc.suspend()
            rollback = {"pid": pid, "name": proc.name(), "status": "suspended"}
            self._quarantined[pid] = rollback
            logger.warning(f"Quarantined process: {proc.name()} (PID {pid}) — {reason}")
            return {"success": True, **rollback, "reason": reason}
        except psutil.NoSuchProcess:
            return {"success": False, "error": "Process not found"}
        except psutil.AccessDenied:
            return {"success": False, "error": "Access denied"}

    def release_process(self, pid: int) -> dict:
        """Resume a quarantined process (rollback)."""
        try:
            proc = psutil.Process(pid)
            proc.resume()
            self._quarantined.pop(pid, None)
            logger.info(f"Released process: {proc.name()} (PID {pid})")
            return {"success": True, "pid": pid, "name": proc.name()}
        except psutil.NoSuchProcess:
            self._quarantined.pop(pid, None)
            return {"success": False, "error": "Process no longer exists"}
        except psutil.AccessDenied:
            return {"success": False, "error": "Access denied"}

    def list_quarantined(self) -> list[dict]:
        return list(self._quarantined.values())
