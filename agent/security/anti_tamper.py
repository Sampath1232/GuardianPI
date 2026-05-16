"""Guardian Pi — Anti-Tamper Engine: binary integrity, debugger detection, self-checks."""
from __future__ import annotations
import hashlib
import logging
import os
import platform
import sys

logger = logging.getLogger("guardian.antitamper")

class AntiTamperEngine:
    def __init__(self):
        self._binary_hash = self._compute_self_hash()
        self._integrity_verified = True

    def _compute_self_hash(self) -> str | None:
        """Compute SHA-256 hash of the agent's own binary/script."""
        try:
            agent_path = os.path.abspath(sys.argv[0])
            sha256 = hashlib.sha256()
            with open(agent_path, "rb") as f:
                for chunk in iter(lambda: f.read(8192), b""):
                    sha256.update(chunk)
            return sha256.hexdigest()
        except Exception:
            return None

    def verify_integrity(self) -> bool:
        """Verify agent binary hasn't been modified."""
        if not self._binary_hash:
            return True
        current = self._compute_self_hash()
        if current != self._binary_hash:
            logger.critical("TAMPER DETECTED: Agent binary hash mismatch!")
            self._integrity_verified = False
            return False
        return True

    def detect_debugger(self) -> bool:
        """Detect if a debugger is attached (non-invasive)."""
        system = platform.system()
        if system == "Linux":
            try:
                with open("/proc/self/status", "r") as f:
                    for line in f:
                        if line.startswith("TracerPid:"):
                            tracer = int(line.split(":")[1].strip())
                            if tracer != 0:
                                logger.warning(f"Debugger detected: TracerPid={tracer}")
                                return True
            except (FileNotFoundError, PermissionError):
                pass
        elif system == "Windows":
            try:
                import ctypes
                if ctypes.windll.kernel32.IsDebuggerPresent():
                    logger.warning("Debugger detected via IsDebuggerPresent")
                    return True
            except Exception:
                pass
        return False

    def check_all(self) -> dict:
        """Run all anti-tamper checks."""
        return {
            "binary_integrity": self.verify_integrity(),
            "debugger_detected": self.detect_debugger(),
            "overall_status": "secure" if self.verify_integrity() and not self.detect_debugger() else "compromised",
        }
