"""Guardian Pi — File Integrity Monitor: SHA-256 baseline comparison."""
from __future__ import annotations
import hashlib
import json
import logging
import os
import platform
from pathlib import Path

logger = logging.getLogger("guardian.fim")

# Critical paths to monitor per OS
MONITORED_PATHS = {
    "windows": [r"C:\Windows\System32\drivers\etc\hosts", r"C:\Windows\System32\config"],
    "linux": ["/etc/passwd", "/etc/shadow", "/etc/hosts", "/etc/crontab", "/etc/ssh/sshd_config"],
    "macos": ["/etc/hosts", "/etc/passwd", "/etc/ssh/sshd_config"],
    "raspberrypi": ["/etc/passwd", "/etc/hosts", "/etc/crontab", "/boot/config.txt"],
}

BASELINE_FILE = "fim_baseline.json"

class FileIntegrityMonitor:
    def __init__(self, custom_paths: list[str] | None = None):
        os_type = platform.system().lower()
        if os_type == "darwin":
            os_type = "macos"
        self.paths = MONITORED_PATHS.get(os_type, []) + (custom_paths or [])
        self.baseline = self._load_baseline()

    def _hash_file(self, filepath: str) -> str | None:
        try:
            sha256 = hashlib.sha256()
            with open(filepath, "rb") as f:
                for chunk in iter(lambda: f.read(8192), b""):
                    sha256.update(chunk)
            return sha256.hexdigest()
        except (PermissionError, FileNotFoundError, OSError):
            return None

    def _load_baseline(self) -> dict[str, str]:
        try:
            if Path(BASELINE_FILE).exists():
                return json.loads(Path(BASELINE_FILE).read_text())
        except Exception:
            pass
        return {}

    def _save_baseline(self):
        try:
            Path(BASELINE_FILE).write_text(json.dumps(self.baseline, indent=2))
        except Exception as e:
            logger.error(f"Failed to save FIM baseline: {e}")

    def initialize_baseline(self):
        """Create initial baseline of all monitored file hashes."""
        for path in self.paths:
            h = self._hash_file(path)
            if h:
                self.baseline[path] = h
        self._save_baseline()
        logger.info(f"FIM baseline created with {len(self.baseline)} files")

    def check(self) -> list[dict]:
        """Compare current file hashes against baseline."""
        if not self.baseline:
            self.initialize_baseline()
            return []

        changes = []
        for path in self.paths:
            current_hash = self._hash_file(path)
            baseline_hash = self.baseline.get(path)

            if current_hash is None and baseline_hash:
                changes.append({"path": path, "change_type": "deleted",
                    "title": f"Monitored file deleted: {path}"})
            elif current_hash and not baseline_hash:
                self.baseline[path] = current_hash
                changes.append({"path": path, "change_type": "new",
                    "title": f"New file in monitored path: {path}"})
            elif current_hash != baseline_hash:
                changes.append({"path": path, "change_type": "modified",
                    "previous_hash": baseline_hash, "current_hash": current_hash,
                    "title": f"File modified: {path}"})
                self.baseline[path] = current_hash

        if changes:
            self._save_baseline()
        return changes
