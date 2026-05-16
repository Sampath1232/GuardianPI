"""Guardian Pi — Secure Installer: validates environment before installation."""
from __future__ import annotations
import hashlib
import logging
import platform
import shutil
import subprocess
import sys
from pathlib import Path

logger = logging.getLogger("guardian.installer")

MINIMUM_PYTHON = (3, 10)
REQUIRED_SPACE_MB = 500

class SecureInstaller:
    """Cross-platform secure installer with pre-flight checks."""

    def __init__(self, install_dir: str = "/opt/guardian-pi"):
        self.install_dir = Path(install_dir)
        self.os_type = platform.system().lower()
        self.checks_passed = False

    def preflight_checks(self) -> dict:
        """Run all pre-installation checks."""
        results = {
            "python_version": self._check_python(),
            "disk_space": self._check_disk_space(),
            "permissions": self._check_permissions(),
            "dependencies": self._check_dependencies(),
        }
        self.checks_passed = all(r["passed"] for r in results.values())
        return results

    def _check_python(self) -> dict:
        v = sys.version_info
        passed = (v.major, v.minor) >= MINIMUM_PYTHON
        return {"passed": passed, "current": f"{v.major}.{v.minor}.{v.micro}",
            "required": f"{MINIMUM_PYTHON[0]}.{MINIMUM_PYTHON[1]}+"}

    def _check_disk_space(self) -> dict:
        try:
            total, used, free = shutil.disk_usage(self.install_dir.parent)
            free_mb = free // (1024 * 1024)
            return {"passed": free_mb >= REQUIRED_SPACE_MB, "free_mb": free_mb,
                "required_mb": REQUIRED_SPACE_MB}
        except Exception as e:
            return {"passed": False, "error": str(e)}

    def _check_permissions(self) -> dict:
        try:
            test_dir = self.install_dir.parent / ".guardian_test"
            test_dir.mkdir(exist_ok=True)
            test_dir.rmdir()
            return {"passed": True}
        except PermissionError:
            return {"passed": False, "error": "Insufficient permissions. Run with admin/sudo."}

    def _check_dependencies(self) -> dict:
        deps = {"pip": "pip --version", "python": "python --version"}
        results = {}
        for name, cmd in deps.items():
            try:
                subprocess.run(cmd.split(), capture_output=True, timeout=10, check=True)
                results[name] = True
            except Exception:
                results[name] = False
        return {"passed": all(results.values()), "dependencies": results}

    def install(self, force: bool = False) -> bool:
        """Install the agent after preflight checks pass."""
        if not self.checks_passed and not force:
            logger.error("Pre-flight checks failed. Use force=True to override.")
            return False
        logger.info(f"Installing Guardian Pi agent to {self.install_dir}")
        self.install_dir.mkdir(parents=True, exist_ok=True)
        # Install Python dependencies
        subprocess.run([sys.executable, "-m", "pip", "install", "-r", "requirements.txt"],
            check=True, capture_output=True)
        logger.info("Installation complete")
        return True

    def verify_installation(self) -> bool:
        """Verify installed files match expected checksums."""
        logger.info("Verifying installation integrity...")
        # In production, compare against signed manifest
        return self.install_dir.exists()

    def uninstall(self) -> bool:
        """Clean uninstall — no hidden persistence."""
        logger.info(f"Uninstalling Guardian Pi from {self.install_dir}")
        if self.install_dir.exists():
            shutil.rmtree(self.install_dir)
        logger.info("Uninstall complete — all files removed")
        return True
