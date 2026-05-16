"""
Guardian Pi — Device Detector
Cross-platform device fingerprinting: OS, arch, RAM, CPU, root/jailbreak, VM detection.
"""

from __future__ import annotations

import os
import platform
import socket
import struct
import subprocess
from pathlib import Path

import psutil


class DeviceDetector:
    """Detects hardware, OS, and security-relevant device properties."""

    # Known VM MAC prefixes
    VM_MAC_PREFIXES = [
        "00:05:69", "00:0c:29", "00:1c:14", "00:50:56",  # VMware
        "08:00:27", "0a:00:27",  # VirtualBox
        "00:15:5d",  # Hyper-V
        "52:54:00",  # QEMU/KVM
    ]

    # Root/jailbreak indicator paths
    ROOT_INDICATORS_ANDROID = [
        "/system/app/Superuser.apk", "/system/xbin/su", "/system/bin/su",
        "/data/local/xbin/su", "/sbin/su",
    ]
    ROOT_INDICATORS_IOS = [
        "/Applications/Cydia.app", "/Library/MobileSubstrate",
        "/private/var/stash", "/usr/sbin/sshd", "/usr/bin/sshd",
    ]

    def detect(self) -> dict:
        """Perform full device detection and return device fingerprint."""
        sys_info = platform.uname()
        os_type = self._normalize_os(sys_info.system)

        return {
            "hostname": socket.gethostname(),
            "os_type": os_type,
            "os_version": platform.version(),
            "os_release": platform.release(),
            "architecture": platform.machine(),
            "cpu_model": self._get_cpu_model(),
            "cpu_cores": psutil.cpu_count(logical=False) or 1,
            "cpu_threads": psutil.cpu_count(logical=True) or 1,
            "ram_mb": round(psutil.virtual_memory().total / (1024 * 1024)),
            "storage_gb": round(self._get_total_storage() / (1024**3)),
            "is_rooted": self._check_rooted(os_type),
            "is_virtual": self._check_virtual(),
            "python_version": platform.python_version(),
            "agent_version": "1.0.0",
        }

    def _normalize_os(self, system: str) -> str:
        system_lower = system.lower()
        if system_lower == "windows":
            return "windows"
        elif system_lower == "linux":
            # Check for Raspberry Pi
            try:
                with open("/proc/cpuinfo", "r") as f:
                    if "raspberry" in f.read().lower():
                        return "raspberrypi"
            except (FileNotFoundError, PermissionError):
                pass
            return "linux"
        elif system_lower == "darwin":
            return "macos"
        return system_lower

    def _get_cpu_model(self) -> str:
        try:
            if platform.system() == "Windows":
                return platform.processor() or "Unknown"
            elif platform.system() == "Linux":
                with open("/proc/cpuinfo", "r") as f:
                    for line in f:
                        if "model name" in line:
                            return line.split(":")[1].strip()
            elif platform.system() == "Darwin":
                result = subprocess.run(
                    ["sysctl", "-n", "machdep.cpu.brand_string"],
                    capture_output=True, text=True, timeout=5,
                )
                return result.stdout.strip() or "Apple Silicon"
        except Exception:
            pass
        return "Unknown"

    def _get_total_storage(self) -> int:
        try:
            if platform.system() == "Windows":
                return psutil.disk_usage("C:\\").total
            return psutil.disk_usage("/").total
        except Exception:
            return 0

    def _check_rooted(self, os_type: str) -> bool:
        """Detect root/jailbreak indicators (non-invasive checks only)."""
        if os_type == "android":
            return any(Path(p).exists() for p in self.ROOT_INDICATORS_ANDROID)
        elif os_type == "ios":
            return any(Path(p).exists() for p in self.ROOT_INDICATORS_IOS)
        elif os_type in ("linux", "raspberrypi"):
            return os.geteuid() == 0 if hasattr(os, "geteuid") else False
        elif os_type == "windows":
            try:
                import ctypes
                return bool(ctypes.windll.shell32.IsUserAnAdmin())
            except Exception:
                return False
        return False

    def _check_virtual(self) -> bool:
        """Detect if running inside a VM or emulator."""
        # Check MAC address prefixes
        try:
            from uuid import getnode
            mac = ':'.join(f'{getnode():012x}'[i:i+2] for i in range(0, 12, 2))
            if any(mac.startswith(prefix) for prefix in self.VM_MAC_PREFIXES):
                return True
        except Exception:
            pass

        # Check for hypervisor flag in CPU info
        if platform.system() == "Linux":
            try:
                with open("/proc/cpuinfo", "r") as f:
                    content = f.read().lower()
                    if "hypervisor" in content:
                        return True
            except (FileNotFoundError, PermissionError):
                pass

        # Check for VM-specific system files
        vm_indicators = [
            "/sys/class/dmi/id/product_name",
            "/sys/class/dmi/id/sys_vendor",
        ]
        vm_strings = ["virtualbox", "vmware", "kvm", "qemu", "xen", "hyper-v"]
        for path in vm_indicators:
            try:
                with open(path, "r") as f:
                    content = f.read().lower()
                    if any(vm_str in content for vm_str in vm_strings):
                        return True
            except (FileNotFoundError, PermissionError):
                pass

        return False
