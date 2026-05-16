"""Guardian Pi — USB Monitor: removable device tracking and alerting."""
from __future__ import annotations
import logging
import psutil

logger = logging.getLogger("guardian.usb")

class USBMonitor:
    def __init__(self):
        self._known_devices: set[str] = set()
        self._initialize()

    def _initialize(self):
        for p in psutil.disk_partitions(all=False):
            if "removable" in p.opts.lower():
                self._known_devices.add(p.device)

    def check(self) -> list[dict]:
        events = []
        current = set()
        for p in psutil.disk_partitions(all=False):
            opts = p.opts.lower()
            if "fixed" in opts:
                continue
            if "removable" not in opts and "usb" not in opts:
                continue
            current.add(p.device)
            if p.device not in self._known_devices:
                try:
                    usage = psutil.disk_usage(p.mountpoint)
                    events.append({"event": "usb_connected", "device": p.device,
                        "mountpoint": p.mountpoint, "filesystem": p.fstype,
                        "total_gb": round(usage.total / (1024**3), 2),
                        "title": f"USB connected: {p.device}"})
                except Exception:
                    events.append({"event": "usb_connected", "device": p.device,
                        "title": f"USB connected: {p.device}"})

        # Detect disconnections
        for dev in self._known_devices - current:
            events.append({"event": "usb_disconnected", "device": dev,
                "title": f"USB disconnected: {dev}"})

        self._known_devices = current
        return events
