"""
Guardian Pi — Security Agent Main Orchestrator
Cross-platform endpoint security agent with scheduled monitoring loops.
"""

from __future__ import annotations

import asyncio
import logging
import platform
import signal
import sys
from datetime import datetime, timezone

logger = logging.getLogger("guardian.agent")


class GuardianAgent:
    """Main agent orchestrator that coordinates all monitoring modules."""

    VERSION = "1.0.0"

    def __init__(self, server_url: str, api_key: str, device_id: str | None = None):
        self.server_url = server_url.rstrip("/")
        self.api_key = api_key
        self.device_id = device_id
        self.running = False
        self._tasks: list[asyncio.Task] = []

        # Module instances (initialized in start)
        self.device_detector = None
        self.process_monitor = None
        self.file_integrity = None
        self.network_monitor = None
        self.usb_monitor = None
        self.anti_tamper = None
        self.telemetry_sender = None

    async def start(self):
        """Start the agent and all monitoring loops."""
        logger.info(f"Guardian Pi Agent v{self.VERSION} starting on {platform.system()}")
        self.running = True

        # Import modules
        from agent.detectors.device_detector import DeviceDetector
        from agent.monitors.process_monitor import ProcessMonitor
        from agent.monitors.file_integrity import FileIntegrityMonitor
        from agent.monitors.network_monitor import NetworkMonitor
        from agent.monitors.usb_monitor import USBMonitor
        from agent.security.anti_tamper import AntiTamperEngine
        from agent.telemetry.sender import TelemetrySender

        self.device_detector = DeviceDetector()
        self.process_monitor = ProcessMonitor()
        self.file_integrity = FileIntegrityMonitor()
        self.network_monitor = NetworkMonitor()
        self.usb_monitor = USBMonitor()
        self.anti_tamper = AntiTamperEngine()
        self.telemetry_sender = TelemetrySender(self.server_url, self.api_key)

        # Register device if needed
        if not self.device_id:
            self.device_id = await self._register_device()

        # Start monitoring loops
        self._tasks = [
            asyncio.create_task(self._heartbeat_loop()),
            asyncio.create_task(self._process_monitor_loop()),
            asyncio.create_task(self._file_integrity_loop()),
            asyncio.create_task(self._network_monitor_loop()),
            asyncio.create_task(self._usb_monitor_loop()),
            asyncio.create_task(self._anti_tamper_loop()),
            asyncio.create_task(self._telemetry_flush_loop()),
        ]

        logger.info(f"Agent registered as device {self.device_id}")
        logger.info("All monitoring loops started")

        # Wait for shutdown signal
        await self._wait_for_shutdown()

    async def stop(self):
        """Gracefully stop all monitoring loops."""
        logger.info("Agent stopping...")
        self.running = False
        for task in self._tasks:
            task.cancel()
        await asyncio.gather(*self._tasks, return_exceptions=True)
        logger.info("Agent stopped")

    async def _register_device(self) -> str:
        """Register this device with the Guardian Pi server."""
        info = self.device_detector.detect()
        logger.info(f"Device info: {info['os_type']} {info['architecture']} {info['ram_mb']}MB RAM")
        # In production, POST to /api/v1/devices/register
        # For now, return a placeholder
        return info.get("hostname", "unknown-device")

    async def _heartbeat_loop(self):
        """Send periodic heartbeats to the server."""
        while self.running:
            try:
                import psutil
                heartbeat = {
                    "cpu_percent": psutil.cpu_percent(interval=0.5),
                    "ram_percent": psutil.virtual_memory().percent,
                    "disk_percent": psutil.disk_usage("/").percent if platform.system() != "Windows"
                        else psutil.disk_usage("C:\\").percent,
                    "uptime_seconds": int((datetime.now(timezone.utc) - datetime.fromtimestamp(
                        psutil.boot_time(), tz=timezone.utc)).total_seconds()),
                    "process_count": len(psutil.pids()),
                    "active_connections": len(psutil.net_connections()),
                }
                if self.telemetry_sender:
                    self.telemetry_sender.queue_event("heartbeat", "info", heartbeat)
            except Exception as e:
                logger.error(f"Heartbeat error: {e}")
            await asyncio.sleep(30)

    async def _process_monitor_loop(self):
        while self.running:
            try:
                alerts = self.process_monitor.scan()
                for alert in alerts:
                    self.telemetry_sender.queue_event("process_alert", alert["severity"], alert)
            except Exception as e:
                logger.error(f"Process monitor error: {e}")
            await asyncio.sleep(10)

    async def _file_integrity_loop(self):
        while self.running:
            try:
                changes = self.file_integrity.check()
                for change in changes:
                    self.telemetry_sender.queue_event("file_change", "high", change)
            except Exception as e:
                logger.error(f"File integrity error: {e}")
            await asyncio.sleep(60)

    async def _network_monitor_loop(self):
        while self.running:
            try:
                anomalies = self.network_monitor.detect_anomalies()
                for anomaly in anomalies:
                    self.telemetry_sender.queue_event("network_anomaly", anomaly["severity"], anomaly)
            except Exception as e:
                logger.error(f"Network monitor error: {e}")
            await asyncio.sleep(15)

    async def _usb_monitor_loop(self):
        while self.running:
            try:
                events = self.usb_monitor.check()
                for event in events:
                    self.telemetry_sender.queue_event("usb_event", "medium", event)
            except Exception as e:
                logger.error(f"USB monitor error: {e}")
            await asyncio.sleep(5)

    async def _anti_tamper_loop(self):
        while self.running:
            try:
                if not self.anti_tamper.verify_integrity():
                    self.telemetry_sender.queue_event("tamper_detected", "critical", {
                        "message": "Agent binary integrity check failed"
                    })
            except Exception as e:
                logger.error(f"Anti-tamper error: {e}")
            await asyncio.sleep(120)

    async def _telemetry_flush_loop(self):
        while self.running:
            try:
                await self.telemetry_sender.flush()
            except Exception as e:
                logger.error(f"Telemetry flush error: {e}")
            await asyncio.sleep(30)

    async def _wait_for_shutdown(self):
        stop_event = asyncio.Event()
        loop = asyncio.get_event_loop()
        if sys.platform != "win32":
            for sig in (signal.SIGTERM, signal.SIGINT):
                loop.add_signal_handler(sig, stop_event.set)
        await stop_event.wait()
        await self.stop()


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Guardian Pi Security Agent")
    parser.add_argument("--server", default="http://localhost:8000", help="Server URL")
    parser.add_argument("--api-key", required=True, help="Agent API key")
    parser.add_argument("--device-id", default=None, help="Device ID (auto-register if empty)")
    args = parser.parse_args()

    logging.basicConfig(level=logging.INFO, format="%(asctime)s | %(name)s | %(levelname)s | %(message)s")
    agent = GuardianAgent(args.server, args.api_key, args.device_id)
    asyncio.run(agent.start())
