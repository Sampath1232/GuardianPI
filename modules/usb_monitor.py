import psutil
from modules.logger import log_threat

known_devices = set()

def get_usb_devices():

    global known_devices

    devices = []

    try:
        partitions = psutil.disk_partitions(all=False)

        for partition in partitions:

            try:
                device = partition.device
                mount = partition.mountpoint
                fstype = partition.fstype
                opts = partition.opts.lower()

                # Skip internal/system partitions
                if 'fixed' in opts:
                    continue

                # Detect removable drives only
                if 'removable' not in opts and 'usb' not in opts:
                    continue

                usage = psutil.disk_usage(mount)

                device_info = {
                    "device": device,
                    "mountpoint": mount,
                    "filesystem": fstype,
                    "total_gb": round(
                        usage.total / (1024 ** 3), 2
                    ),
                    "used_percent": usage.percent,
                    "type": "USB Storage"
                }

                devices.append(device_info)

                if device not in known_devices:

                    known_devices.add(device)

                    log_threat(
                        f"USB Storage Connected: {device}"
                    )

            except Exception as e:
                print("Partition Error:", e)

    except Exception as e:

        devices.append({
            "error": str(e)
        })

    return devices