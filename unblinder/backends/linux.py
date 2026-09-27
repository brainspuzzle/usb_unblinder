import os
import platform
import subprocess
from pathlib import Path

from ..util import make_device

SYSFS = Path("/sys/bus/usb/devices")


def _read(path):
    try:
        return path.read_text(errors="backslashreplace").strip()
    except OSError:
        return None


def _hex(path):
    v = _read(path)
    try:
        return int(v, 16) if v else None
    except ValueError:
        return None


class LinuxBackend:
    name = "Linux sysfs (/sys/bus/usb)"
    poll_interval = 0.5

    def info(self):
        return {"os": f"Linux {platform.release()} ({platform.machine()})",
                "backend": self.name, "screen_lock_detection": True}

    def snapshot(self):
        devices = {}
        for d in SYSFS.iterdir():
            # skip interfaces ("1-2:1.0") and root hubs ("usb1")
            if ":" in d.name or d.name.startswith("usb") or not (d / "idVendor").exists():
                continue
            interfaces = []
            for itf in sorted(SYSFS.glob(f"{d.name}:*")):
                interfaces.append({
                    "number": _hex(itf / "bInterfaceNumber"),
                    "class": _hex(itf / "bInterfaceClass"),
                    "subclass": _hex(itf / "bInterfaceSubClass"),
                    "protocol": _hex(itf / "bInterfaceProtocol"),
                })
            dev_id = f"{d.name}#{_read(d / 'busnum')}-{_read(d / 'devnum')}"
            speed = _read(d / "speed")
            raw = {f: _read(d / f) for f in ("bcdDevice", "bcdUSB", "bMaxPower", "bNumInterfaces",
                                            "authorized", "removable", "version") if (d / f).exists()}
            devices[dev_id] = make_device(
                id=dev_id,
                location=d.name,
                vid=_hex(d / "idVendor"),
                pid=_hex(d / "idProduct"),
                name=_read(d / "product"),
                manufacturer=_read(d / "manufacturer"),
                serial=_read(d / "serial"),
                speed=f"{speed} Mb/s" if speed else None,
                device_class=_hex(d / "bDeviceClass"),
                interfaces=interfaces,
                raw=raw,
            )
        return devices

    def screen_locked(self):
        session = os.environ.get("XDG_SESSION_ID")
        if not session:
            return None
        try:
            out = subprocess.run(["loginctl", "show-session", session, "-p", "LockedHint", "--value"],
                                 capture_output=True, text=True, timeout=3).stdout.strip()
            return {"yes": True, "no": False}.get(out)
        except Exception:
            return None
