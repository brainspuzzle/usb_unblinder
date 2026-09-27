import platform
import plistlib
import re
import subprocess

from ..util import make_device

SPEEDS = {0: "1.5 Mb/s (low)", 1: "12 Mb/s (full)", 2: "480 Mb/s (high)",
          3: "5 Gb/s (super)", 4: "10 Gb/s (super+)", 5: "20 Gb/s (super+ 2x2)"}

# ioreg emits raw control characters inside <string> (device descriptor strings
# are attacker-controlled), which breaks the XML parser. Keep them visible as \xNN.
_BAD_XML = re.compile(rb"[\x00-\x08\x0b\x0c\x0e-\x1f]")


def _ioreg(*args):
    out = subprocess.run(["ioreg", *args, "-a", "-w0"], capture_output=True,
                         timeout=10, check=True).stdout
    out = _BAD_XML.sub(lambda m: b"\\x%02x" % m.group()[0], out)
    if not out.strip():
        return []
    data = plistlib.loads(out)
    return data if isinstance(data, list) else [data]


class MacOSBackend:
    name = "macOS IOKit registry (ioreg)"
    poll_interval = 0.5

    def info(self):
        return {"os": f"macOS {platform.mac_ver()[0]} ({platform.machine()})",
                "backend": self.name, "screen_lock_detection": True}

    def snapshot(self):
        interfaces = {}
        for itf in _ioreg("-r", "-c", "IOUSBHostInterface", "-d", "1"):
            interfaces.setdefault(itf.get("locationID"), []).append({
                "number": itf.get("bInterfaceNumber"),
                "class": itf.get("bInterfaceClass"),
                "subclass": itf.get("bInterfaceSubClass"),
                "protocol": itf.get("bInterfaceProtocol"),
            })

        devices = {}
        for n in _ioreg("-r", "-c", "IOUSBHostDevice", "-d", "1"):
            loc = n.get("locationID")
            if loc is None:
                continue
            # sessionID changes on every re-enumeration, so a fast replug on the
            # same port still shows up as remove + connect
            dev_id = f"{loc:08x}-{n.get('sessionID', 0)}"
            devices[dev_id] = make_device(
                id=dev_id,
                location=f"0x{loc:08x}",
                vid=n.get("idVendor"),
                pid=n.get("idProduct"),
                name=n.get("USB Product Name") or n.get("kUSBProductString") or n.get("IORegistryEntryName"),
                manufacturer=n.get("USB Vendor Name") or n.get("kUSBVendorString"),
                serial=n.get("USB Serial Number") or n.get("kUSBSerialNumberString"),
                speed=SPEEDS.get(n.get("Device Speed"), n.get("Device Speed")),
                device_class=n.get("bDeviceClass"),
                interfaces=sorted(interfaces.get(loc, []), key=lambda i: i["number"] or 0),
                raw={k: v for k, v in n.items() if k != "IORegistryEntryChildren"},
            )
        return devices

    def screen_locked(self):
        try:
            root = _ioreg("-n", "Root", "-d", "1")
            return bool(root[0].get("IOConsoleLocked")) if root else None
        except Exception:
            return None
