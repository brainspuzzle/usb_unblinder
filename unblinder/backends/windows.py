import json
import platform
import re
import subprocess

from ..util import make_device

_PS = ("Get-CimInstance Win32_PnPEntity | Where-Object { $_.PNPDeviceID -match 'VID_[0-9A-F]{4}' } | "
       "Select-Object PNPDeviceID,Name,Manufacturer,PNPClass,Service | ConvertTo-Json -Compress")
_ID = re.compile(r"VID_([0-9A-F]{4})&PID_([0-9A-F]{4})", re.I)

# Windows reports interface roles as separate PnP children; map them to USB class triples
_CLASS_HINTS = {
    "keyboard": (3, 1, 1), "mouse": (3, 1, 2), "hidclass": (3, 0, 0),
    "diskdrive": (8, 6, 80), "net": (2, 6, 0), "ports": (2, 2, 0),
    "media": (1, 0, 0), "camera": (14, 0, 0), "image": (14, 0, 0),
    "bluetooth": (0xE0, 1, 1), "printer": (7, 1, 2), "smartcardreader": (0x0B, 0, 0),
}


class WindowsBackend:
    name = "Windows PnP (PowerShell CIM) - experimental"
    poll_interval = 2.0

    def info(self):
        return {"os": f"Windows {platform.release()} ({platform.machine()})",
                "backend": self.name, "screen_lock_detection": False}

    def snapshot(self):
        out = subprocess.run(["powershell", "-NoProfile", "-Command", _PS],
                             capture_output=True, text=True, timeout=30, check=True).stdout
        entries = json.loads(out) if out.strip() else []
        if isinstance(entries, dict):
            entries = [entries]

        roles = {}
        for e in entries:
            m = _ID.search(e.get("PNPDeviceID") or "")
            hint = _CLASS_HINTS.get((e.get("PNPClass") or "").lower())
            if (e.get("Service") or "").upper() == "USBSTOR":
                hint = _CLASS_HINTS["diskdrive"]
            if m and hint:
                roles.setdefault(m.group(0).upper(), set()).add(hint)

        devices = {}
        for e in entries:
            pnp = e.get("PNPDeviceID") or ""
            m = _ID.search(pnp)
            if not m or not pnp.upper().startswith("USB\\") or "&MI_" in pnp.upper():
                continue
            instance = pnp.split("\\")[-1]
            devices[pnp] = make_device(
                id=pnp,
                location=instance,
                vid=int(m.group(1), 16),
                pid=int(m.group(2), 16),
                name=e.get("Name"),
                manufacturer=e.get("Manufacturer"),
                serial=None if "&" in instance else instance,
                speed=None,
                device_class=None,
                interfaces=[{"number": i, "class": c, "subclass": s, "protocol": p}
                            for i, (c, s, p) in enumerate(sorted(roles.get(m.group(0).upper(), [])))],
                raw=e,
            )
        return devices

    def screen_locked(self):
        return None
