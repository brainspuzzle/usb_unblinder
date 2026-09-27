"""Windows evidence (experimental): PnP properties of the device and its child functions."""
import json
import re
import subprocess


def _ps(script, timeout=40):
    out = subprocess.run(["powershell", "-NoProfile", "-Command", script], capture_output=True,
                         text=True, timeout=timeout, errors="backslashreplace").stdout
    data = json.loads(out) if out.strip() else []
    return data if isinstance(data, list) else [data]


def collect(dev, heavy=False):
    m = re.search(r"VID_[0-9A-F]{4}&PID_[0-9A-F]{4}", dev["id"], re.I)
    if not m:
        return {"present_in_registry": False}
    key = m.group(0).replace("'", "")
    try:
        related = _ps(f"Get-PnpDevice -PresentOnly | Where-Object {{ $_.InstanceId -like '*{key}*' }} | "
                      "Select-Object InstanceId,FriendlyName,Class,Service,Status | ConvertTo-Json -Compress")
    except Exception as e:
        return {"present_in_registry": True, "error": str(e)}
    ev = {"present_in_registry": bool(related), "drivers": [], "open_by": [], "hid": [], "disks": [],
          "network_interfaces": [], "serial_ports": [], "pnp": related}
    for r in related:
        ev["drivers"].append({"class": r.get("Class"), "bundle": r.get("Service"), "name": r.get("FriendlyName")})
        cls = (r.get("Class") or "").lower()
        if cls == "net":
            ev["network_interfaces"].append({"bsd": r.get("FriendlyName")})
        elif cls == "ports":
            ev["serial_ports"].append(r.get("FriendlyName"))
        elif cls == "diskdrive":
            ev["disks"].append({"bsd": r.get("FriendlyName")})
    return ev


def mountpoints(evidence):
    return []


def system_log(since_wall):
    return []
