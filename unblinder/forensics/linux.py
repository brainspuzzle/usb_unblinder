"""Linux evidence from sysfs/udev: drivers, HID descriptors, block devices, network, tty."""
import json
import os
import subprocess
from pathlib import Path

from .. import hid

SYSFS = Path("/sys/bus/usb/devices")


def _run(args, timeout=15):
    try:
        return subprocess.run(args, capture_output=True, text=True, timeout=timeout, errors="backslashreplace").stdout
    except Exception as e:
        return f"error: {e}"


def _walk(root, max_depth=7):
    root_depth = str(root).count(os.sep)
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        if dirpath.count(os.sep) - root_depth >= max_depth:
            dirnames[:] = []
        yield Path(dirpath), dirnames, filenames


def _read(p):
    try:
        return p.read_text(errors="backslashreplace").strip()
    except OSError:
        return None


def collect(dev, heavy=False):
    path = SYSFS / dev["location"]
    if not path.exists():
        return {"present_in_registry": False}
    real = path.resolve()
    ev = {"present_in_registry": True, "drivers": [], "open_by": [], "hid": [], "disks": [],
          "network_interfaces": [], "serial_ports": [], "sysfs_path": str(real)}
    for d, dirnames, files in _walk(real):
        drv = d / "driver"
        if drv.is_symlink():
            ev["drivers"].append({"class": d.name, "bundle": os.path.basename(os.readlink(drv)), "depth": 0})
        if "report_descriptor" in files:
            try:
                desc = (d / "report_descriptor").read_bytes()
                ev["hid"].append({"class": d.name, "descriptor_hex": desc.hex(), "decoded": hid.parse(desc)})
            except OSError:
                pass
        if d.name == "block":
            for disk in dirnames:
                data = _run(["lsblk", "-J", "-o", "NAME,MOUNTPOINT,FSTYPE,LABEL,SIZE,UUID,RM,RO", f"/dev/{disk}"])
                try:
                    ev["disks"].append({"bsd": disk, "lsblk": json.loads(data)})
                except ValueError:
                    ev["disks"].append({"bsd": disk, "error": data[:500]})
        if d.name == "net":
            for iface in dirnames:
                ev["network_interfaces"].append({"bsd": iface, "mac": _read(d / iface / "address"),
                                                 "ifconfig": _run(["ip", "addr", "show", "dev", iface])})
        if d.name == "tty":
            ev["serial_ports"] += [f"/dev/{t}" for t in dirnames]
    if heavy:
        ev["udevadm"] = _run(["udevadm", "info", "-a", "-p", str(real)])[:60000]
    return ev


def mountpoints(evidence):
    def flatten(devs):
        for d in devs or []:
            yield d
            yield from flatten(d.get("children"))
    for disk in evidence.get("disks", []):
        for d in flatten((disk.get("lsblk") or {}).get("blockdevices")):
            if d.get("mountpoint"):
                yield d["mountpoint"], d.get("fstype")


def system_log(since_wall):
    lines = _run(["journalctl", "-k", "--no-pager", "-o", "short-precise", "--since", f"@{int(since_wall - 5)}"], 30)
    return lines.splitlines()[-600:]
