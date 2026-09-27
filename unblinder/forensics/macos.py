"""macOS evidence: full IOKit subtree of the device (drivers, HID, disks, network, serial)."""
import datetime as dt
import plistlib
import subprocess

from .. import hid
from ..backends.macos import _ioreg
from ..util import jsonable


def _subtree(location):
    loc = int(location, 16)
    for node in _ioreg("-r", "-c", "IOUSBHostDevice", "-l"):
        if node.get("locationID") == loc:
            return node
    return None


def _walk(node, depth=0):
    yield node, depth
    for child in node.get("IORegistryEntryChildren", []):
        yield from _walk(child, depth + 1)


def _diskutil(bsd):
    try:
        out = subprocess.run(["diskutil", "info", "-plist", bsd], capture_output=True, timeout=15).stdout
        info = plistlib.loads(out)
    except Exception as e:
        return {"bsd": bsd, "error": str(e)}
    keep = ("DeviceIdentifier", "MountPoint", "VolumeName", "FilesystemType", "FilesystemUserVisibleName",
            "TotalSize", "Size", "Writable", "WritableMedia", "Ejectable", "Internal", "RemovableMedia",
            "VolumeUUID", "DiskUUID", "MediaName", "Content", "BusProtocol", "Encryption", "SMARTStatus")
    return {k: jsonable(info[k]) for k in keep if k in info}


def _ifconfig(name):
    try:
        return subprocess.run(["ifconfig", name], capture_output=True, text=True, timeout=5).stdout
    except Exception as e:
        return str(e)


def collect(dev, heavy=False):
    node = _subtree(dev["location"])
    if node is None:
        return {"present_in_registry": False}
    ev = {"present_in_registry": True, "drivers": [], "open_by": [], "hid": [], "disks": [],
          "network_interfaces": [], "serial_ports": [], "registry_nodes": 0}
    seen_desc = set()
    for n, depth in _walk(node):
        ev["registry_nodes"] += 1
        cls = n.get("IOObjectClass", "")
        if "UserClient" in cls:
            ev["open_by"].append({"app": n.get("IORegistryEntryName"), "class": cls,
                                  "creator": n.get("IOUserClientCreator")})
            continue
        if n.get("CFBundleIdentifier") and depth > 0:
            ev["drivers"].append({"class": cls, "bundle": n.get("CFBundleIdentifier"), "depth": depth,
                                  "name": n.get("IORegistryEntryName")})
        desc = n.get("ReportDescriptor")
        if isinstance(desc, bytes) and desc not in seen_desc:
            seen_desc.add(desc)
            ev["hid"].append({
                "class": cls, "product": n.get("Product"),
                "primary_usage_page": n.get("PrimaryUsagePage"), "primary_usage": n.get("PrimaryUsage"),
                "usage_pairs": jsonable(n.get("DeviceUsagePairs")),
                "max_input_report": n.get("MaxInputReportSize"), "max_output_report": n.get("MaxOutputReportSize"),
                "report_interval_us": n.get("ReportInterval"),
                "descriptor_hex": desc.hex(),
                "decoded": hid.parse(desc),
            })
        bsd = n.get("BSD Name")
        if bsd:
            if cls.endswith("Media") or bsd.startswith("disk"):
                ev["disks"].append({"bsd": bsd, "whole": n.get("Whole"), "class": cls, "size": n.get("Size"),
                                    "content": n.get("Content")})
            else:
                ev["network_interfaces"].append({"bsd": bsd, "class": cls,
                                                 "mac": n.get("IOMACAddress", b"").hex(":") if isinstance(n.get("IOMACAddress"), bytes) else None})
        for key in ("IOCalloutDevice", "IODialinDevice"):
            if n.get(key):
                ev["serial_ports"].append(n[key])

    for d in ev["disks"]:
        if not d["whole"] or len(ev["disks"]) == 1:
            d["info"] = _diskutil(d["bsd"])
    for i in ev["network_interfaces"]:
        i["ifconfig"] = _ifconfig(i["bsd"])
    if heavy:
        ev["registry_subtree"] = jsonable(node, max_depth=60)
    return ev


def mountpoints(evidence):
    for d in evidence.get("disks", []):
        info = d.get("info") or {}
        if info.get("MountPoint"):
            yield info["MountPoint"], info.get("FilesystemType")


def system_log(since_wall):
    start = dt.datetime.fromtimestamp(since_wall - 5).strftime("%Y-%m-%d %H:%M:%S")
    predicate = ('(eventMessage CONTAINS[c] "USB" OR subsystem BEGINSWITH "com.apple.iokit" '
                 'OR process == "kernel" OR eventMessage CONTAINS[c] "HID") AND process != "log"')
    try:
        out = subprocess.run(["/usr/bin/log", "show", "--start", start, "--style", "compact", "--predicate", predicate],
                             capture_output=True, text=True, timeout=40, errors="backslashreplace").stdout
    except Exception as e:
        return [f"log error: {e}"]
    lines = [l for l in out.splitlines()[1:] if l.strip()]
    return lines[-600:]
