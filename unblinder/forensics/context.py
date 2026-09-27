"""System-wide state sampled before and after a device appears."""
import glob
import json
import os
import plistlib
import re
import subprocess
import sys
import time

from ..util import now_iso

MAC, LINUX, WIN = sys.platform == "darwin", sys.platform.startswith("linux"), sys.platform.startswith("win")
_ENV = {**os.environ, "LC_ALL": "C"}


def _run(args, timeout=10):
    return subprocess.run(args, capture_output=True, text=True, timeout=timeout, env=_ENV,
                          errors="backslashreplace").stdout


def _safe(fn):
    try:
        return fn()
    except Exception as e:
        return {"error": f"{type(e).__name__}: {e}"}


def interfaces():
    if MAC:
        return sorted(_run(["ifconfig", "-l"]).split())
    if LINUX:
        return sorted(os.listdir("/sys/class/net"))
    return None


def default_route():
    if MAC:
        out = _run(["route", "-n", "get", "default"])
        info = dict(re.findall(r"^\s*(gateway|interface):\s*(\S+)", out, re.M))
        return info or None
    if LINUX:
        m = re.search(r"default via (\S+) dev (\S+)", _run(["ip", "route", "show", "default"]))
        return {"gateway": m.group(1), "interface": m.group(2)} if m else None
    return None


def dns_servers():
    if MAC:
        return sorted(set(re.findall(r"nameserver\[\d+\]\s*:\s*(\S+)", _run(["scutil", "--dns"]))))
    if LINUX:
        with open("/etc/resolv.conf") as f:
            return sorted(set(re.findall(r"^nameserver\s+(\S+)", f.read(), re.M)))
    return None


def serial_ports():
    if MAC:
        return sorted(glob.glob("/dev/cu.*"))
    if LINUX:
        return sorted(glob.glob("/dev/ttyUSB*") + glob.glob("/dev/ttyACM*"))
    return None


def hid_idle_seconds():
    """Seconds since the last keyboard/mouse input anywhere on the system."""
    if not MAC:
        return None
    out = subprocess.run(["ioreg", "-r", "-c", "IOHIDSystem", "-d", "1", "-a"], capture_output=True, timeout=5).stdout
    data = plistlib.loads(out)
    node = data[0] if isinstance(data, list) else data
    return node["HIDIdleTime"] / 1e9


def sample():
    return {
        "time": now_iso(), "wall": time.time(),
        "interfaces": _safe(interfaces),
        "default_route": _safe(default_route),
        "dns": _safe(dns_servers),
        "serial_ports": _safe(serial_ports),
        "hid_idle": _safe(hid_idle_seconds),
    }


def processes():
    """[{pid, ppid, start (epoch), command}] - full command lines."""
    if WIN:
        ps = ("Get-CimInstance Win32_Process | Select-Object ProcessId,ParentProcessId,CommandLine,Name,"
              "@{n='Start';e={[DateTimeOffset]::new($_.CreationDate).ToUnixTimeSeconds()}} | ConvertTo-Json -Compress")
        rows = json.loads(_run(["powershell", "-NoProfile", "-Command", ps], timeout=30) or "[]")
        return [{"pid": r["ProcessId"], "ppid": r["ParentProcessId"], "start": r.get("Start"),
                 "command": r.get("CommandLine") or r.get("Name")} for r in rows]
    flag = "-axo" if MAC else "-eo"
    result = []
    for line in _run(["ps", flag, "pid=,ppid=,lstart=,command="]).splitlines():
        parts = line.split(None, 7)
        if len(parts) < 8:
            continue
        try:
            start = time.mktime(time.strptime(" ".join(parts[2:7]), "%a %b %d %H:%M:%S %Y"))
        except ValueError:
            continue
        result.append({"pid": int(parts[0]), "ppid": int(parts[1]), "start": start, "command": parts[7]})
    return result


_TOOL = re.compile(r"(usb_unblinder\.py|\bapp\.py)\b")


def own_descendants(procs, started_before):
    """PIDs belonging to this tool: itself and other instances already running before the incident
    plus everything they spawn (ioreg, ps, osascript...), and - without their other children - the
    shells that launched it. Terminal's other children stay visible: injected commands land there."""
    by_pid = {p["pid"]: p for p in procs}
    children = {}
    for p in procs:
        children.setdefault(p["ppid"], []).append(p["pid"])
    roots = {os.getpid()} | {p["pid"] for p in procs if _TOOL.search(p["command"] or "") and "ython" in p["command"]
                             and p.get("start") and p["start"] < started_before}
    seen, stack = set(roots), list(roots)
    while stack:
        pid = stack.pop()
        for c in children.get(pid, []):
            if c not in seen:
                seen.add(c)
                stack.append(c)
    pid = os.getpid()
    while pid in by_pid and by_pid[pid]["ppid"] not in (0, 1) and len(seen) < 100000:
        pid = by_pid[pid]["ppid"]
        seen.add(pid)
    return seen
