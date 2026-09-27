#!/usr/bin/env python3
"""
USB Unblinder CLI - watches USB plug/unplug and flags suspicious behavior.
The OS backend (macOS / Linux / Windows) is picked automatically.

  python3 usb_unblinder.py              watch live (default)
  python3 usb_unblinder.py list         show current devices and exit
  python3 usb_unblinder.py known        devices ever seen on this computer
  python3 usb_unblinder.py trust FP     mark a device fingerprint as trusted (untrust FP to undo)
  python3 usb_unblinder.py probe VID PID   dump descriptors via libusb (hex ids)
  python3 usb_unblinder.py scan 046d:c077  deep forensic scan of a connected device (~60s)
  python3 usb_unblinder.py incidents       list deep-scan incidents
  python3 usb_unblinder.py incident ID     print a full incident report

Logs: logs/events.jsonl (all), logs/suspicious.jsonl, logs/incidents/<id>.json|.txt

Web UI: python3 app.py
"""
import argparse
import json
import sys
import time
from pathlib import Path

from unblinder import DEFAULT_DB, DEFAULT_LOGS, create_monitor
from unblinder.probe import probe

COLORS = {"info": "\033[37m", "low": "\033[36m", "medium": "\033[33m", "high": "\033[1;31m"}
RESET = "\033[0m"
USE_COLOR = sys.stdout.isatty()


def c(level, text):
    return f"{COLORS[level]}{text}{RESET}" if USE_COLOR else text


def describe(dev):
    kinds = ",".join(dev.get("kinds") or []) or "-"
    return (f"{dev['name']}  {dev['vendor_id']}:{dev['product_id']}  "
            f"serial={dev['serial'] or '-'}  [{kinds}]  @{dev['location']}")


def print_findings(findings):
    for f in findings:
        print(f"      {c(f['level'], f['level'].upper().ljust(6))} {f['message']}")


def print_event(ev):
    t = ev["time"].split("T")[1]
    if ev["type"] == "snapshot":
        print(f"[{t}] {len(ev['devices'])} devices present")
        for d in ev["devices"]:
            print(f"  {c(d['level'], '●')} {describe(d)}")
            print_findings([f for f in d["findings"] if f["level"] != "info"])
    elif ev["type"] in ("connected", "removed"):
        tag = "CONNECTED" if ev["type"] == "connected" else "REMOVED  "
        print(f"[{t}] {c(ev['level'], tag)} {describe(ev['device'])}")
        print_findings(ev["findings"])
    elif ev["type"] == "status" and ev["status"]["error"]:
        print(f"[{t}] {c('high', 'ERROR')} {ev['status']['error']}")
    elif ev["type"] == "incident" and ev["incident"]["status"] != "scanning":
        i = ev["incident"]
        print(f"[{t}] {c(i['level'], 'DEEP SCAN ' + i['status'].upper())} {i['name']} - {i['summary']}")
        print(f"      report: {i.get('report_path')}")
    elif ev["type"] == "incident" and ev["incident"]["progress"]["pass"] == 0:
        print(f"[{t}] {c('medium', 'DEEP SCAN')} started for {ev['incident']['name']} ({ev['incident']['id']})")


def find_device(devices, query):
    q = query.lower().replace("0x", "")
    for d in devices:
        vp = f"{d['vendor_id']}:{d['product_id']}".replace("0x", "")
        if q in (vp, d.get("fingerprint"), d["id"].lower()) or q in d["name"].lower():
            return d
    return None


def main():
    ap = argparse.ArgumentParser(description="USB plug/unplug and suspicious behavior monitor")
    ap.add_argument("command", nargs="?", default="watch",
                    choices=["watch", "list", "known", "trust", "untrust", "probe", "scan", "incidents", "incident"])
    ap.add_argument("args", nargs="*")
    ap.add_argument("--json", action="store_true", help="print events as JSON lines")
    ap.add_argument("--db", default=DEFAULT_DB, help="SQLite history file")
    ap.add_argument("--logs", default=DEFAULT_LOGS, help="log + incident report directory")
    ap.add_argument("--no-notify", action="store_true", help="disable desktop notifications")
    ap.add_argument("--poll", type=float, help="poll interval in seconds")
    a = ap.parse_args()

    if a.command == "probe":
        if len(a.args) != 2:
            ap.error("probe needs VID PID in hex, e.g. probe 046d c077")
        result = probe(int(a.args[0], 16), int(a.args[1], 16))
        print(json.dumps(result, indent=2) if result else "Device not found")
        return

    mon = create_monitor(a.db, notify=not a.no_notify, poll_interval=a.poll, logs_dir=a.logs,
                         forensics=a.command in ("watch", "scan"))

    if a.command == "incidents":
        for i in mon.store.incidents():
            print(f"{c(i['level'], i['level'].upper().ljust(6))} {i['id']}  {i['status']:<11} {i['name']}  - {i['summary']}")
        return
    if a.command == "incident":
        if len(a.args) != 1:
            ap.error("incident needs an incident id (see: incidents)")
        i = mon.store.get_incident(a.args[0])
        if not i or not i.get("report_path"):
            print("Unknown incident or report not written yet")
            return
        print(Path(i["report_path"]).with_suffix(".txt").read_text(encoding="utf-8"))
        return
    if a.command == "scan":
        if len(a.args) != 1:
            ap.error("scan needs a device: VID:PID, fingerprint or part of the name (see: list)")
        mon.start()
        while mon.status["state"] != "running":
            time.sleep(0.2)
        dev = find_device(mon.current_devices(), a.args[0])
        if not dev:
            print("No connected device matches", a.args[0])
            return
        mon.listeners.append(print_event)
        incident_id = mon.scanner.start(dev, "manual")
        print(f"Deep-scanning {dev['name']} for ~60s (incident {incident_id})…")
        while (mon.store.get_incident(incident_id) or {}).get("status") == "scanning":
            time.sleep(1)
        i = mon.store.get_incident(incident_id)
        print(Path(i["report_path"]).with_suffix(".txt").read_text(encoding="utf-8"))
        return

    if a.command in ("trust", "untrust"):
        if len(a.args) != 1:
            ap.error(f"{a.command} needs a fingerprint (see: known)")
        ok = mon.store.set_trusted(a.args[0], a.command == "trust")
        print("OK" if ok else "Unknown fingerprint")
        return
    if a.command == "known":
        for r in mon.store.known_devices():
            print(f"{'✓' if r['trusted'] else ' '} {r['fingerprint']}  {r['name']}  "
                  f"seen={r['seen_count']}  last={r['last_seen']}  [{','.join(r['kinds'])}]")
        return
    if a.command == "list":
        devices = mon.scan()
        if a.json:
            print(json.dumps(devices, indent=2))
        else:
            print_event({"type": "snapshot", "time": "T" + time.strftime("%H:%M:%S"), "devices": devices})
        return

    info = mon.backend.info()
    print(f"USB Unblinder - {info['os']} - backend: {info['backend']}  (Ctrl+C to stop)")
    mon.listeners.append((lambda ev: print(json.dumps(ev), flush=True)) if a.json else print_event)
    mon.start()
    try:
        while True:
            time.sleep(3600)
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
