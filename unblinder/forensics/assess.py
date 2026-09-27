"""Turn collected deep-scan evidence into findings."""
import os
import re

from ..analysis import _f

SUSPICIOUS_CMD = re.compile(
    r"^(terminal|iterm2?|osascript|bash|sh|zsh|dash|fish|ksh|curl|wget|python\d*(\.\d+)?|perl|ruby|php|node|"
    r"nc|ncat|netcat|socat|ssh|scp|sftp|telnet|powershell|pwsh|cmd|cmd\.exe|powershell\.exe|wscript(\.exe)?|"
    r"cscript(\.exe)?|mshta(\.exe)?|rundll32(\.exe)?|regsvr32(\.exe)?|certutil(\.exe)?|bitsadmin(\.exe)?|base64|"
    r"openssl|sudo|launchctl|security|screencapture|xattr|chmod|crontab|systemctl|nohup|dd|xterm|"
    r"gnome-terminal|konsole|x-terminal-emulator)$", re.I)


def process_name(command):
    command = (command or "").strip()
    if command.startswith("(") and command.endswith(")"):
        # macOS shows already-exited processes as "(bash)" - a quick injected command looks exactly like this
        command = command[1:-1]
    tokens = command.split(" ")
    if tokens[0].startswith("/"):
        # executable paths may contain spaces ("Google Chrome"): take the longest prefix that is a file
        for i in range(len(tokens), 0, -1):
            candidate = " ".join(tokens[:i])
            if os.path.isfile(candidate):
                return os.path.basename(candidate)
    return os.path.basename(tokens[0].strip('"'))


def _all(incident, key):
    for p in incident["passes"]:
        ev = p.get("evidence") or {}
        yield from ev.get(key, []) or []


def assess(incident):
    findings = []
    dev = incident["device"]
    passes = incident["passes"]
    auto = incident["reason"] == "auto"
    hid_caps = [h["decoded"] for h in _all(incident, "hid")]
    usb_kinds = set(dev.get("kinds") or [])
    for p in passes:
        if p.get("device"):
            usb_kinds |= set(p["device"].get("kinds") or [])
    can_type = "keyboard" in usb_kinds or any(c["can_type"] for c in hid_caps)

    # ── identity over time ──
    changes = [c for p in passes for c in p.get("changes", [])]
    fields = {c["field"] for c in changes}
    if fields & {"vendor_id", "product_id", "serial"}:
        findings.append(_f("high", "IDENTITY_SHIFT", "Device changed its USB identity during observation: " +
                           "; ".join(f"{c['field']} {c['before']} → {c['after']}" for c in changes
                                     if c["field"] in ("vendor_id", "product_id", "serial"))))
    if "interfaces" in fields:
        findings.append(_f("high", "INTERFACES_CHANGED", "Device changed what it presents itself as (interfaces) after connecting"))
    if fields & {"name", "manufacturer"}:
        findings.append(_f("medium", "NAME_SHIFT", "Device changed its name/manufacturer strings during observation"))
    if "id" in fields:
        findings.append(_f("medium", "REENUMERATED", "Device re-enumerated (reset itself) while being observed"))
    states = [p["state"] for p in passes]
    if states and states[0] != "absent" and states[-1] == "absent":
        gone = next(p["offset"] for p in passes if p["state"] == "absent")
        findings.append(_f("medium" if gone <= 5 else "low", "DISAPPEARED",
                           f"Device disappeared ≈{gone}s into the scan (hit-and-run devices do this)"))

    # ── HID capabilities ──
    if any(c["can_type"] for c in hid_caps) and "keyboard" not in usb_kinds:
        findings.append(_f("high", "HIDDEN_KEYBOARD",
                           "HID report descriptor declares a keyboard although the device does not present a boot keyboard"))
    if any(c["system_control"] for c in hid_caps):
        findings.append(_f("low", "HID_SYSTEM_CONTROL", "Can send system power/sleep keys"))
    vendor = sorted({p for c in hid_caps for p in c["vendor_pages"]})
    if vendor:
        # common on ordinary keyboards (firmware/RGB control), so evidence rather than an alarm on its own
        findings.append(_f("low", "HID_VENDOR_CHANNEL",
                           f"Vendor-defined HID channel ({', '.join(vendor)}) - can carry hidden data/commands"
                           + (" alongside keyboard input" if can_type else "")))
    if any(c["parse_error"] for c in hid_caps):
        findings.append(_f("medium", "HID_MALFORMED", "Malformed HID report descriptor"))

    # ── input activity right after a new keyboard appeared ──
    base = incident.get("baseline") or {}
    connect = incident.get("connected_at_wall")
    if auto and can_type and connect and isinstance(base.get("hid_idle"), (int, float)):
        idle_before = base["hid_idle"]
        first_input = None
        for p in passes:
            idle = (p.get("context") or {}).get("hid_idle")
            if isinstance(idle, (int, float)):
                at = p["context"]["wall"] - idle - connect
                if at > 0.3 and (first_input is None or at < first_input):
                    first_input = at
        incident["input_activity"] = {"idle_before_s": round(idle_before, 1),
                                      "first_input_after_connect_s": round(first_input, 2) if first_input else None}
        if first_input is not None and first_input <= 20:
            if idle_before >= 3:
                findings.append(_f("high", "INPUT_AFTER_CONNECT",
                                   f"Keyboard/mouse input started {first_input:.1f}s after this keyboard-capable device "
                                   f"connected, while the user had been idle ≥{idle_before:.0f}s (possible keystroke injection)"))
            else:
                findings.append(_f("info", "INPUT_AFTER_CONNECT",
                                   f"Input activity {first_input:.1f}s after connect (user was active - cannot attribute)"))

    # ── processes ──
    procs = incident.get("new_processes", [])
    bad = [p for p in procs if p.get("suspicious")]
    if bad:
        names = ", ".join(sorted({p["name"] for p in bad}))
        findings.append(_f("high" if can_type else "medium", "SUSPICIOUS_PROCESS",
                           f"Shell/scripting processes started after connection: {names}"))
    if procs:
        findings.append(_f("info", "NEW_PROCESSES", f"{len(procs)} process(es) started during observation"))

    # ── network ──
    later = [p["context"] for p in passes if p.get("context")]
    own_ifaces = {i["bsd"] for i in _all(incident, "network_interfaces")}
    if isinstance(base.get("interfaces"), list):
        new_if = sorted({i for c in later if isinstance(c.get("interfaces"), list)
                         for i in c["interfaces"]} - set(base["interfaces"]))
        new_if = sorted(set(new_if) | own_ifaces)
        if new_if:
            hidden = "network" not in usb_kinds
            findings.append(_f("high" if hidden or can_type else "medium", "NEW_NETWORK_INTERFACE",
                               f"New network interface(s): {', '.join(new_if)}"
                               + (" - device did not declare itself as a network adapter" if hidden else "")))
    routes = [c.get("default_route") for c in later if isinstance(c.get("default_route"), dict) and "error" not in c["default_route"]]
    before_route = base.get("default_route") if isinstance(base.get("default_route"), dict) else None
    if before_route and routes and routes[-1] and routes[-1].get("interface") != before_route.get("interface"):
        findings.append(_f("high", "DEFAULT_ROUTE_CHANGED",
                           f"Default route moved {before_route.get('interface')} → {routes[-1].get('interface')} "
                           f"(gateway {routes[-1].get('gateway')}) - traffic may be intercepted"))
    dns_after = [c.get("dns") for c in later if isinstance(c.get("dns"), list)]
    if isinstance(base.get("dns"), list) and dns_after and dns_after[-1] != base["dns"]:
        findings.append(_f("high" if own_ifaces else "medium", "DNS_CHANGED",
                           f"DNS servers changed {base['dns']} → {dns_after[-1]}"))

    # ── serial ──
    ports = sorted(set(_all(incident, "serial_ports")))
    if ports:
        findings.append(_f("medium" if can_type else "low", "SERIAL_PORT",
                           f"Exposes serial port(s) {', '.join(ports)} - a command/control channel"))

    # ── storage ──
    for vol in incident.get("storage", []):
        for f in vol.get("flagged", []):
            reasons = " ".join(f["reasons"])
            if "disguised" in reasons or "hidden executable" in reasons:
                level, code = "high", "DISGUISED_EXECUTABLE"
            elif "autorun" in reasons:
                level, code = "medium", "AUTORUN_FILE"
            else:
                level, code = "medium", "EXECUTABLE_ON_VOLUME"
            findings.append(_f(level, code, f"{vol['mountpoint']}/{f['path']}: {'; '.join(f['reasons'])}"))

    # ── libusb cross-check ──
    probe = incident.get("probe")
    if isinstance(probe, list) and probe:
        p0 = probe[0]
        for field, os_value in (("product", dev.get("name")), ("manufacturer", dev.get("manufacturer")),
                                ("serial", dev.get("serial"))):
            lv = p0.get(field)
            if lv and os_value and not str(lv).startswith("<unreadable") and lv.strip() != os_value.strip():
                findings.append(_f("medium", "DESCRIPTOR_MISMATCH",
                                   f"{field} differs: OS reports “{os_value}”, device descriptor says “{lv}”"))
        if len(p0.get("configurations", [])) > 1:
            findings.append(_f("low", "MULTI_CONFIG", "Device offers multiple configurations (can switch function)"))

    apps = sorted({o["app"] for o in _all(incident, "open_by") if o.get("app")})
    if apps:
        findings.append(_f("info", "OPEN_BY_APPS", f"Opened by: {', '.join(apps)}"))

    # dedupe identical findings coming from several passes
    unique, seen = [], set()
    for f in findings:
        key = (f["code"], f["message"])
        if key not in seen:
            seen.add(key)
            unique.append(f)
    return unique
