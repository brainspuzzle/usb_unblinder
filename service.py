#!/usr/bin/env python3
"""
Run USB Unblinder as a background service that starts at login and restarts if it crashes.

  python3 service.py install     macOS: launchd agent   Linux: systemd user service
  python3 service.py uninstall
  python3 service.py status
  python3 service.py install --port 5055 --dry-run   print the service file without installing
"""
import argparse
import os
import plistlib
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
LABEL = "com.usbunblinder.agent"
UNIT = "usb-unblinder.service"


def python_exe():
    venv = ROOT / ".venv" / ("Scripts/python.exe" if os.name == "nt" else "bin/python")
    return str(venv if venv.exists() else Path(sys.executable))


def command(port):
    return [python_exe(), str(ROOT / "app.py"), "--port", str(port)]


# ── macOS ──────────────────────────────────────────────────────────────
def mac_plist_path(label):
    return Path.home() / "Library" / "LaunchAgents" / f"{label}.plist"


def mac_plist(port, label):
    logs = ROOT / "logs"
    return {
        "Label": label,
        "ProgramArguments": command(port),
        "WorkingDirectory": str(ROOT),
        "RunAtLoad": True,
        "KeepAlive": True,
        "ThrottleInterval": 10,
        "ProcessType": "Interactive",
        "EnvironmentVariables": {"PYTHONUNBUFFERED": "1"},
        "StandardOutPath": str(logs / "service.out.log"),
        "StandardErrorPath": str(logs / "service.err.log"),
    }


def mac(action, port, label, dry_run):
    path = mac_plist_path(label)
    domain = f"gui/{os.getuid()}"
    if action == "install":
        data = plistlib.dumps(mac_plist(port, label))
        if dry_run:
            print(data.decode())
            return
        (ROOT / "logs").mkdir(exist_ok=True)
        path.parent.mkdir(parents=True, exist_ok=True)
        subprocess.run(["launchctl", "bootout", f"{domain}/{label}"], capture_output=True)
        path.write_bytes(data)
        subprocess.run(["launchctl", "bootstrap", domain, str(path)], check=True)
        print(f"Installed {path}\nRunning at http://127.0.0.1:{port} - starts automatically at login.")
    elif action == "uninstall":
        subprocess.run(["launchctl", "bootout", f"{domain}/{label}"], capture_output=True)
        path.unlink(missing_ok=True)
        print("Uninstalled.")
    else:
        r = subprocess.run(["launchctl", "print", f"{domain}/{label}"], capture_output=True, text=True)
        if r.returncode:
            print("Not installed.")
            return
        shown = set()
        for line in r.stdout.splitlines():
            key = line.strip().split(" =")[0]
            if key in ("state", "pid", "last exit code", "program") and key not in shown:
                shown.add(key)
                print(line.strip())


# ── Linux ──────────────────────────────────────────────────────────────
def linux_unit(port):
    cmd = " ".join(f'"{c}"' for c in command(port))
    return f"""[Unit]
Description=USB Unblinder - USB activity and threat monitor
After=graphical-session.target

[Service]
ExecStart={cmd}
WorkingDirectory={ROOT}
Environment=PYTHONUNBUFFERED=1
Restart=always
RestartSec=5

[Install]
WantedBy=default.target
"""


def linux(action, port, dry_run):
    path = Path.home() / ".config" / "systemd" / "user" / UNIT
    ctl = ["systemctl", "--user"]
    if action == "install":
        unit = linux_unit(port)
        if dry_run:
            print(unit)
            return
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(unit)
        subprocess.run(ctl + ["daemon-reload"], check=True)
        subprocess.run(ctl + ["enable", "--now", UNIT], check=True)
        print(f"Installed {path}\nRunning at http://127.0.0.1:{port}.\n"
              f"To keep it running without a login session: sudo loginctl enable-linger {os.environ.get('USER', '$USER')}")
    elif action == "uninstall":
        subprocess.run(ctl + ["disable", "--now", UNIT], capture_output=True)
        path.unlink(missing_ok=True)
        subprocess.run(ctl + ["daemon-reload"], capture_output=True)
        print("Uninstalled.")
    else:
        subprocess.run(ctl + ["status", UNIT, "--no-pager"])


def main():
    ap = argparse.ArgumentParser(description="Install USB Unblinder as a background service")
    ap.add_argument("action", choices=["install", "uninstall", "status"])
    ap.add_argument("--port", type=int, default=5050)
    ap.add_argument("--label", default=LABEL, help="launchd label (macOS)")
    ap.add_argument("--dry-run", action="store_true", help="print the service definition only")
    a = ap.parse_args()
    if sys.platform == "darwin":
        mac(a.action, a.port, a.label, a.dry_run)
    elif sys.platform.startswith("linux"):
        linux(a.action, a.port, a.dry_run)
    else:
        sys.exit("Service install is supported on macOS and Linux. On Windows, add a Task Scheduler "
                 f"task that runs at logon: {' '.join(command(a.port))}")


if __name__ == "__main__":
    main()
