# USB Unblinder

A local USB activity and threat monitor. It records every USB plug and unplug, flags devices that behave
like attack tools (BadUSB, keystroke injectors, rogue network adapters), and runs an automatic deep
forensic re-scan of every suspicious event. It has a web dashboard, a CLI, and can run as a background
service.

It picks the right backend for the OS it runs on:

| OS | Device source | Status |
|---|---|---|
| macOS | IOKit registry (`ioreg`) | primary, tested |
| Linux | sysfs (`/sys/bus/usb`) + udev/journal | supported |
| Windows | PnP via PowerShell | experimental, untested |

Everything stays on your machine. The web UI listens on `127.0.0.1` only.

## Quick start

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python3 app.py
```

Open http://127.0.0.1:5050. Port 5000 is avoided because macOS AirPlay Receiver uses it.

The optional **Probe descriptors** button needs libusb: `brew install libusb` on macOS,
`apt install libusb-1.0-0` on Debian/Ubuntu.

## Run as a background service

```bash
python3 service.py install      # starts now and at every login, restarts if it crashes
python3 service.py status
python3 service.py uninstall
```

- **macOS:** a launchd agent at `~/Library/LaunchAgents/com.usbunblinder.agent.plist`.
  It runs as your user, which is what desktop notifications need; no root is required.
- **Linux:** a systemd user service `usb-unblinder.service`. To keep it running without a login
  session, run `sudo loginctl enable-linger $USER`.
- **Windows:** not automated yet; `service.py` prints the command to add as a Task Scheduler logon task.

Use `--port` to pick another port and `--dry-run` to print the service file without installing it.
Service output goes to `logs/service.out.log` and `logs/service.err.log`.

## What it detects

### On connect

| Finding | Level |
|---|---|
| New keyboard never seen on this computer | high |
| Keyboard combined with storage or network in one device | high |
| Known programmable boards (Teensy, Digispark, Arduino Leonardo/Micro, Pro Micro, RP2040, …) | high |
| Connected while the screen was locked | high |
| Serial number copied from a known device with different IDs | high |
| Device reconnecting 3+ times in 30 s | high |
| A different device appearing on the same port within 5 s (mode switch) | medium/high |
| USB network adapter | medium |
| Firmware-update (DFU) mode | medium |
| Control characters in the name, manufacturer or serial string | medium |
| Known device reporting a different name than before | medium |
| Disconnected within 3 s of connecting | low |

### Deep scan

Every medium or high event starts an automatic deep scan. You can also start one from any device, or
from the CLI. The device is observed in 8 passes over 60 seconds (at 0, 1, 2, 4, 8, 15, 30 and 60 s):

- **Identity over time:** VID:PID, serial, name or interfaces change after connecting; the device
  re-enumerates or vanishes ("hit and run").
- **HID capabilities:** the report descriptor is decoded, which reveals hidden keyboards (a device that
  can type without presenting a boot keyboard), power/sleep keys and vendor-defined data channels.
- **Input activity:** keyboard or mouse input starting right after a keyboard-capable device connects
  while you were idle, a typical sign of keystroke injection. Only the timing is used; what was typed
  is never read.
- **Processes started after the connect**, with shells and scripting tools highlighted: Terminal,
  `sh`/`zsh`/`bash`, `osascript`, `curl`, `python`, `powershell` and others.
- **Network:** new interfaces, the default route moving to the device, DNS server changes.
- **Serial ports** the device exposes.
- **Mounted volumes**, inspected read-only (files are never opened or run): autorun files,
  executables, files whose content doesn't match their extension (for example an `invoice.pdf` that
  is really a Windows program), hidden scripts. Flagged files get a SHA-256 hash.
- **OS evidence:** the full driver tree, apps holding the device open, the system log around the
  event, and a libusb descriptor cross-check.

**Limitation:** the process and input checks cannot tell an attacker from you. If you type in Terminal
during the 60-second scan of a keyboard-type device, that is reported too. Each report shows the exact
processes and timings so you can judge.

Trusted devices (toggle in the UI or `usb_unblinder.py trust`) stop raising device-type alerts. Behavior
alerts such as reconnect loops and identity changes still fire.

## Logs and reports

```
logs/
  events.jsonl            every plug/unplug event (rotating, 10 × 20 MB)
  suspicious.jsonl        suspicious events + deep-scan start/result (rotating, 20 × 20 MB)
  incidents/<id>.json     full evidence for one incident (~1 MB)
  incidents/<id>.txt      the same incident as a readable report
unblinder.db              SQLite: known devices, trust, event history, incident index
```

These files contain serial numbers, process command lines and file listings. They are excluded in
`.gitignore`; don't publish them.

## CLI

```bash
python3 usb_unblinder.py                   # watch live (default)
python3 usb_unblinder.py list              # current devices with findings
python3 usb_unblinder.py known             # every device ever seen
python3 usb_unblinder.py trust FINGERPRINT # or: untrust FINGERPRINT
python3 usb_unblinder.py probe 046d c077   # libusb descriptor dump
python3 usb_unblinder.py scan 046d:c077    # 60 s deep scan, then print the report
python3 usb_unblinder.py incidents         # list incidents
python3 usb_unblinder.py incident ID       # print one incident report
```

Common options: `--db PATH`, `--logs DIR`, `--no-notify`, `--poll SECONDS`, `--json` (for `watch`).

`app.py` takes `--host`, `--port` (or `PORT=`), `--db`, `--logs`, `--poll` and `--no-notify`.

## Web UI

- **Devices:** live cards sorted by risk. Click one for its findings, interfaces, raw OS properties,
  trust, the libusb probe and a deep scan.
- **Activity:** plug/unplug timeline grouped by day, filterable by level, CSV/JSON export.
- **Incidents:** deep scans with live progress and the full evidence view, TXT/JSON download, re-scan.
- **Known:** every device ever seen, with a trust switch.
- Search (`/`), tabs (`1`–`4`), `Esc` to close; light/dark/auto theme; optional browser notifications.

The server rejects requests whose `Host` is not local (blocks DNS rebinding) and accepts only JSON
POSTs, which other websites cannot forge without a CORS preflight.

## Project layout

```
app.py                  web server (Flask) + JSON API + live event stream (SSE)
usb_unblinder.py        CLI
service.py              background service installer
unblinder/
  backends/             per-OS device snapshots (macos, linux, windows)
  analysis.py           on-connect rules and behavior over time
  monitor.py            polling loop, snapshot diffing, event fan-out
  store.py              SQLite storage
  logbook.py            rotating JSONL logs and incident report files
  notify.py             desktop notifications
  probe.py              libusb descriptor dump
  hid.py                HID report descriptor decoder
  forensics/            deep scan: scheduler, evidence collectors, assessment, text report
templates/, static/     web UI
```

## Requirements

Python 3.10+ and Flask. `pyusb` + libusb are optional (probe only). No root or admin rights are needed.
