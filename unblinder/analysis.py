import re
import time
from collections import defaultdict, deque

LEVELS = ["info", "low", "medium", "high"]

CLASS_NAMES = {
    0x00: "per-interface", 0x01: "audio", 0x02: "communications (CDC)", 0x03: "HID",
    0x05: "physical", 0x06: "image", 0x07: "printer", 0x08: "mass storage", 0x09: "hub",
    0x0A: "CDC data", 0x0B: "smart card", 0x0D: "content security", 0x0E: "video",
    0x0F: "healthcare", 0x10: "audio/video", 0x11: "billboard", 0x12: "USB-C bridge",
    0xDC: "diagnostic", 0xE0: "wireless", 0xEF: "miscellaneous", 0xFE: "application specific",
    0xFF: "vendor specific",
}

# Programmable boards commonly flashed as keystroke injectors. Not exhaustive:
# attack tools can spoof any VID:PID, so this is a hint, not proof.
KNOWN_BOARDS = {
    (0x16C0, 0x27DB): "V-USB keyboard (Digispark and clones)",
    (0x16D0, 0x0753): "Digispark bootloader",
    (0x16C0, 0x0478): "Teensy bootloader",
    (0x16C0, 0x0482): "Teensy (keyboard/mouse/joystick)",
    (0x16C0, 0x0483): "Teensy (serial)",
    (0x16C0, 0x0487): "Teensy (serial + keyboard/mouse)",
    (0x16C0, 0x0489): "Teensy (serial + keyboard/mouse/joystick)",
    (0x2341, 0x8036): "Arduino Leonardo",
    (0x2341, 0x0036): "Arduino Leonardo bootloader",
    (0x2341, 0x8037): "Arduino Micro",
    (0x2341, 0x0037): "Arduino Micro bootloader",
    (0x1B4F, 0x9205): "SparkFun Pro Micro",
    (0x1B4F, 0x9206): "SparkFun Pro Micro",
    (0x2E8A, 0x0003): "Raspberry Pi RP2040 bootloader",
    (0x2E8A, 0x0005): "Raspberry Pi Pico (MicroPython)",
    (0x2E8A, 0x000A): "Raspberry Pi Pico (SDK)",
    (0x0483, 0x5740): "STM32 virtual COM port (Flipper Zero, many dev boards)",
}
KNOWN_VENDORS = {0x239A: "Adafruit (CircuitPython boards can act as keyboards)"}

FLAP_WINDOW, FLAP_COUNT = 30, 3
SWAP_WINDOW = 5
SHORT_LIVED = 3
_GENERIC_SERIAL = re.compile(r"0*1?|0123456789.*|1234567890.*|(.)\1*", re.I)
_NONPRINTABLE = re.compile(r"\\x[0-9a-f]{2}|[\x00-\x1f\x7f]", re.I)


def fingerprint(dev):
    who = dev["serial"] or f"noserial:{dev['name']}"
    return f"{dev['vendor_id']}:{dev['product_id']}:{who}".lower()


def classify(dev):
    kinds = set()
    classes = [(i["class"], i["subclass"], i["protocol"]) for i in dev["interfaces"]]
    if dev["device_class"] not in (None, 0x00, 0xEF, 0xFF):
        classes.append((dev["device_class"], None, None))
    for c, s, p in classes:
        if c == 0x03:
            kinds.add({(1, 1): "keyboard", (1, 2): "mouse"}.get((s, p), "hid"))
        elif c == 0x08:
            kinds.add("storage")
        elif c == 0x09:
            kinds.add("hub")
        elif (c, s) in ((0x02, 0x06), (0x02, 0x0D), (0x02, 0x0A)) or (c, s, p) in ((0xE0, 1, 3), (0xEF, 4, 1)):
            kinds.add("network")
        elif (c, s) == (0x02, 0x02):
            kinds.add("serial")
        elif (c, s, p) == (0xE0, 1, 1):
            kinds.add("bluetooth")
        elif c == 0x01:
            kinds.add("audio")
        elif c == 0x0E:
            kinds.add("camera")
        elif (c, s) == (0xFE, 0x01):
            kinds.add("dfu")
        elif c in CLASS_NAMES and c not in (0x00, 0x02, 0x0A, 0xEF):
            kinds.add(CLASS_NAMES[c])
    if "keyboard" in kinds or "mouse" in kinds:
        kinds.discard("hid")
    return sorted(kinds)


def max_level(findings):
    return max((f["level"] for f in findings), key=LEVELS.index, default="info")


def _f(level, code, message):
    return {"level": level, "code": code, "message": message}


class Analyzer:
    """Scores single devices and watches behavior over time."""

    def __init__(self, store):
        self.store = store
        self.connects = defaultdict(deque)   # fingerprint -> connect timestamps
        self.connected_at = {}                # device id -> timestamp
        self.removed_at = {}                  # location -> (timestamp, device)

    def on_connect(self, dev, *, baseline=False, locked=None):
        now = time.monotonic()
        dev["kinds"] = classify(dev)
        fp = dev["fingerprint"] = fingerprint(dev)
        known = self.store.get_device(fp)
        trusted = bool(known and known["trusted"])
        kinds = set(dev["kinds"])
        static, behavior = [], []

        if not known:
            static.append(_f("info", "NEW", "Present at startup, first time recorded" if baseline
                             else "Never seen on this computer before"))
        elif known["name"] != dev["name"]:
            static.append(_f("medium", "NAME_CHANGED",
                             f"Same VID:PID and serial but name changed from “{known['name']}”"))

        if "keyboard" in kinds:
            if not known and not baseline:
                static.append(_f("high", "NEW_KEYBOARD",
                                 "A new keyboard appeared - it can type commands on this computer"))
            else:
                static.append(_f("low", "KEYBOARD", "Acts as a keyboard"))
            if kinds & {"storage", "network"}:
                static.append(_f("high", "HID_COMBO",
                                 "Keyboard combined with " + "/".join(sorted(kinds & {"storage", "network"}))
                                 + " in one device (typical of BadUSB tools)"))
        if "network" in kinds:
            static.append(_f("medium", "NETWORK",
                             "USB network adapter - can capture or redirect traffic"))
        if "dfu" in kinds:
            static.append(_f("medium", "DFU", "Device is in firmware-update (DFU) mode"))
        if "storage" in kinds:
            static.append(_f("info", "STORAGE", "Mass storage"))

        board = KNOWN_BOARDS.get((dev["vid"], dev["pid"])) or KNOWN_VENDORS.get(dev["vid"])
        if board:
            static.append(_f("high", "KNOWN_BOARD", f"Programmable board: {board}"))

        for field in ("name", "manufacturer", "serial"):
            if dev[field] and _NONPRINTABLE.search(dev[field]):
                static.append(_f("medium", "CONTROL_CHARS",
                                 f"Control characters in the {field} string"))

        serial = dev["serial"]
        if serial and len(serial) >= 6 and not _GENERIC_SERIAL.fullmatch(serial):
            clones = [r for r in self.store.find_by_serial(serial) if r["fingerprint"] != fp]
            if clones:
                other = clones[0]
                static.append(_f("high", "SERIAL_CLONE",
                                 f"Serial matches a known device with different IDs "
                                 f"({other['vendor_id']}:{other['product_id']} “{other['name']}”)"))

        if not baseline:
            if locked:
                behavior.append(_f("high", "WHILE_LOCKED", "Connected while the screen was locked"))

            times = self.connects[fp]
            times.append(now)
            while times and now - times[0] > FLAP_WINDOW:
                times.popleft()
            if len(times) >= FLAP_COUNT:
                behavior.append(_f("high", "FLAPPING",
                                   f"Reconnected {len(times)} times in {FLAP_WINDOW}s - bad cable, "
                                   f"or a device re-enumerating to switch identity"))

            prev = self.removed_at.get(dev["location"])
            if prev and now - prev[0] <= SWAP_WINDOW and prev[1]["fingerprint"] != fp \
                    and (prev[1]["vid"], prev[1]["pid"]) != (dev["vid"], dev["pid"]):
                level = "high" if kinds & {"keyboard", "network", "hid"} else "medium"
                behavior.append(_f(level, "IDENTITY_CHANGE",
                                   f"Replaced “{prev[1]['name']}” ({prev[1]['vendor_id']}:{prev[1]['product_id']}) "
                                   f"on the same port within {now - prev[0]:.1f}s - mode switch or quick swap"))

        self.connected_at[dev["id"]] = now

        if trusted:
            static = [dict(f, level="info") for f in static]
            static.append(_f("info", "TRUSTED", "Marked as trusted"))
        dev["trusted"] = trusted
        return static + behavior

    def on_remove(self, dev):
        now = time.monotonic()
        self.removed_at[dev["location"]] = (now, dev)
        started = self.connected_at.pop(dev["id"], None)
        if started is not None and now - started < SHORT_LIVED:
            return [_f("low", "SHORT_LIVED", f"Disconnected {now - started:.1f}s after connecting")]
        return []
