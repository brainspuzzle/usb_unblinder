"""Minimal HID report descriptor decoder: what can this device actually do?"""

APP_USAGES = {
    (0x01, 0x01): "Pointer", (0x01, 0x02): "Mouse", (0x01, 0x04): "Joystick", (0x01, 0x05): "Gamepad",
    (0x01, 0x06): "Keyboard", (0x01, 0x07): "Keypad", (0x01, 0x08): "Multi-axis controller",
    (0x01, 0x80): "System Control (power/sleep keys)", (0x0C, 0x01): "Consumer Control (media keys)",
    (0x0D, 0x01): "Digitizer", (0x0D, 0x02): "Pen", (0x0D, 0x04): "Touch screen", (0x0D, 0x05): "Touch pad",
    (0x0B, 0x05): "Telephony headset", (0x20, 0x01): "Sensor", (0x84, 0x04): "UPS / power device",
    (0x12, 0x01): "Eye tracker",
}


def _page_name(page):
    if page >= 0xFF00:
        return f"Vendor-defined 0x{page:04x}"
    return {0x01: "Generic Desktop", 0x07: "Keyboard/Keypad", 0x08: "LED", 0x09: "Button",
            0x0C: "Consumer", 0x0D: "Digitizer", 0x0B: "Telephony", 0x20: "Sensor",
            0x84: "Power", 0x85: "Battery", 0x12: "Eye/Head tracker"}.get(page, f"0x{page:02x}")


def parse(data):
    """Decode short items of a report descriptor into capabilities."""
    if isinstance(data, str):
        data = bytes.fromhex(data)
    usage_page = report_size = report_count = 0
    local_usages, apps, pages, report_ids = [], [], set(), set()
    inputs = outputs = features = input_bits = 0
    key_input = led_output = False
    i, errors = 0, None
    while i < len(data):
        b = data[i]
        if b == 0xFE:  # long item
            i += 3 + (data[i + 1] if i + 1 < len(data) else 0)
            continue
        size = (0, 1, 2, 4)[b & 3]
        typ, tag = (b >> 2) & 3, (b >> 4) & 0xF
        if i + 1 + size > len(data):
            errors = f"truncated item at byte {i}"
            break
        val = int.from_bytes(data[i + 1:i + 1 + size], "little")
        i += 1 + size
        if typ == 1:
            if tag == 0:
                usage_page = val
                pages.add(val)
            elif tag == 7:
                report_size = val
            elif tag == 8:
                report_ids.add(val)
            elif tag == 9:
                report_count = val
        elif typ == 2 and tag == 0:
            local_usages.append((val >> 16, val & 0xFFFF) if size == 4 else (usage_page, val))
        elif typ == 0:
            if tag == 0xA and val == 1 and local_usages:
                apps.append(local_usages[0])
            elif tag == 0x8:
                inputs += 1
                input_bits += report_size * report_count
                key_input |= usage_page == 0x07
            elif tag == 0x9:
                outputs += 1
                led_output |= usage_page == 0x08
            elif tag == 0xB:
                features += 1
            local_usages = []

    names = [APP_USAGES.get(a, f"{_page_name(a[0])} usage 0x{a[1]:02x}") for a in apps]
    vendor = sorted(p for p in pages if p >= 0xFF00)
    return {
        "application_collections": names,
        "usage_pages": [_page_name(p) for p in sorted(pages)],
        "report_ids": sorted(report_ids),
        "inputs": inputs, "outputs": outputs, "features": features, "input_bits": input_bits,
        "can_type": key_input or (0x01, 0x06) in apps or (0x01, 0x07) in apps,
        "can_point": any(a in apps for a in ((0x01, 0x01), (0x01, 0x02), (0x0D, 0x04), (0x0D, 0x05))),
        "system_control": (0x01, 0x80) in apps,
        "consumer_control": (0x0C, 0x01) in apps,
        "vendor_pages": [f"0x{p:04x}" for p in vendor],
        "keyboard_leds": led_output,
        "parse_error": errors,
    }
