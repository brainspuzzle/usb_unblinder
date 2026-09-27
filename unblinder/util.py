import datetime as _dt


def now_iso():
    return _dt.datetime.now().isoformat(timespec="milliseconds")


def hexid(value):
    return f"0x{value:04x}" if isinstance(value, int) else "?"


def jsonable(obj, depth=0):
    """Make plist/sysfs values JSON-safe (bytes, dates, nested containers)."""
    if depth > 6:
        return str(obj)
    if isinstance(obj, dict):
        return {str(k): jsonable(v, depth + 1) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [jsonable(v, depth + 1) for v in obj]
    if isinstance(obj, bytes):
        return obj[:256].hex()
    if isinstance(obj, (_dt.date, _dt.datetime)):
        return obj.isoformat()
    if obj is None or isinstance(obj, (str, int, float, bool)):
        return obj
    return str(obj)


def make_device(*, id, location, vid, pid, name, manufacturer, serial, speed,
                device_class, interfaces, raw):
    """Common device shape produced by every backend."""
    return {
        "id": id,
        "location": location,
        "vid": vid,
        "pid": pid,
        "vendor_id": hexid(vid),
        "product_id": hexid(pid),
        "name": (name or "").strip() or "Unknown device",
        "manufacturer": (manufacturer or "").strip() or None,
        "serial": (serial or "").strip() or None,
        "speed": speed,
        "device_class": device_class,
        "interfaces": interfaces,
        "raw": jsonable(raw),
    }
