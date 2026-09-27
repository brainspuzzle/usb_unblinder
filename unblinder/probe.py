"""Low-level descriptor dump through libusb (pyusb)."""
import sys

TRANSFER = {0: "control", 1: "isochronous", 2: "bulk", 3: "interrupt"}


def libusb_status():
    try:
        import usb.backend.libusb1
    except ImportError:
        return False, "pyusb not installed (pip install pyusb)"
    if usb.backend.libusb1.get_backend() is None:
        hint = "brew install libusb" if sys.platform == "darwin" else "install libusb-1.0"
        return False, f"libusb not found ({hint})"
    return True, "libusb ready"


def _string(dev, index):
    import usb.util
    if not index:
        return None
    try:
        return usb.util.get_string(dev, index)
    except Exception as e:
        return f"<unreadable: {e}>"


def probe(vid, pid):
    import usb.core
    ok, msg = libusb_status()
    if not ok:
        raise RuntimeError(msg)
    found = list(usb.core.find(find_all=True, idVendor=vid, idProduct=pid))
    if not found:
        return None
    result = []
    for dev in found:
        info = {
            "bus": dev.bus, "address": dev.address,
            "bcdUSB": f"{dev.bcdUSB >> 8}.{(dev.bcdUSB >> 4) & 0xF}{dev.bcdUSB & 0xF}",
            "bcdDevice": hex(dev.bcdDevice),
            "device_class": dev.bDeviceClass, "max_packet_size0": dev.bMaxPacketSize0,
            "manufacturer": _string(dev, dev.iManufacturer),
            "product": _string(dev, dev.iProduct),
            "serial": _string(dev, dev.iSerialNumber),
            "configurations": [],
        }
        for cfg in dev:
            c = {"value": cfg.bConfigurationValue, "max_power_ma": cfg.bMaxPower * 2, "interfaces": []}
            for intf in cfg:
                c["interfaces"].append({
                    "number": intf.bInterfaceNumber, "alt": intf.bAlternateSetting,
                    "class": intf.bInterfaceClass, "subclass": intf.bInterfaceSubClass,
                    "protocol": intf.bInterfaceProtocol,
                    "endpoints": [{
                        "address": f"0x{ep.bEndpointAddress:02x}",
                        "direction": "IN" if ep.bEndpointAddress & 0x80 else "OUT",
                        "transfer": TRANSFER[ep.bmAttributes & 3],
                        "max_packet_size": ep.wMaxPacketSize,
                        "interval": ep.bInterval,
                    } for ep in intf],
                })
            info["configurations"].append(c)
        result.append(info)
    return result
