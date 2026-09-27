import Foundation
import AppKit
import IOKit.hid

func emit(_ category: String, _ data: [String: Any]) {
    let row: [String: Any] = ["category": category, "data": data, "wall": Date().timeIntervalSince1970]
    if let bytes = try? JSONSerialization.data(withJSONObject: row), let line = String(data: bytes, encoding: .utf8) {
        print(line)
        fflush(stdout)
    }
}
let recordKeys = CommandLine.arguments.contains("--keys")
let manager = IOHIDManagerCreate(kCFAllocatorDefault, IOOptionBits(kIOHIDOptionsTypeNone))
let matches: [[String: Any]] = [
    [kIOHIDDeviceUsagePageKey: 1, kIOHIDDeviceUsageKey: 6],
    [kIOHIDDeviceUsagePageKey: 1, kIOHIDDeviceUsageKey: 2]
]
IOHIDManagerSetDeviceMatchingMultiple(manager, matches as CFArray)
let inputCallback: IOHIDValueCallback = { _, _, _, value in
    let element = IOHIDValueGetElement(value)
    let page = IOHIDElementGetUsagePage(element)
    let usage = IOHIDElementGetUsage(element)
    guard page == 7 || page == 9 else { return }
    let device = IOHIDElementGetDevice(element)
    func prop(_ key: String) -> Any { return IOHIDDeviceGetProperty(device, key as CFString) ?? "unknown" as CFString }
    var data: [String: Any] = ["page": page, "pressed": IOHIDValueGetIntegerValue(value) != 0,
        "vendor_id": prop(kIOHIDVendorIDKey), "product_id": prop(kIOHIDProductIDKey),
        "location_id": prop(kIOHIDLocationIDKey), "product": prop(kIOHIDProductKey)]
    if recordKeys { data["usage"] = usage }
    emit("hid", data)
}
IOHIDManagerRegisterInputValueCallback(manager, inputCallback, nil)
IOHIDManagerScheduleWithRunLoop(manager, CFRunLoopGetCurrent(), CFRunLoopMode.defaultMode.rawValue)
let status = IOHIDManagerOpen(manager, IOOptionBits(kIOHIDOptionsTypeNone))
emit("collector", ["source": "hid", "open_result": status, "keys_recorded": recordKeys,
    "listen_access": IOHIDCheckAccess(kIOHIDRequestTypeListenEvent).rawValue])
let center = NSWorkspace.shared.notificationCenter
let token = center.addObserver(forName: NSWorkspace.didActivateApplicationNotification, object: nil, queue: .main) { notification in
    if let app = notification.userInfo?[NSWorkspace.applicationUserInfoKey] as? NSRunningApplication {
        emit("foreground", ["pid": app.processIdentifier, "name": app.localizedName ?? "", "bundle": app.bundleIdentifier ?? ""])
    }
}
RunLoop.main.run()
