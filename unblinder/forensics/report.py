"""Human-readable incident report."""
import datetime as dt


def _ts(wall):
    return dt.datetime.fromtimestamp(wall).strftime("%H:%M:%S") if wall else "?"


def render_text(inc):
    d = inc["device"]
    out = []
    w = out.append
    w("=" * 78)
    w(f"USB UNBLINDER - INCIDENT {inc['id']}")
    w("=" * 78)
    w(f"Level:      {inc['level'].upper()}")
    w(f"Status:     {inc['status']}   ({inc['progress']['pass']}/{inc['progress']['of']} passes)")
    w(f"Reason:     {inc['reason']}   triggered {inc['created']}")
    w(f"Device:     {d.get('name')}  {d.get('vendor_id')}:{d.get('product_id')}")
    w(f"            manufacturer={d.get('manufacturer') or '-'}  serial={d.get('serial') or '-'}")
    w(f"            kinds={','.join(d.get('kinds') or []) or '-'}  location={d.get('location')}  speed={d.get('speed') or '-'}")
    w(f"            fingerprint={d.get('fingerprint')}")
    if inc.get("related_events"):
        w(f"Related:    {len(inc['related_events'])} more event(s) from the same device during the scan")
    w("")
    w("FINDINGS")
    w("-" * 78)
    for f in sorted(inc["all_findings"], key=lambda f: ["high", "medium", "low", "info"].index(f["level"])):
        w(f"  [{f['level'].upper():6}] {f['code']:<22} {f['message']}")
    w("")
    w("OBSERVATION TIMELINE")
    w("-" * 78)
    for p in inc["passes"]:
        ev = p.get("evidence") or {}
        extra = []
        if ev.get("drivers"):
            extra.append(f"{len(ev['drivers'])} drivers")
        if ev.get("hid"):
            extra.append(f"{len(ev['hid'])} HID")
        if ev.get("disks"):
            extra.append(f"{len(ev['disks'])} disks")
        if ev.get("network_interfaces"):
            extra.append("net " + ",".join(i["bsd"] for i in ev["network_interfaces"]))
        w(f"  +{p['offset']:>4}s  {p['time'][11:23]}  {p['state']:<13} {' · '.join(extra)}")
        for c in p.get("changes", []):
            w(f"           CHANGE {c['field']}: {c['before']} → {c['after']}")
    w("")
    hids = [h for p in inc["passes"] for h in (p.get("evidence") or {}).get("hid", [])]
    seen = set()
    if hids:
        w("HID CAPABILITIES")
        w("-" * 78)
        for h in hids:
            if h["descriptor_hex"] in seen:
                continue
            seen.add(h["descriptor_hex"])
            c = h["decoded"]
            w(f"  {', '.join(c['application_collections']) or 'no application collections'}")
            w(f"    can_type={c['can_type']} can_point={c['can_point']} system_control={c['system_control']} "
              f"vendor_pages={c['vendor_pages'] or '-'} report_ids={c['report_ids'] or '-'}")
            w(f"    descriptor ({len(h['descriptor_hex']) // 2} bytes): {h['descriptor_hex']}")
        w("")
    if "input_activity" in inc:
        ia = inc["input_activity"]
        w("INPUT ACTIVITY")
        w("-" * 78)
        w(f"  user idle before connect: {ia['idle_before_s']}s   first input after connect: {ia['first_input_after_connect_s']}s")
        w("")
    if inc.get("new_processes"):
        w("PROCESSES STARTED DURING OBSERVATION")
        w("-" * 78)
        for p in inc["new_processes"]:
            flag = "  <-- SUSPICIOUS" if p.get("suspicious") else ""
            w(f"  {p['offset']:>+7.1f}s  pid {p['pid']:<7} ppid {p['ppid']:<7} {p['command'][:300]}{flag}")
        w("")
    base = inc.get("baseline") or {}
    last = next((p["context"] for p in reversed(inc["passes"]) if p.get("context")), {})
    w("NETWORK / SYSTEM STATE (before → after)")
    w("-" * 78)
    for key in ("interfaces", "default_route", "dns", "serial_ports"):
        w(f"  {key:<14} {base.get(key)}")
        if last.get(key) != base.get(key):
            w(f"  {'':<14} → {last.get(key)}")
    w("")
    for vol in inc.get("storage", []):
        w(f"VOLUME {vol['mountpoint']} ({vol.get('fstype')}) - {vol.get('entries', 0)} entries, "
          f"{vol.get('total_bytes', 0)} bytes{' (truncated)' if vol.get('truncated') else ''}")
        w("-" * 78)
        if vol.get("error"):
            w(f"  error: {vol['error']}")
        for f in vol.get("flagged", []):
            w(f"  ! {f['path']}  [{'; '.join(f['reasons'])}]  sha256={f.get('sha256', '-')}")
        for e in vol.get("tree", [])[:300]:
            w(f"    {'d' if e.get('dir') else '-'} {e.get('size', 0):>12}  {e['path']}")
        w("")
    ev0 = next((p.get("evidence") for p in inc["passes"] if p.get("evidence")), None) or {}
    if ev0.get("drivers"):
        w("DRIVERS ATTACHED")
        w("-" * 78)
        for dr in ev0["drivers"]:
            w(f"  {'  ' * dr.get('depth', 0)}{dr['class']}  ({dr['bundle']})")
        w("")
    if ev0.get("open_by"):
        w("OPENED BY")
        w("-" * 78)
        for o in ev0["open_by"]:
            w(f"  {o['app']}  {o.get('creator') or ''}")
        w("")
    if inc.get("probe"):
        w("LIBUSB PROBE")
        w("-" * 78)
        w(f"  {inc['probe']}")
        w("")
    if inc.get("system_log"):
        w(f"SYSTEM LOG ({len(inc['system_log'])} lines)")
        w("-" * 78)
        out.extend("  " + l for l in inc["system_log"])
    return "\n".join(out) + "\n"
