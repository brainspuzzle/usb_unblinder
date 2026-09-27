"""Deep re-scan of suspicious devices.

Every suspicious connect starts a background incident that observes the device in several
passes over a minute: identity/interface changes, the full OS driver tree, HID descriptors,
mounted volumes, network/DNS/route changes, serial ports, new processes and input activity.
"""
import datetime as dt
import secrets
import sys
import threading
import time
import traceback
from collections import deque

from ..analysis import LEVELS, max_level
from ..logbook import compact_device, is_suspicious
from ..probe import libusb_status, probe
from ..util import now_iso
from . import context, storage
from .assess import SUSPICIOUS_CMD, assess, process_name
from .report import render_text

if sys.platform == "darwin":
    from . import macos as collector
elif sys.platform.startswith("linux"):
    from . import linux as collector
else:
    from . import windows as collector

PASSES = (0, 1, 2, 4, 8, 15, 30, 60)
MAX_PARALLEL = 3
SAMPLE_EVERY = 5
COMPARE = ("vendor_id", "product_id", "serial", "name", "manufacturer")


def _itf_key(dev):
    return [(i.get("class"), i.get("subclass"), i.get("protocol")) for i in dev.get("interfaces") or []]


def _diff(prev, cur):
    changes = [{"field": k, "before": prev.get(k), "after": cur.get(k)} for k in COMPARE if prev.get(k) != cur.get(k)]
    if _itf_key(prev) != _itf_key(cur):
        changes.append({"field": "interfaces", "before": _itf_key(prev), "after": _itf_key(cur)})
    if prev.get("id") != cur.get("id"):
        changes.append({"field": "id", "before": prev.get("id"), "after": cur.get("id")})
    return changes


def _guard(fn, *args):
    try:
        return fn(*args)
    except Exception as e:
        return {"error": f"{type(e).__name__}: {e}"}


class DeepScanner:
    def __init__(self, monitor, logbook):
        self.monitor = monitor
        self.store = monitor.store
        self.logbook = logbook
        self.lock = threading.Lock()
        self.samples = deque(maxlen=8)
        self.active = {}
        self.slots = threading.BoundedSemaphore(MAX_PARALLEL)
        threading.Thread(target=self._sampler, name="context-sampler", daemon=True).start()

    # ── baseline sampling ──
    def _sampler(self):
        while True:
            s = context.sample()
            with self.lock:
                self.samples.append(s)
            time.sleep(SAMPLE_EVERY)

    def _baseline(self, wall):
        with self.lock:
            before = [s for s in self.samples if s["wall"] <= wall]
            return before[-1] if before else (self.samples[0] if self.samples else None)

    # ── entry points ──
    def on_event(self, ev):
        if ev.get("type") == "connected" and is_suspicious(ev) and not ev["device"].get("trusted"):
            self.start(ev["device"], "auto", ev)

    def start(self, dev, reason, ev=None):
        fp = dev.get("fingerprint")
        with self.lock:
            running = self.active.get(fp)
            if running:
                running["related_events"].append({"time": (ev or {}).get("time", now_iso()), "type": (ev or {}).get("type", reason),
                                                  "level": (ev or {}).get("level"), "device_id": dev["id"]})
                return running["id"]
            created = time.time()
            trigger = ev or {"type": "manual", "time": now_iso(), "level": dev.get("level", "info"),
                             "findings": dev.get("findings", [])}
            inc = {
                "id": dt.datetime.now().strftime("%Y%m%d-%H%M%S-") + f"{dev.get('vid') or 0:04x}{dev.get('pid') or 0:04x}-" + secrets.token_hex(2),
                "created": now_iso(), "updated": now_iso(), "status": "scanning", "reason": reason,
                "trigger": {"type": trigger["type"], "time": trigger["time"], "level": trigger.get("level", "info"),
                            "findings": trigger.get("findings", [])},
                "device": compact_device(dev),
                "connected_at_wall": dt.datetime.fromisoformat(trigger["time"]).timestamp() if reason == "auto" else created,
                "related_events": [], "passes": [], "storage": [], "new_processes": [],
                "progress": {"pass": 0, "of": len(PASSES)},
                "findings": [], "all_findings": list(trigger.get("findings", [])),
                "level": trigger.get("level", "info"), "summary": "Scanning…",
            }
            self.active[fp] = inc
        self._publish(inc, "incident_started")
        threading.Thread(target=self._run, args=(inc, dev), name=f"scan-{inc['id']}", daemon=True).start()
        return inc["id"]

    # ── bookkeeping ──
    def summary(self, inc):
        return {k: inc.get(k) for k in ("id", "created", "updated", "status", "reason", "level", "summary",
                                        "progress", "report_path")} | {
            "fingerprint": inc["device"].get("fingerprint"), "name": inc["device"].get("name"),
            "vendor_id": inc["device"].get("vendor_id"), "product_id": inc["device"].get("product_id"),
            "kinds": inc["device"].get("kinds"), "findings": inc["all_findings"],
            "related": len(inc["related_events"]),
        }

    def _publish(self, inc, record=None):
        inc["updated"] = now_iso()
        s = self.summary(inc)
        self.store.save_incident(s)
        if record:
            self.logbook.incident(record, s)
        self.monitor.emit({"type": "incident", "time": inc["updated"], "incident": s}, persist=False)

    def _locate(self, dev, prev):
        devices = self.monitor.current_devices()
        for d in devices:
            if d["id"] == prev["id"]:
                return d, "present"
        for d in devices:
            if d["location"] == dev["location"]:
                return d, "re-enumerated"
        for d in devices:
            if d.get("fingerprint") == dev.get("fingerprint"):
                return d, "moved"
        return None, "absent"

    def _processes(self, inc, seen):
        procs = context.processes()
        since = inc["connected_at_wall"] - 1.5
        own = context.own_descendants(procs, started_before=since)
        for p in procs:
            if p["pid"] in own or p["pid"] in seen or not p.get("start") or p["start"] < since:
                continue
            seen.add(p["pid"])
            name = process_name(p["command"])
            inc["new_processes"].append({**p, "name": name, "offset": round(p["start"] - inc["connected_at_wall"], 1),
                                         "suspicious": bool(SUSPICIOUS_CMD.match(name))})

    # ── the scan ──
    def _run(self, inc, dev):
        try:
            with self.slots:
                self._scan(inc, dev)
        except Exception:
            inc["status"] = "error"
            inc["error"] = traceback.format_exc()
            inc["summary"] = "Scan failed: " + inc["error"].strip().splitlines()[-1]
            self._finish(inc)
        finally:
            with self.lock:
                self.active.pop(dev.get("fingerprint"), None)

    def _scan(self, inc, dev):
        inc["baseline"] = self._baseline(inc["connected_at_wall"])
        start = time.monotonic()
        prev, seen_pids, inspected = dev, set(), set()
        for idx, offset in enumerate(PASSES):
            delay = start + offset - time.monotonic()
            if delay > 0:
                time.sleep(delay)
            cur, state = self._locate(dev, prev)
            changes = _diff(prev, cur) if cur else []
            heavy = idx == 0 or bool(changes)
            evidence = _guard(collector.collect, cur, heavy) if cur else None
            rec = {"index": idx, "offset": offset, "time": now_iso(), "state": state, "changes": changes,
                   "device": compact_device(cur) if cur else None, "context": context.sample(), "evidence": evidence}
            try:
                self._processes(inc, seen_pids)
            except Exception as e:
                rec["process_error"] = str(e)
            inc["passes"].append(rec)

            if isinstance(evidence, dict) and "error" not in evidence:
                for mount, fstype in collector.mountpoints(evidence):
                    if mount not in inspected:
                        inspected.add(mount)
                        inc["storage"].append(_guard(storage.inspect_volume, mount, fstype) | {"mountpoint": mount})
            if idx == 0 and cur and libusb_status()[0]:
                inc["probe"] = _guard(probe, cur["vid"], cur["pid"])
            if cur:
                prev = cur
            inc["progress"] = {"pass": idx + 1, "of": len(PASSES)}
            inc["findings"] = assess(inc)
            self._merge(inc)
            inc["summary"] = f"Observing… pass {idx + 1}/{len(PASSES)}"
            self._publish(inc)

        inc["system_log"] = _guard(collector.system_log, inc["connected_at_wall"])
        inc["findings"] = assess(inc)
        self._merge(inc)
        inc["status"] = "done"
        self._finish(inc)

    def _merge(self, inc):
        seen = {(f["code"], f["message"]) for f in inc["trigger"]["findings"]}
        inc["all_findings"] = list(inc["trigger"]["findings"]) + [f for f in inc["findings"]
                                                                  if (f["code"], f["message"]) not in seen]
        inc["level"] = max_level(inc["all_findings"])

    def _finish(self, inc):
        deep = [f for f in inc["findings"] if f["level"] != "info"]
        if inc["status"] == "done":
            top = sorted(deep, key=lambda f: -LEVELS.index(f["level"]))[:2]
            inc["summary"] = (f"{len(deep)} deep finding(s): " + " · ".join(f["message"] for f in top)) if deep \
                else "Deep scan found nothing beyond the initial alert"
        try:
            inc["report_path"] = self.logbook.write_report(inc, render_text(inc))
        except Exception as e:
            inc["report_error"] = str(e)
        self._publish(inc, "incident_done")
        self._update_device(inc, deep)
        trigger_level = inc["trigger"].get("level", "info")
        if LEVELS.index(inc["level"]) > LEVELS.index(trigger_level) or any(f["level"] == "high" for f in deep):
            self.monitor.notifier.send(f"{inc['device'].get('fingerprint')}:deep",
                                       f"USB incident {inc['level'].upper()}: {inc['device'].get('name')}",
                                       inc["summary"][:200])

    def _update_device(self, inc, deep):
        if not deep:
            return
        for d in self.monitor.current_devices():
            if d.get("fingerprint") == inc["device"].get("fingerprint"):
                have = {(f["code"], f["message"]) for f in d.get("findings", [])}
                d["findings"] = d.get("findings", []) + [dict(f, deep=True) for f in deep
                                                         if (f["code"], f["message"]) not in have]
                d["level"] = max_level(d["findings"])
                d["incident"] = inc["id"]
                self.monitor.emit({"type": "device_update", "time": now_iso(), "device": d}, persist=False)

    def report(self, incident_id):
        with self.lock:
            for inc in self.active.values():
                if inc["id"] == incident_id:
                    return inc
        return None
