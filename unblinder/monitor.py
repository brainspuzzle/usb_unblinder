import queue
import threading
import time

from .analysis import LEVELS, Analyzer, max_level
from .util import now_iso

ALERT_LEVELS = ("medium", "high")


class Monitor:
    """Polls the OS backend, diffs snapshots, scores events and fans them out."""

    def __init__(self, backend, store, notifier, poll_interval=None):
        self.backend = backend
        self.store = store
        self.notifier = notifier
        self.analyzer = Analyzer(store)
        self.poll_interval = poll_interval or backend.poll_interval
        self.devices = {}
        self.lock = threading.Lock()
        self.subscribers = []
        self.listeners = []
        self.status = {"state": "starting", "error": None, "started": now_iso(), "last_poll": None}

    def start(self):
        threading.Thread(target=self._run, name="usb-monitor", daemon=True).start()

    def subscribe(self):
        q = queue.Queue(maxsize=1000)
        with self.lock:
            self.subscribers.append(q)
        return q

    def unsubscribe(self, q):
        with self.lock:
            if q in self.subscribers:
                self.subscribers.remove(q)

    def current_devices(self):
        with self.lock:
            return list(self.devices.values())

    def emit(self, ev, persist=True):
        if persist:
            self.store.add_event(ev)
        with self.lock:
            subs = list(self.subscribers)
        for q in subs:
            try:
                q.put_nowait(ev)
            except queue.Full:
                pass
        for fn in self.listeners:
            fn(ev)

    def _set_status(self, state, error=None):
        changed = (state, error) != (self.status["state"], self.status["error"])
        self.status.update(state=state, error=error)
        if changed:
            self.emit({"type": "status", "time": now_iso(), "status": dict(self.status)}, persist=False)

    def scan(self):
        """One-shot scan without starting the watcher thread."""
        self._baseline(self.backend.snapshot())
        return self.current_devices()

    def _run(self):
        first = True
        while True:
            try:
                snap = self.backend.snapshot()
            except Exception as e:
                self._set_status("error", f"{type(e).__name__}: {e}")
                time.sleep(max(self.poll_interval, 2))
                continue
            self.status["last_poll"] = now_iso()
            self._set_status("running")
            if first:
                self._baseline(snap)
                first = False
            else:
                self._diff(snap)
            time.sleep(self.poll_interval)

    def _baseline(self, snap):
        for dev in snap.values():
            dev["findings"] = self.analyzer.on_connect(dev, baseline=True)
            dev["level"] = max_level(dev["findings"])
            self.store.record_seen(dev)
        with self.lock:
            self.devices = dict(snap)
        self.emit({"type": "snapshot", "time": now_iso(), "devices": list(snap.values())}, persist=False)

    def _diff(self, snap):
        with self.lock:
            removed = [d for i, d in self.devices.items() if i not in snap]
            added = [d for i, d in snap.items() if i not in self.devices]

        for dev in removed:
            findings = self.analyzer.on_remove(dev)
            with self.lock:
                self.devices.pop(dev["id"], None)
            self.emit({"type": "removed", "time": now_iso(), "device": dev,
                        "findings": findings, "level": max_level(findings)})

        locked = self.backend.screen_locked() if added else None
        for dev in added:
            findings = self.analyzer.on_connect(dev, locked=locked)
            dev["findings"] = findings
            dev["level"] = max_level(findings)
            self.store.record_seen(dev)
            with self.lock:
                self.devices[dev["id"]] = dev
            self.emit({"type": "connected", "time": now_iso(), "device": dev,
                        "findings": findings, "level": dev["level"]})
            if dev["level"] in ALERT_LEVELS:
                worst = max(findings, key=lambda f: LEVELS.index(f["level"]))
                self.notifier.send(f"{dev['fingerprint']}:{worst['code']}",
                                   f"USB {dev['level'].upper()}: {dev['name']}", worst["message"])
