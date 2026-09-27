import json
import sqlite3
import threading

from .util import now_iso

SCHEMA = """
CREATE TABLE IF NOT EXISTS devices (
    fingerprint TEXT PRIMARY KEY,
    vendor_id TEXT, product_id TEXT, name TEXT, manufacturer TEXT, serial TEXT,
    kinds TEXT, first_seen TEXT, last_seen TEXT,
    seen_count INTEGER DEFAULT 0, trusted INTEGER DEFAULT 0
);
CREATE INDEX IF NOT EXISTS devices_serial ON devices(serial);
CREATE TABLE IF NOT EXISTS events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    time TEXT, type TEXT, fingerprint TEXT, level TEXT,
    device TEXT, findings TEXT
);
CREATE INDEX IF NOT EXISTS events_time ON events(time);
"""


class Store:
    def __init__(self, path):
        self.db = sqlite3.connect(path, check_same_thread=False)
        self.db.row_factory = sqlite3.Row
        self.lock = threading.Lock()
        with self.lock:
            self.db.executescript(SCHEMA)

    def _all(self, sql, args=()):
        with self.lock:
            return [dict(r) for r in self.db.execute(sql, args).fetchall()]

    def get_device(self, fp):
        rows = self._all("SELECT * FROM devices WHERE fingerprint = ?", (fp,))
        return rows[0] if rows else None

    def find_by_serial(self, serial):
        return self._all("SELECT * FROM devices WHERE serial = ?", (serial,))

    def record_seen(self, dev):
        t = now_iso()
        with self.lock, self.db:
            self.db.execute("""
                INSERT INTO devices (fingerprint, vendor_id, product_id, name, manufacturer, serial,
                                     kinds, first_seen, last_seen, seen_count)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 1)
                ON CONFLICT(fingerprint) DO UPDATE SET
                    name = excluded.name, manufacturer = excluded.manufacturer, kinds = excluded.kinds,
                    last_seen = excluded.last_seen, seen_count = seen_count + 1
            """, (dev["fingerprint"], dev["vendor_id"], dev["product_id"], dev["name"],
                  dev["manufacturer"], dev["serial"], json.dumps(dev.get("kinds", [])), t, t))

    def set_trusted(self, fp, trusted):
        with self.lock, self.db:
            return self.db.execute("UPDATE devices SET trusted = ? WHERE fingerprint = ?",
                                   (1 if trusted else 0, fp)).rowcount > 0

    def known_devices(self):
        rows = self._all("SELECT * FROM devices ORDER BY last_seen DESC")
        for r in rows:
            r["kinds"] = json.loads(r["kinds"] or "[]")
            r["trusted"] = bool(r["trusted"])
        return rows

    def add_event(self, ev):
        dev = ev.get("device") or {}
        with self.lock, self.db:
            self.db.execute(
                "INSERT INTO events (time, type, fingerprint, level, device, findings) VALUES (?, ?, ?, ?, ?, ?)",
                (ev["time"], ev["type"], dev.get("fingerprint"), ev.get("level", "info"),
                 json.dumps(dev), json.dumps(ev.get("findings", []))))

    def recent_events(self, limit=200, min_level=None):
        from .analysis import LEVELS
        levels = LEVELS[LEVELS.index(min_level):] if min_level in LEVELS else LEVELS
        rows = self._all(
            f"SELECT * FROM events WHERE level IN ({','.join('?' * len(levels))}) ORDER BY id DESC LIMIT ?",
            (*levels, limit))
        return [{"id": r["id"], "time": r["time"], "type": r["type"], "level": r["level"],
                 "device": json.loads(r["device"]), "findings": json.loads(r["findings"])}
                for r in rows]
