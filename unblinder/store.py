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
CREATE TABLE IF NOT EXISTS incidents (
    id TEXT PRIMARY KEY,
    created TEXT, updated TEXT, status TEXT, level TEXT, fingerprint TEXT,
    summary TEXT, report_path TEXT, data TEXT
);
CREATE INDEX IF NOT EXISTS incidents_created ON incidents(created);
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

    def save_incident(self, s):
        with self.lock, self.db:
            self.db.execute("""
                INSERT INTO incidents (id, created, updated, status, level, fingerprint, summary, report_path, data)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(id) DO UPDATE SET updated = excluded.updated, status = excluded.status,
                    level = excluded.level, summary = excluded.summary, report_path = excluded.report_path,
                    data = excluded.data
            """, (s["id"], s["created"], s["updated"], s["status"], s["level"], s["fingerprint"],
                  s["summary"], s.get("report_path"), json.dumps(s)))

    def incidents(self, limit=200):
        return [json.loads(r["data"]) for r in
                self._all("SELECT data FROM incidents ORDER BY created DESC LIMIT ?", (limit,))]

    def get_incident(self, incident_id):
        rows = self._all("SELECT data FROM incidents WHERE id = ?", (incident_id,))
        return json.loads(rows[0]["data"]) if rows else None

    def mark_interrupted(self):
        """Scans that were running when the app stopped will never finish."""
        with self.lock, self.db:
            rows = self.db.execute("SELECT id, data FROM incidents WHERE status = 'scanning'").fetchall()
            for r in rows:
                data = json.loads(r["data"])
                data.update(status="interrupted", summary="App stopped before the scan finished")
                self.db.execute("UPDATE incidents SET status = 'interrupted', summary = ?, data = ? WHERE id = ?",
                                (data["summary"], json.dumps(data), r["id"]))

    def recent_events(self, limit=200, min_level=None):
        from .analysis import LEVELS
        levels = LEVELS[LEVELS.index(min_level):] if min_level in LEVELS else LEVELS
        rows = self._all(
            f"SELECT * FROM events WHERE level IN ({','.join('?' * len(levels))}) ORDER BY id DESC LIMIT ?",
            (*levels, limit))
        return [{"id": r["id"], "time": r["time"], "type": r["type"], "level": r["level"],
                 "device": json.loads(r["device"]), "findings": json.loads(r["findings"])}
                for r in rows]
