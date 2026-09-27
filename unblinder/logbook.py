"""Persistent logs.

logs/events.jsonl      every plug/unplug event (rotating)
logs/suspicious.jsonl  suspicious events + deep-scan results (rotating)
logs/incidents/        one full forensic report per incident (.json + readable .txt)
"""
import json
import logging
import logging.handlers
from pathlib import Path

from .analysis import LEVELS

SUSPICIOUS_LEVEL = "medium"


def _logger(name, path, max_mb, backups):
    log = logging.getLogger(f"unblinder.{name}")
    log.setLevel(logging.INFO)
    log.propagate = False
    for h in list(log.handlers):
        log.removeHandler(h)
    h = logging.handlers.RotatingFileHandler(path, maxBytes=max_mb * 1024 * 1024,
                                             backupCount=backups, encoding="utf-8")
    h.setFormatter(logging.Formatter("%(message)s"))
    log.addHandler(h)
    return log


def compact_device(dev):
    return {k: v for k, v in (dev or {}).items() if k != "raw"}


def is_suspicious(ev):
    return LEVELS.index(ev.get("level", "info")) >= LEVELS.index(SUSPICIOUS_LEVEL)


class LogBook:
    def __init__(self, root):
        self.root = Path(root)
        self.incident_dir = self.root / "incidents"
        self.incident_dir.mkdir(parents=True, exist_ok=True)
        self.events = _logger("events", self.root / "events.jsonl", 20, 10)
        self.suspicious = _logger("suspicious", self.root / "suspicious.jsonl", 20, 20)

    def on_event(self, ev):
        if ev.get("type") not in ("connected", "removed"):
            return
        line = {"time": ev["time"], "type": ev["type"], "level": ev.get("level", "info"),
                "device": compact_device(ev.get("device")), "findings": ev.get("findings", [])}
        self.events.info(json.dumps(line, ensure_ascii=False))
        if is_suspicious(ev):
            self.suspicious.info(json.dumps({"record": "event", **line,
                                             "raw": ev.get("device", {}).get("raw")}, ensure_ascii=False))

    def incident(self, record, summary):
        self.suspicious.info(json.dumps({"record": record, **summary}, ensure_ascii=False))

    def write_report(self, report, text):
        base = self.incident_dir / report["id"]
        json_path = base.with_suffix(".json")
        json_path.write_text(json.dumps(report, indent=1, ensure_ascii=False), encoding="utf-8")
        base.with_suffix(".txt").write_text(text, encoding="utf-8")
        return str(json_path)
