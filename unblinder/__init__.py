from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DEFAULT_DB = ROOT / "unblinder.db"
DEFAULT_LOGS = ROOT / "logs"


def create_monitor(db_path=DEFAULT_DB, notify=True, poll_interval=None, logs_dir=DEFAULT_LOGS, forensics=True):
    """Wire backend + store + notifier; with forensics=True also persistent logs and deep scans."""
    from .backends import detect_backend
    from .monitor import Monitor
    from .notify import Notifier
    from .store import Store
    monitor = Monitor(detect_backend(), Store(str(db_path)), Notifier(notify), poll_interval)
    monitor.logbook = monitor.scanner = None
    if forensics:
        from .forensics import DeepScanner
        from .logbook import LogBook
        monitor.store.mark_interrupted()
        monitor.logbook = LogBook(logs_dir)
        monitor.scanner = DeepScanner(monitor, monitor.logbook)
        monitor.listeners.append(monitor.logbook.on_event)
        monitor.listeners.append(monitor.scanner.on_event)
    from .capture import Capture
    monitor.capture = Capture(logs_dir)
    from .telemetry import Telemetry
    monitor.store.init_telemetry()
    monitor.telemetry = Telemetry(monitor)
    monitor.listeners.append(monitor.telemetry.on_event)
    return monitor
